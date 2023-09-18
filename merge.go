package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ackToRequest = AckToRequest{mp: map[uint32]FlyHttp{}}
var ackToResponse = AckToResponse{mp: map[uint32][]FlyHttp{}}
var seqToAck = SeqToAck{seqToAck: map[uint32]uint32{}}

// AckToRequest save the ACK and corresponding request in the HTTP request message
type AckToRequest struct {
	mp   map[uint32]FlyHttp
	lock sync.RWMutex
}

func (a *AckToRequest) Get(key uint32) (FlyHttp, bool) {
	a.lock.Lock()
	defer a.lock.Unlock()
	v, ok := a.mp[key]
	return v, ok
}

func (a *AckToRequest) List() map[uint32]FlyHttp {
	a.lock.Lock()
	defer a.lock.Unlock()
	tmp, _ := json.Marshal(a.mp)
	ret := map[uint32]FlyHttp{}
	json.Unmarshal(tmp, &ret)
	return ret
}

func (a *AckToRequest) Save(http FlyHttp) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.mp[http.Ack] = http
}

func (a *AckToRequest) Delete(key uint32) {
	a.lock.Lock()
	defer a.lock.Unlock()
	delete(a.mp, key)
}

// AckToResponse save the ACK and corresponding response in the HTTP response message
type AckToResponse struct {
	mp   map[uint32][]FlyHttp
	lock sync.RWMutex
}

func (a *AckToResponse) Get(key uint32) []FlyHttp {
	a.lock.Lock()
	defer a.lock.Unlock()
	return a.mp[key]
}

func (a *AckToResponse) Save(http FlyHttp) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.mp[http.Ack] = append(a.mp[http.Ack], http)
}

func (a *AckToResponse) Delete(key uint32) {
	a.lock.Lock()
	defer a.lock.Unlock()
	delete(a.mp, key)
}

// SeqToAck save the association between HTTP request and HTTP response message, Seq and Ack
type SeqToAck struct {
	seqToAck map[uint32]uint32
	lock     sync.RWMutex
}

func (a *SeqToAck) Get(key uint32) (uint32, bool) {
	a.lock.Lock()
	defer a.lock.Unlock()
	v, ok := a.seqToAck[key]
	return v, ok
}

func (a *SeqToAck) Save(http FlyHttp) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.seqToAck[http.Seq] = http.Ack
}

func (a *SeqToAck) Delete(key uint32) {
	a.lock.Lock()
	defer a.lock.Unlock()
	delete(a.seqToAck, key)
}

func MageHttp(ctx context.Context, save chan<- model) {
	ticker := time.Tick(3 * time.Second)
	for {
		select {
		case <-ctx.Done():
			break
		case <-ticker:
			request := ackToRequest.List()
			for k, v := range request {
				ack, ok := seqToAck.Get(k)
				if !ok {
					continue
				}

				flyResponses := ackToResponse.Get(ack)
				if flyResponses == nil {
					continue
				}

				if Verbose {
					log.Printf("[PRISM] request ack:%+v\n", k)
					log.Printf("[PRISM] \tseq:%+v,ack:%+v,url:%+v,value:%+v\n", v.Seq, v.Ack, v.Data.RequestLine, v.Data.Headers)
					log.Printf("[PRISM] response ack:%+v\n", ack)
					for _, v := range flyResponses {
						log.Printf("[PRISM] \tseq:%+v,ack:%+v,value:%+v\n", v.Seq, v.Ack, v.Data.Headers)
					}
				}

				if !checkoutBodyLen(flyResponses) {
					continue
				}
				save <- mergeOperation(v, flyResponses)
				ackToRequest.Delete(k)
				seqToAck.Delete(k)
				ackToResponse.Delete(ack)
			}
		}
	}
}

func checkoutBodyLen(flyHttps []FlyHttp) bool {
	var maxBody int = 0
	var currentBody int = -1
	var lastTime = flyHttps[len(flyHttps)-1].CreateTime
	var lastBody = flyHttps[len(flyHttps)-1].Data.Body
	for i, _ := range flyHttps {
		if maxBody == 0 {
			maxBody, _ = strconv.Atoi(flyHttps[i].Data.Headers[ContentLength])
		}
		currentBody += len(flyHttps[i].Data.Body)
	}

	if Verbose {
		log.Printf("[PRISM] HTTP max body len:%+v, current body len:%+v", maxBody, currentBody)
	}

	if currentBody == maxBody {
		return true
	}

	if bytes.HasSuffix(lastBody, []byte("\r\n0")) {
		return true
	}

	if time.Since(lastTime).Seconds() > 10 {
		return true
	}

	return false
}

func mergeOperation(request FlyHttp, responses []FlyHttp) model {
	fmt.Println()

	log.Printf("[PRISM] HTTP request: %+v", request.Data.RequestLine)
	if Debug {
		printFormatHeader(request.Data.Headers)
		log.Printf("[PRISM] HTTP request param: %+v", string(request.Data.Body))
	}

	urls, err := url.Parse(request.Data.RequestLine.URN)
	if err != nil {
		log.Printf("[ERROR] url parse (%+v)", err.Error())
		return model{}
	}
	Parma, _ := url.ParseQuery(urls.RawQuery)

	var md = model{
		RequestSrcMAC:      request.SrcMAC,
		RequestDstMAC:      request.DstMAC,
		RequestSrcIP:       request.SrcIP,
		RequestDstIP:       request.DstIP,
		RequestSrcPort:     request.SrcPort,
		RequestDstPort:     request.DstPort,
		RequestMethod:      request.Data.RequestLine.Method,
		RequestURL:         urls.Path,
		RequestParma:       Parma,
		RequestHeaders:     request.Data.Headers,
		RequestContentType: request.Data.Headers[ContentType],
		RequestBody:        string(request.Data.Body),
	}

	if _, ok := request.Data.Headers[XForwardedFor]; ok {
		md.Tag = []string{XForwardedFor}
	}

	var isExit = map[uint32]struct{}{}
	var responseLine ResponseLine
	var responseHeaders map[string]string

	// Create a buffer to store the merged response body
	var mergedBody bytes.Buffer
	for i, v := range responses {
		if _, ok := isExit[v.Seq]; ok {
			continue
		}
		isExit[v.Seq] = struct{}{}

		if len(responses[i].Data.Headers) > 0 {
			responseLine = responses[i].Data.ResponseLine
			responseHeaders = responses[i].Data.Headers
		}

		if Verbose {
			if _, ok := responseHeaders[ContentLength]; !ok {
				log.Printf("[PRISM] HTTP response[%d] body: %+v", i, string(responses[i].Data.Body))
			}
		}

		if Encoding, ok := responseHeaders[TransferEncoding]; ok && Encoding == "chunked" {
			body := bytes.NewReader(responses[i].Data.Body)

			// Try reading a block and get the total data length
			var chunkSize int
			_, err := fmt.Fscanf(body, "%x\r\n", &chunkSize)
			if err != nil {
				// Handle irregular data
				tmp := bytes.TrimSuffix(responses[i].Data.Body, []byte("\r\n\r\n"))
				tmp = bytes.TrimSuffix(responses[i].Data.Body, []byte("\r\n0"))
				mergedBody.Write(tmp)
				continue
			}

			// Process the first piece of data
			if chunkSize > len(responses[i].Data.Body) {
				tmp, _ := io.ReadAll(body)
				tmp = bytes.TrimSuffix(tmp, []byte("\r\n\r\n"))
				mergedBody.Write(tmp)
			} else {
				// Handle situations where there is only one piece of data
				chunkData := make([]byte, chunkSize)
				_, err = body.Read(chunkData)
				if err != nil {
					log.Printf("[ERROR] read chunked (%+v)", err.Error())
					continue
				}
				mergedBody.Write(chunkData)
			}

		} else if len(responses[i].Data.Body) > 0 {
			mergedBody.Write(responses[i].Data.Body)
		}
	}

	md.ResponseStatus = responseLine.Status
	md.ResponseContextType = responseHeaders[ContentType]

	if Debug {
		log.Printf("[PRISM] HTTP response: %+v", responseLine.String())
		printFormatHeader(responseHeaders)
	}

	if v, ok := responseHeaders[ContentType]; ok && !strings.Contains(v, ContentTypeHTML) {
		if encoding, ok := responseHeaders[ContentEncoding]; ok && encoding == "gzip" {
			ret, err := parseGzip(mergedBody.Bytes())
			if err != nil && err.Error() != "unexpected EOF" {
				log.Printf("[PRISM] gzip decode (%s)", err.Error())
			}
			if contentType, ok := responseHeaders[ContentType]; ok &&
				(strings.Contains(contentType, ContentTypePlain) || strings.Contains(contentType, ContentTypeJSON)) {

				log.Printf("[PRISM] HTTP gzip response body: %+v", string(ret))
				md.ResponseBody = string(ret)
			}

		} else {
			if contentType, ok := responseHeaders[ContentType]; ok &&
				(strings.Contains(contentType, ContentTypePlain) || strings.Contains(contentType, ContentTypeJSON)) {

				log.Printf("[PRISM] HTTP response body: %+v", mergedBody.String())
				md.ResponseBody = mergedBody.String()
			}
		}
	}

	return md
}

func parseGzip(in []byte) ([]byte, error) {
	// remove messy heads
	for i := 0; i < len(in) && len(in) > 3; i++ {
		if in[i] == 31 && in[i+1] == 139 && in[i+2] == 8 {
			in = in[i:]
			break
		}
	}

	reader, err := gzip.NewReader(bytes.NewReader(in))
	if err != nil {
		var out []byte
		return out, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func printFormatHeader(headers map[string]string) {
	log.Printf("[PRISM] HTTP headers:\n")
	for k, v := range headers {
		log.Printf("[PRISM] \t\t%s: %s\n", k, v)
	}
}

type model struct {
	Id                 string              `json:"id"`
	RequestSrcMAC      string              `json:"request_src_mac"`
	RequestDstMAC      string              `json:"request_dst_mac"`
	RequestSrcIP       string              `json:"request_src_ip"`
	RequestDstIP       string              `json:"request_dst_ip"`
	RequestSrcPort     string              `json:"request_src_port"`
	RequestDstPort     string              `json:"request_dst_port"`
	RequestMethod      string              `json:"request_method"`
	RequestURL         string              `json:"request_url"`
	RequestParma       map[string][]string `json:"request_parma"`
	RequestHeaders     map[string]string   `json:"request_headers"`
	RequestBody        string              `json:"request_body"`
	RequestContentType string              `json:"request_content_type"`

	ResponseStatus      int         `json:"response_status"`
	ResponseContextType string      `json:"response_context_type"`
	ResponseBody        interface{} `json:"response_body"`

	Tag []string `json:"tag"`
}

func (m *model) key() string {
	m.Id = fmt.Sprintf("%s-%s", m.RequestMethod, m.RequestURL)
	return m.Id
}
