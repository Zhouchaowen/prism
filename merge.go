package main

import (
	"bytes"
	"compress/gzip"
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

var ackRequest = AckRequest{ackRequest: map[uint32]FlyHttp{}}
var ackResponse = AckResponse{ackResponse: map[uint32][]FlyHttp{}}
var seqToAck = SeqToAck{seqToAck: map[uint32]uint32{}}

type AckRequest struct {
	ackRequest map[uint32]FlyHttp
	lock       sync.RWMutex
}

func (a *AckRequest) Get(key uint32) (FlyHttp, bool) {
	a.lock.Lock()
	defer a.lock.Unlock()
	v, ok := a.ackRequest[key]
	return v, ok
}

func (a *AckRequest) List() map[uint32]FlyHttp {
	a.lock.Lock()
	defer a.lock.Unlock()
	tmp, _ := json.Marshal(a.ackRequest)
	ret := map[uint32]FlyHttp{}
	json.Unmarshal(tmp, &ret)
	return ret
}

func (a *AckRequest) Save(http FlyHttp) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.ackRequest[http.Ack] = http
}

func (a *AckRequest) Delete(key uint32) {
	a.lock.Lock()
	defer a.lock.Unlock()
	delete(a.ackRequest, key)
}

type AckResponse struct {
	ackResponse map[uint32][]FlyHttp
	lock        sync.RWMutex
}

func (a *AckResponse) Get(key uint32) []FlyHttp {
	a.lock.Lock()
	defer a.lock.Unlock()
	return a.ackResponse[key]
}

func (a *AckResponse) Save(http FlyHttp) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.ackResponse[http.Ack] = append(a.ackResponse[http.Ack], http)
}

func (a *AckResponse) Delete(key uint32) {
	a.lock.Lock()
	defer a.lock.Unlock()
	delete(a.ackResponse, key)
}

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

func MageHttp(save chan<- model) {
	request := ackRequest.List()
	for k, v := range request {
		ack, ok := seqToAck.Get(k)
		if !ok {
			continue
		}

		if Verbose {
			log.Printf("\treq ack:%+v\n\t\tseq:%+v,ack:%+v,url:%+v,value:%+v\n", k, v.Seq, v.Ack, v.Data.RequestLine, v.Data.Headers)
		}

		flyHttps := ackResponse.Get(ack)
		if flyHttps == nil {
			continue
		}
		if Verbose {
			log.Printf("\tres ack:%+v\n", ack)
			for _, v := range flyHttps {
				log.Printf("\t\tseq:%+v,ack:%+v,value:%+v\n", v.Seq, v.Ack, v.Data.Headers)
			}
		}

		if !checkoutBodyLen(flyHttps) {
			continue
		}

		save <- mergeReqAndRes(v, flyHttps)
		ackRequest.Delete(k)
		seqToAck.Delete(k)
		ackResponse.Delete(ack)
	}
}

func checkoutBodyLen(flyHttps []FlyHttp) bool {
	var maxBody int = 0
	var currentBody int = -1
	var lastTime time.Time
	for i, _ := range flyHttps {
		if maxBody == 0 {
			maxBody, _ = strconv.Atoi(flyHttps[i].Data.Headers[ContentLength])
		}
		currentBody += len(flyHttps[i].Data.Body)
		lastTime = flyHttps[i].CreateTime
	}

	if Verbose {
		log.Printf("maxBody:%+v,currentBody:%+v", maxBody, currentBody)
	}

	if currentBody == maxBody {
		return true
	}

	if time.Since(lastTime).Seconds() > 10 {
		return true
	}

	return false
}

func mergeReqAndRes(request FlyHttp, responses []FlyHttp) model {
	fmt.Println()

	log.Printf("request: %+v", request.Data.RequestLine)
	if Debug {
		printFormatHeader(request.Data.Headers)
		log.Printf("request param: %+v", string(request.Data.Body))
	}

	urls, err := url.Parse(request.Data.RequestLine.URN)
	if err != nil {
		log.Printf("url.Parse error %+v", err.Error())
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
	var responseBody []byte
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
				log.Printf("response[%d] body: %+v", i, string(responses[i].Data.Body))
			}
		}
		responseBody = append(responseBody, responses[i].Data.Body...)
	}

	md.ResponseStatus = responseLine.Status
	md.ResponseContextType = responseHeaders[ContentType]

	if Debug {
		log.Printf("response: %+v", responseLine.String())
		printFormatHeader(responseHeaders)
	}

	if v, ok := responseHeaders[ContentType]; ok && !strings.Contains(v, ContentTypeHTML) {
		if encoding, ok := responseHeaders[ContentEncoding]; ok && encoding == "gzip" {
			ret, err := parseGzip(responseBody)
			if err != nil && err.Error() != "unexpected EOF" {
				log.Printf("gzip decode err: %s", err.Error())
			}
			if contentType, ok := responseHeaders[ContentType]; ok &&
				(strings.Contains(contentType, ContentTypePlain) ||
					strings.Contains(contentType, ContentTypeJSON)) {

				log.Printf("gzip response body: %+v", string(ret))
				md.ResponseBody = string(ret)
			}

		} else {
			if contentType, ok := responseHeaders[ContentType]; ok &&
				(strings.Contains(contentType, ContentTypePlain) ||
					strings.Contains(contentType, ContentTypeJSON)) {

				log.Printf("response body: %+v", string(responseBody))
				md.ResponseBody = string(responseBody)
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
	fmt.Printf("headers:\n")
	for k, v := range headers {
		fmt.Printf("\t%s: %s\n", k, v)
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
