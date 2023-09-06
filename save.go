package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/syndtr/goleveldb/leveldb"
	"io"
	"log"
	"net/url"
	"strings"
)

func saveHttpData(db *leveldb.DB, mbChan <-chan *MergeBuilder) {
	for mb := range mbChan {
		md := mb.MergeReqAndRes()
		if !strings.Contains(md.ResponseContextType, "text/plain") && !strings.Contains(md.ResponseContextType, "application/json") {
			log.Printf("package is no text/plain,application/json")
			continue
		}
		byt, err := json.Marshal(md)
		if err != nil {
			log.Printf("marshal error %s", err.Error())
			continue
		}
		if err := db.Put([]byte(md.key()), byt, nil); err != nil {
			log.Printf("put error %s", err.Error())
			continue
		}
	}
}

type MergeBuilder struct {
	SrcMAC        string    `json:"src_mac"`
	DstMAC        string    `json:"dst_mac"`
	SrcIP         string    `json:"src_ip"`
	DstIP         string    `json:"dst_ip"`
	SrcPort       string    `json:"src_port"`
	DstPort       string    `json:"dst_port"`
	Seq           uint32    `json:"seq"`
	Ack           uint32    `json:"ack"`
	ContentLength int       `json:"content_length"`
	MaxBody       int       `json:"max_body"`
	Data          []FlyHttp `json:"data"`
}

func (m MergeBuilder) MergeReqAndRes() model {
	var responseLine ResponseLine
	var responseHeaders map[string]string
	var responseBody []byte
	fmt.Println()

	var md = model{}

	for _, v := range m.Data {
		if v.Data.Type == IsRequest {
			log.Printf("request: %+v", v.Data.RequestLine)
			if Debug {
				printFormatHeader(v.Data.Headers)
				log.Printf("request param: %+v", string(v.Data.Body))
			}

			md.RequestSrcMAC = v.SrcMAC
			md.RequestDstMAC = v.DstMAC
			md.RequestSrcIP = v.SrcIP
			md.RequestDstIP = v.DstIP
			md.RequestSrcPort = v.SrcPort
			md.RequestDstPort = v.DstPort
			urls, err := url.Parse(v.Data.RequestLine.URN)
			if err != nil {
				log.Printf("url.Parse error %+v", err.Error())
				continue
			}

			Parma, _ := url.ParseQuery(urls.RawQuery)
			md.RequestMethod = v.Data.RequestLine.Method
			md.RequestURL = urls.Path
			md.RequestParma = Parma
			md.RequestHeaders = v.Data.Headers
			md.RequestContentType = v.Data.Headers["Content-Type"]
			md.RequestBody = string(v.Data.Body)

			continue
		}

		if v.Data.Type == IsResponse {
			if v.Data.ResponseLine.Status != 0 {
				responseLine = v.Data.ResponseLine
				responseHeaders = v.Data.Headers

			}
			responseBody = append(responseBody, v.Data.Body...)
		}
	}

	md.ResponseStatus = responseLine.Status
	md.ResponseContextType = responseHeaders["Content-Type"]
	md.Tag = []string{responseHeaders["X-Forwarded-For"]}
	if Debug {
		log.Printf("response: %+v", responseLine.String())
		printFormatHeader(responseHeaders)
	}
	if v, ok := responseHeaders["Content-Type"]; ok && !strings.Contains(v, "text/html") {
		if encoding, ok := responseHeaders["Content-Encoding"]; ok && encoding == "gzip" {
			ret, err := ParseGzip(responseBody)
			if err != nil && err.Error() != "unexpected EOF" {
				log.Printf("decode err: %s", err.Error())
			}
			if contentType, ok := responseHeaders["Content-Type"]; ok && (strings.Contains(contentType, "text/plain") || strings.Contains(contentType, "application/json")) {
				log.Printf("response body: %+v", string(ret))
				md.ResponseBody = string(ret)
			}

		} else {
			if contentType, ok := responseHeaders["Content-Type"]; ok && (strings.Contains(contentType, "text/plain") || strings.Contains(contentType, "application/json")) {
				log.Printf("response body: %+v", string(responseBody))
				md.ResponseBody = string(responseBody)
			}
		}
	}
	if Debug {
		log.Printf("model: %+v", md)
	}
	return md
}

func ParseGzip(in []byte) ([]byte, error) {
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
