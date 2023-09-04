package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/syndtr/goleveldb/leveldb"
	"io"
	"net/url"
	"strings"
)

func SaveHttpData(db *leveldb.DB, mbChan <-chan *MergeBuilder) {
	for mb := range mbChan {
		md := mb.MergeReqAndRes()
		if !strings.Contains(md.ResponseContextType, "text/plain") && !strings.Contains(md.ResponseContextType, "application/json") {
			fmt.Printf("package is no text/plain,application/json")
			continue
		}
		byt, err := json.Marshal(md)
		if err != nil {
			fmt.Printf("marshal error %s\n", err.Error())
			continue
		}
		if err := db.Put([]byte(md.RequestURL), byt, nil); err != nil {
			fmt.Printf("put error %s\n", err.Error())
			continue
		}
	}
}

type MergeBuilder struct {
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
			fmt.Printf("request: %+v\n", v.Data.RequestLine)
			printFormatHeader(v.Data.Headers)
			fmt.Printf("request param: %+v\n", string(v.Data.Body))

			urls, err := url.Parse(v.Data.RequestLine.URN)
			if err != nil {
				fmt.Printf("url.Parse", err.Error())
				continue
			}

			fmt.Println(urls.Path)
			fmt.Println(urls.RawQuery)
			Parma, _ := url.ParseQuery(urls.RawQuery)
			fmt.Println(Parma)
			md.RequestURL = urls.Path
			md.RequestParma = Parma
			md.RequestHeaders = v.Data.Headers
			md.RequestContentType = v.Data.Headers["Content-Type"]
			md.RequestBody = v.Data.Body
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

	fmt.Printf("response: %+v\n", responseLine.String())
	printFormatHeader(responseHeaders)
	if v, ok := responseHeaders["Content-Type"]; ok && !strings.Contains(v, "text/html") {
		if encoding, ok := responseHeaders["Content-Encoding"]; ok && encoding == "gzip" {
			ret, err := GZIPDe(responseBody)
			if err != nil && err.Error() != "unexpected EOF" {
				fmt.Printf("decode err: %s\n", err.Error())
			}
			if contentType, ok := responseHeaders["Content-Type"]; ok && (strings.Contains(contentType, "text/plain") || strings.Contains(contentType, "application/json")) {
				fmt.Printf("response body: %+v\n", string(ret))
				md.ResponseBody = string(ret)
			}

		} else {
			if contentType, ok := responseHeaders["Content-Type"]; ok && (strings.Contains(contentType, "text/plain") || strings.Contains(contentType, "application/json")) {
				fmt.Printf("response body: %+v\n", string(responseBody))
				md.ResponseBody = string(responseBody)
			}
		}
	}
	return md
}

// GZIPDe gzip解密
func GZIPDe(in []byte) ([]byte, error) {
	// 剔除 多余的乱七八糟的头
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
	RequestURL         string              `json:"request_url"`
	RequestParma       map[string][]string `json:"request_parma"`
	RequestHeaders     map[string]string   `json:"request_headers"`
	RequestBody        []byte              `json:"request_body"`
	RequestContentType string              `json:"request_content_type"`

	ResponseStatus      int         `json:"response_status"`
	ResponseContextType string      `json:"response_context_type"`
	ResponseBody        interface{} `json:"response_body"`
}
