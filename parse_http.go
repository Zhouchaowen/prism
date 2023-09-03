package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"io"
	"strconv"
	"strings"
)

const (
	IsRequest  = 1
	IsResponse = 2
)

var mp = map[uint32]*MergeBuilder{}
var ackMp = map[uint32]uint32{}

func ParseHttp(data []byte) error {
	httpData, err := ExtractFlyHttp(data)
	if err != nil {
		return err
	}

	if httpData.Data.Type == IsRequest {
		if Debug {
			fmt.Printf("[HTTP]	Request    Line: %+v\n", httpData.Data.RequestLine.String())
			fmt.Printf("[HTTP]	Request Headers: %+v\n", httpData.Data.Headers)
			fmt.Printf("[HTTP]	Request    Body: %+v\n", string(httpData.Data.Body))
		}

		var mb = MergeBuilder{}
		mb.Seq = httpData.Seq
		mb.Ack = httpData.Ack
		mb.Data = append(mb.Data, httpData)
		mp[httpData.Ack] = &mb
	}

	if httpData.Data.Type == IsResponse { // 防止不是成对出现
		if Debug {
			fmt.Printf("[HTTP]	Response    Line: %+v\n", httpData.Data.ResponseLine.String())
			fmt.Printf("[HTTP]	Response Headers: %+v\n", httpData.Data.Headers)
			//fmt.Printf("[HTTP]	Response    Body: %+v\n", httpData.Data.Body)
		}

		if v, ok := httpData.Data.Headers["Content-Type"]; !ok || v == "text/html" || v == "multipart/form-data" {
			fmt.Printf("skip text/html and multipart/form-data\n")
			return nil
		}

		if v, ok := mp[httpData.Seq]; ok {
			v.Seq = httpData.Seq
			v.Ack = httpData.Ack
			v.ContentLength += len(httpData.Data.Body)
			v.MaxBody, _ = strconv.Atoi(httpData.Data.Headers["Content-Length"])
			fmt.Printf("MaxBody: %d\n", v.MaxBody)
			v.Data = append(v.Data, httpData)

			if v.ContentLength >= v.MaxBody {
				v.MergeReqAndRes()
				delete(mp, httpData.Seq)
			} else {
				// response 第一次返回，后续可能被截断，只保存第一次ack的seq
				ackMp[httpData.Ack] = httpData.Seq
			}
			return nil
		}

		if v, ok := ackMp[httpData.Ack]; ok {
			var mb = mp[v]
			mb.Seq = httpData.Seq
			mb.Ack = httpData.Ack
			mb.ContentLength += len(httpData.Data.Body)
			mb.Data = append(mb.Data, httpData)

			if mb.ContentLength >= mb.MaxBody {
				mb.MergeReqAndRes()
				delete(mp, httpData.Seq)
			}
			return nil
		}

	}
	return nil
}

func ExtractFlyHttp(data []byte) (FlyHttp, error) {
	eth := &layers.Ethernet{}
	ipv4 := &layers.IPv4{}
	stack := []gopacket.DecodingLayer{eth, ipv4}
	nf := gopacket.NilDecodeFeedback
	for _, d := range stack {
		_ = d.DecodeFromBytes(data, nf)
		data = d.LayerPayload()
	}

	if ipv4.Protocol != layers.IPProtocolTCP {
		return FlyHttp{}, errors.New("packet is not tcp")
	}

	tcp := &layers.TCP{}
	stack = []gopacket.DecodingLayer{tcp}
	for _, d := range stack {
		_ = d.DecodeFromBytes(data, nf)
		data = d.LayerPayload()
	}

	if Debug {
		fmt.Printf("[ETH]       SrcMAC: %s,  DstMAC: %s\n", eth.SrcMAC, eth.DstMAC)
		fmt.Printf("[IPV4]       SrcIP: %s,   DstIP: %s\n", ipv4.SrcIP, ipv4.DstIP)
		fmt.Printf("[TCP]      SrcPort: %s, DstPort: %s\n", tcp.SrcPort, tcp.DstPort)
		fmt.Printf("[IPV4]     Version: %d\n", ipv4.Version)
		fmt.Printf("[IPV4]      Length: %d\n", ipv4.Length)
		fmt.Printf("[TCP]          Seq: %d\n", tcp.Seq)
		fmt.Printf("[TCP]          Ack: %d\n", tcp.Ack)
		fmt.Printf("[TCP]          FIN: %t\n", tcp.FIN)
		fmt.Printf("[TCP]          SYN: %t\n", tcp.SYN)
		fmt.Printf("[TCP]          RST: %t\n", tcp.RST)
		fmt.Printf("[TCP]          PSH: %t\n", tcp.PSH)
		fmt.Printf("[TCP]          ACK: %t\n", tcp.ACK)
		fmt.Printf("[TCP]          URG: %t\n", tcp.URG)
		fmt.Printf("[TCP]          ECE: %t\n", tcp.ECE)
		fmt.Printf("[TCP]          CWR: %t\n", tcp.CWR)
		fmt.Printf("[TCP]           NS: %t\n", tcp.NS)
		fmt.Printf("[TCP]       Window: %d\n", tcp.Window)
		fmt.Printf("[TCP]     Checksum: %d\n", tcp.Checksum)
		fmt.Printf("[TCP]       Urgent: %d\n", tcp.Urgent)
		fmt.Printf("[TCP]      Options: %d\n", tcp.Options)
		fmt.Printf("[TCP]      Padding: %+v\n", tcp.Padding)
	}

	httpData := ParseHttpData(data)

	fmt.Printf("response:%+v\n", httpData.Body)

	return FlyHttp{
		Seq:  tcp.Seq,
		Ack:  tcp.Ack,
		Data: httpData,
	}, nil
}

func ParseHttpData(data []byte) HttpData {
	// 将二进制数据转换为字符串
	rawData := string(data)

	// 切分请求头和请求体
	parts := strings.SplitN(rawData, "\r\n\r\n", 2)
	headerPart := parts[0]
	bodyPart := ""
	if len(parts) > 1 {
		bodyPart = parts[1]
	} else {
		fmt.Printf("is truncation\n")
		// 被截断了
		return HttpData{
			IsTruncation: true,
			Type:         IsResponse,
			Body:         bytes.NewBufferString(headerPart).Bytes(),
		}
	}

	// 解析请求行和请求头
	headerLines := strings.Split(headerPart, "\r\n")
	firstLine := headerLines[0]
	headers := make(map[string]string)
	for _, line := range headerLines[1:] {
		headerParts := strings.SplitN(line, ":", 2)
		if len(headerParts) == 2 {
			headerName := strings.TrimSpace(headerParts[0])
			headerValue := strings.TrimSpace(headerParts[1])
			headers[headerName] = headerValue
		}
	}
	var ret = HttpData{
		Type:    RequestOrResponse(firstLine),
		Headers: headers,
		Body:    bytes.NewBufferString(bodyPart).Bytes(),
	}
	if ret.Type == IsRequest {
		ret.RequestLine.parseFirstLine(firstLine)
	} else {
		ret.ResponseLine.parseFirstLine(firstLine)
	}

	return ret
}

func RequestOrResponse(FirstLine string) int {
	lines := strings.Split(FirstLine, " ")
	// 肯定是截断数据
	if len(lines) > 3 {
		return IsResponse
	}
	// 2 Response
	if strings.Contains(lines[0], "HTTP") {
		return IsResponse
	}
	// 1 Request
	return IsRequest
}

type FlyHttp struct {
	Seq  uint32   `json:"seq"`
	Ack  uint32   `json:"ack"`
	Data HttpData `json:"data"`
}

type HttpData struct {
	Type         int
	RequestLine  RequestLine
	ResponseLine ResponseLine
	IsTruncation bool
	Headers      map[string]string
	Body         []byte
}

type FirstLine interface {
	parseFirstLine(data string)
	isErr() error
}

// RequestLine GET / HTTP/1.1
type RequestLine struct {
	err     error  `json:"err"`
	Method  string `json:"method"`
	URN     string `json:"urn"`
	Version string `json:"version"`
}

func (r RequestLine) String() string {
	return fmt.Sprintf("Method:%s URN:%s Version:%s", r.Method, r.URN, r.Version)
}

func (r *RequestLine) parseFirstLine(data string) {
	tmp := strings.TrimSpace(data)
	requestLineInfos := strings.Split(tmp, " ")
	if len(requestLineInfos) < 3 {
		r.err = errors.New(fmt.Sprintf("requestLine [%s] format err", data))
		return
	}
	r.Method = requestLineInfos[0]
	r.URN = requestLineInfos[1]
	r.Version = requestLineInfos[2]
}

func (r *RequestLine) isErr() error {
	return r.err
}

// ResponseLine HTTP/1.1 200 OK
type ResponseLine struct {
	err        error  `json:"err"`
	Version    string `json:"version"`
	Status     int    `json:"status"`
	StatusCode string `json:"status_code"`
}

func (r ResponseLine) String() string {
	return fmt.Sprintf("Version:%s Status:%d Code:%s", r.Version, r.Status, r.StatusCode)
}

func (r *ResponseLine) parseFirstLine(data string) {
	tmp := strings.TrimSpace(data)
	requestLineInfos := strings.Split(tmp, " ")
	if len(requestLineInfos) < 3 {
		r.err = errors.New(fmt.Sprintf("requestLine [%s] format err", data))
		return
	}
	r.Version = requestLineInfos[0]
	r.Status, _ = strconv.Atoi(requestLineInfos[1])
	r.StatusCode = requestLineInfos[2]
}

func (r *ResponseLine) isErr() error {
	return r.err
}

type MergeBuilder struct {
	Seq           uint32    `json:"seq"`
	Ack           uint32    `json:"ack"`
	ContentLength int       `json:"content_length"`
	MaxBody       int       `json:"max_body"`
	Data          []FlyHttp `json:"data"`
}

func (m MergeBuilder) MergeReqAndRes() {
	var responseLine string
	var responseHeaders map[string]string
	var responseBody []byte
	for _, v := range m.Data {
		if v.Data.Type == IsRequest {
			fmt.Printf("request: %+v\n", v.Data.RequestLine)
			fmt.Printf("header: %+v\n", v.Data.Headers)
			if header, ok := v.Data.Headers["Content-Type"]; ok && header != "multipart/form-data" {
				fmt.Printf("request param: %+v\n", string(v.Data.Body))
			}
			continue
		}

		if v.Data.Type == IsResponse {
			if v.Data.ResponseLine.Status != 0 {
				responseLine = v.Data.ResponseLine.String()
				responseHeaders = v.Data.Headers
			}
			responseBody = append(responseBody, v.Data.Body...)
		}
	}
	fmt.Printf("response: %+v\n", responseLine)
	fmt.Printf("header: %+v\n", responseHeaders)
	if v, ok := responseHeaders["Content-Type"]; ok && v != "text/html" {
		if encoding, ok := responseHeaders["Content-Encoding"]; ok && encoding == "gzip" {
			// 剔除[0:4]的协议头
			ret, err := GZIPDe(responseBody[4:])
			if err != nil && err.Error() != "unexpected EOF" {
				fmt.Printf("decode err: %s\n", err.Error())
				return
			}
			fmt.Printf("response body: %+v\n", string(ret))
		} else {
			fmt.Printf("response body: %+v\n", string(responseBody))
		}
	}
}

// GZIPDe gzip解密
func GZIPDe(in []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(in))
	if err != nil {
		var out []byte
		return out, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}
