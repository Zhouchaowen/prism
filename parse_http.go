package main

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"strconv"
	"strings"
)

const (
	Max        = 10000
	IsRequest  = 1
	IsResponse = 2
)

var stack DateStack

func init() {
	stack = DateStack{
		Stack: make([]HttpData, Max),
		Index: 0,
		Cap:   Max,
	}
}

func ParseHttp(direction uint32, data []byte) error {
	httpData, err := ExtractHttpData(data)
	if err != nil {
		return err
	}

	if len(httpData) == 0 {
		return errors.New("no http data")
	}

	httpD := ParseHttpData(httpData)

	flag := httpD.RequestOrResponse()
	if flag == IsRequest {
		fmt.Printf("[HTTP]	Request Line: %+v\n", httpD.FirstLine)
		fmt.Printf("[HTTP]	Request Body: %+v\n", httpD.Body)
	}

	if flag == IsResponse { // 防止不是成对出现
		fmt.Printf("[HTTP]	Response Line: %+v\n", httpD.FirstLine)
		fmt.Printf("[HTTP]	Response Body: %+v\n", httpD.Body)
	}
	return nil
}

func ExtractHttpData(data []byte) ([]byte, error) {
	eth := &layers.Ethernet{}
	ipv4 := &layers.IPv4{}
	stack := []gopacket.DecodingLayer{eth, ipv4}
	nf := gopacket.NilDecodeFeedback
	for _, d := range stack {
		_ = d.DecodeFromBytes(data, nf)
		data = d.LayerPayload()
	}

	if ipv4.Protocol != layers.IPProtocolTCP {
		return nil, errors.New("packet is not tcp")
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
	return data, nil
}

type HttpData struct {
	IsTruncation bool
	FirstLine    string
	Headers      map[string]string
	Body         string
}

func (h HttpData) RequestOrResponse() int {
	lines := strings.Split(h.FirstLine, " ")
	// 肯定是截断数据
	if len(lines) > 3 || h.IsTruncation {
		return IsResponse
	}
	// 2 Response
	if strings.Contains(lines[0], "HTTP") {
		return IsResponse
	}
	// 1 Request
	return IsRequest
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
			Body:         headerPart,
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

	return HttpData{
		FirstLine: firstLine,
		Headers:   headers,
		Body:      bodyPart,
	}
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
