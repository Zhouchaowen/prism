package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"strconv"
	"strings"
	"time"
)

const (
	IsRequest                    = 1
	IsResponse                   = 2
	ContentType                  = "Content-Type"
	ContentLength                = "Content-Length"
	ContentEncoding              = "Content-Encoding"
	ContentTypeJSON              = "application/json"
	ContentTypeHTML              = "text/html"
	ContentTypePlain             = "text/plain"
	ContentTypeForm              = "application/x-www-form-urlencoded"
	ContentTypeMultipartPOSTForm = "multipart/form-data"

	XForwardedFor    = "X-Forwarded-For"
	TransferEncoding = "Transfer-Encoding"
	HTTP             = "HTTP"
)

func ParseHttp(data []byte) error {
	if Debug && Verbose {
		log.Printf("[PRISM] data:%+v", data)
	}

	flyHttp, err := extractFlyHttp(data)
	if err != nil {
		log.Printf("[ERROR] extract fly http error (%+v)", err.Error())
		return err
	}

	rType := flyHttp.Data.Type
	if rType == IsRequest {
		if Debug && Verbose {
			log.Printf("[PRISM] HTTP Request Body: %+v", string(flyHttp.Data.Body))
			log.Println()
		}
		ackToRequest.Save(flyHttp)
	}

	if rType == IsResponse {
		if Debug && Verbose {
			log.Printf("[PRISM] HTTP Response Body: %+v", flyHttp.Data.Body)
			log.Println()
		}

		// If the response http data is not truncated, the seq to ack mapping is saved,
		// through which the request can be associated with multiple responses.
		if !flyHttp.Data.IsTruncation {
			seqToAck.Save(flyHttp)
		}

		ackToResponse.Save(flyHttp)
	}

	return nil
}

func extractFlyHttp(data []byte) (FlyHttp, error) {
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
		log.Printf("[PRISM] ETH   SrcMAC: %s,  DstMAC: %s", eth.SrcMAC, eth.DstMAC)
		log.Printf("[PRISM] IPV4   SrcIP: %s,   DstIP: %s", ipv4.SrcIP, ipv4.DstIP)
		log.Printf("[PRISM] TCP  SrcPort: %s, DstPort: %s", tcp.SrcPort, tcp.DstPort)
		log.Printf("[PRISM] IPV4 Version: %d", ipv4.Version)
		log.Printf("[PRISM] IPV4  Length: %d", ipv4.Length)
		log.Printf("[PRISM] TCP      Seq: %d", tcp.Seq)
		log.Printf("[PRISM] TCP      Ack: %d", tcp.Ack)
		log.Printf("[PRISM] TCP      FIN: %t", tcp.FIN)
		log.Printf("[PRISM] TCP      SYN: %t", tcp.SYN)
		log.Printf("[PRISM] TCP      RST: %t", tcp.RST)
		log.Printf("[PRISM] TCP      PSH: %t", tcp.PSH)
		log.Printf("[PRISM] TCP      ACK: %t", tcp.ACK)
		log.Printf("[PRISM] TCP      URG: %t", tcp.URG)
		log.Printf("[PRISM] TCP      ECE: %t", tcp.ECE)
		log.Printf("[PRISM] TCP      CWR: %t", tcp.CWR)
		log.Printf("[PRISM] TCP       NS: %t", tcp.NS)
		log.Printf("[PRISM] TCP   Window: %d", tcp.Window)
		log.Printf("[PRISM] TCP Checksum: %d", tcp.Checksum)
		log.Printf("[PRISM] TCP   Urgent: %d", tcp.Urgent)
		log.Printf("[PRISM] TCP  Options: %d", tcp.Options)
		log.Printf("[PRISM] TCP  Padding: %+v", tcp.Padding)
	}

	reqOrResData := parseReqOrResData(data)

	if reqOrResData.Type == IsRequest {
		if Debug && !reqOrResData.IsTruncation {
			log.Printf("[HTTP] Request    Line: %+v", reqOrResData.RequestLine.String())
			log.Printf("[HTTP] Request Headers: %+v", reqOrResData.Headers)
			log.Println()
		}
	}

	if reqOrResData.Type == IsResponse {
		if Debug && !reqOrResData.IsTruncation {
			log.Printf("[PRISM] HTTP Response    Line: %+v", reqOrResData.ResponseLine.String())
			log.Printf("[PRISM] HTTP Response Headers: %+v", reqOrResData.Headers)
			log.Println()
		}
	}

	return FlyHttp{
		SrcMAC:     eth.SrcMAC.String(),
		DstMAC:     eth.DstMAC.String(),
		SrcIP:      ipv4.SrcIP.String(),
		DstIP:      ipv4.DstIP.String(),
		SrcPort:    tcp.SrcPort.String(),
		DstPort:    tcp.DstPort.String(),
		Seq:        tcp.Seq,
		Ack:        tcp.Ack,
		Data:       reqOrResData,
		CreateTime: time.Now(),
	}, nil
}

func parseReqOrResData(data []byte) ReqOrResData {
	rawData := string(data)

	// split request headers and request bodies
	parts := strings.SplitN(rawData, "\r\n\r\n", 2)
	headerPart := parts[0]

	IsTruncation := true
	// check whether response data is truncated
	if len(parts) > 1 {
		headerLines := strings.Split(headerPart, "\r\n")
		if len(headerLines) > 1 {
			firstLine := strings.Split(strings.TrimSpace(headerLines[0]), " ")
			if len(firstLine) == 3 && strings.Contains(headerLines[0], HTTP) {
				IsTruncation = false
			}
		}
	}

	if IsTruncation {
		if Debug {
			log.Printf("[PRISM] HTTP is truncation")
		}
		// is truncation
		return ReqOrResData{
			IsTruncation: true,
			Type:         IsResponse,
			Body:         bytes.NewBufferString(headerPart).Bytes(),
		}
	}

	bodyPart := parts[1]

	// parse request lines and headers
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

	var ret = ReqOrResData{
		Type:    requestOrResponse(firstLine),
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

func requestOrResponse(FirstLine string) int {
	lines := strings.Split(FirstLine, " ")
	// 肯定是截断数据
	if len(lines) > 3 {
		return IsResponse
	}
	// 2 Response
	if strings.Contains(lines[0], HTTP) {
		return IsResponse
	}
	// 1 Request
	return IsRequest
}

type FlyHttp struct {
	SrcMAC     string       `json:"request_src_mac"`
	DstMAC     string       `json:"request_dst_mac"`
	SrcIP      string       `json:"request_src_ip"`
	DstIP      string       `json:"request_dst_ip"`
	SrcPort    string       `json:"request_src_port"`
	DstPort    string       `json:"request_dst_port"`
	Seq        uint32       `json:"seq"`
	Ack        uint32       `json:"ack"`
	Data       ReqOrResData `json:"data"`
	CreateTime time.Time    `json:"create_time"`
}

type ReqOrResData struct {
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
