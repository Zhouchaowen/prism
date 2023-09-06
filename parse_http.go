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
)

const (
	IsRequest  = 1
	IsResponse = 2
)

var mergeMp = map[uint32]*MergeBuilder{}
var ackMp = map[uint32]uint32{}

func parseHttp(saveChan chan *MergeBuilder, data []byte) error {
	httpData, err := extractFlyHttp(data)
	if err != nil {
		return err
	}

	if httpData.Data.Type == IsRequest {
		if Debug {
			log.Printf("[HTTP]	Request    Line: %+v", httpData.Data.RequestLine.String())
			log.Printf("[HTTP]	Request Headers: %+v", httpData.Data.Headers)
			log.Printf("[HTTP]	Request    Body: %+v", string(httpData.Data.Body))
			log.Println()
		}

		mb := MergeBuilder{
			Seq:     httpData.Seq,
			Ack:     httpData.Ack,
			SrcMAC:  httpData.SrcMAC,
			DstMAC:  httpData.DstMAC,
			SrcIP:   httpData.SrcIP,
			DstIP:   httpData.DstIP,
			SrcPort: httpData.SrcPort,
			DstPort: httpData.DstPort,
		}
		mb.Data = append(mb.Data, httpData)

		mergeMp[httpData.Ack] = &mb
	}

	// prevent not appearing in pairs
	if httpData.Data.Type == IsResponse {
		if Debug {
			log.Printf("[HTTP]	Response    Line: %+v", httpData.Data.ResponseLine.String())
			log.Printf("[HTTP]	Response Headers: %+v", httpData.Data.Headers)
			if Verbose {
				log.Printf("[HTTP]	Response    Body: %+v", httpData.Data.Body)
			}
			log.Println()
		}

		if v, ok := mergeMp[httpData.Seq]; ok {
			v.Seq = httpData.Seq
			v.Ack = httpData.Ack
			v.ContentLength += len(httpData.Data.Body)
			v.MaxBody, _ = strconv.Atoi(httpData.Data.Headers["Content-Length"])
			v.Data = append(v.Data, httpData)

			if v.ContentLength >= v.MaxBody {
				saveChan <- v
				delete(mergeMp, httpData.Seq)
			} else {
				// the first return may be truncated later, and only the seq of the first ack is saved.
				ackMp[httpData.Ack] = httpData.Seq
			}
			return nil
		}

		if v, ok := ackMp[httpData.Ack]; ok {
			var mb = mergeMp[v]
			mb.Seq = httpData.Seq
			mb.Ack = httpData.Ack
			mb.ContentLength += len(httpData.Data.Body)
			mb.Data = append(mb.Data, httpData)

			if mb.ContentLength >= mb.MaxBody {
				saveChan <- mb
				delete(mergeMp, httpData.Seq)
			}
			return nil
		}

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
		log.Printf("[ETH]       SrcMAC: %s,  DstMAC: %s", eth.SrcMAC, eth.DstMAC)
		log.Printf("[IPV4]       SrcIP: %s,   DstIP: %s", ipv4.SrcIP, ipv4.DstIP)
		log.Printf("[TCP]      SrcPort: %s, DstPort: %s", tcp.SrcPort, tcp.DstPort)
		log.Printf("[IPV4]     Version: %d", ipv4.Version)
		log.Printf("[IPV4]      Length: %d", ipv4.Length)
		log.Printf("[TCP]          Seq: %d", tcp.Seq)
		log.Printf("[TCP]          Ack: %d", tcp.Ack)
		log.Printf("[TCP]          FIN: %t", tcp.FIN)
		log.Printf("[TCP]          SYN: %t", tcp.SYN)
		log.Printf("[TCP]          RST: %t", tcp.RST)
		log.Printf("[TCP]          PSH: %t", tcp.PSH)
		log.Printf("[TCP]          ACK: %t", tcp.ACK)
		log.Printf("[TCP]          URG: %t", tcp.URG)
		log.Printf("[TCP]          ECE: %t", tcp.ECE)
		log.Printf("[TCP]          CWR: %t", tcp.CWR)
		log.Printf("[TCP]           NS: %t", tcp.NS)
		log.Printf("[TCP]       Window: %d", tcp.Window)
		log.Printf("[TCP]     Checksum: %d", tcp.Checksum)
		log.Printf("[TCP]       Urgent: %d", tcp.Urgent)
		log.Printf("[TCP]      Options: %d", tcp.Options)
		log.Printf("[TCP]      Padding: %+v", tcp.Padding)
	}

	httpData := parseHttpData(data)

	return FlyHttp{
		SrcMAC:  eth.SrcMAC.String(),
		DstMAC:  eth.DstMAC.String(),
		SrcIP:   ipv4.SrcIP.String(),
		DstIP:   ipv4.DstIP.String(),
		SrcPort: tcp.SrcPort.String(),
		DstPort: tcp.DstPort.String(),
		Seq:     tcp.Seq,
		Ack:     tcp.Ack,
		Data:    httpData,
	}, nil
}

func parseHttpData(data []byte) HttpData {
	rawData := string(data)

	// split request headers and request bodies
	parts := strings.SplitN(rawData, "\r\n\r\n", 2)
	headerPart := parts[0]
	bodyPart := ""
	if len(parts) > 1 {
		bodyPart = parts[1]
	} else {
		if Debug {
			log.Printf("is truncation")
		}
		// is truncation
		return HttpData{
			IsTruncation: true,
			Type:         IsResponse,
			Body:         bytes.NewBufferString(headerPart).Bytes(),
		}
	}

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
	var ret = HttpData{
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
	if strings.Contains(lines[0], "HTTP") {
		return IsResponse
	}
	// 1 Request
	return IsRequest
}

type FlyHttp struct {
	SrcMAC  string   `json:"request_src_mac"`
	DstMAC  string   `json:"request_dst_mac"`
	SrcIP   string   `json:"request_src_ip"`
	DstIP   string   `json:"request_dst_ip"`
	SrcPort string   `json:"request_src_port"`
	DstPort string   `json:"request_dst_port"`
	Seq     uint32   `json:"seq"`
	Ack     uint32   `json:"ack"`
	Data    HttpData `json:"data"`
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
