package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"time"
)

// Structs for DNS Header
type DNSHeader struct {
	ID      uint16 // 16 bits - Packet Identifier
	QR      byte   // 1 bit  - Query/Response Indicator (0=query, 1=response)
	OPCODE  byte   // 4 bits - Operation Code
	AA      byte   // 1 bit  - Authoritative Answer
	TC      byte   // 1 bit  - Truncation
	RD      byte   // 1 bit  - Recursion Desired
	RA      byte   // 1 bit  - Recursion Available
	Z       byte   // 3 bits - Reserved (DNSSEC)
	RCODE   byte   // 4 bits - Response Code
	QDCount uint16 // 16 bits - Question Count
	ANCount uint16 // 16 bits - Answer Record Count
	NSCount uint16 // 16 bits - Authority Record Count
	ARCount uint16 // 16 bits - Additional Record Count
}

type DNSQuestion struct {
	Name  []byte
	Type  uint16
	Class uint16
}

type DNSAnswer struct {
	Name     []byte
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

// Marshal packs the header into 12 bytes (BigEndian per RFC1035
// Byte layout of the flags word(bytes 2-3):
// 0                   1                   2                   3
// Bit: 15    14-11    10   9    8    7	  6-4   3-0
// Field QR | OPCODE | AA | TC | RD | RA | Z | RCODE
func (h *DNSHeader) Marshal() []byte {
	buf := make([]byte, 12) // 12 bytes for header
	binary.BigEndian.PutUint16(buf[0:2], h.ID)

	flags := uint16(h.QR&0x1)<<15 | uint16(h.OPCODE&0xF)<<11 | uint16(h.AA&0x1)<<10 | uint16(h.TC&0x1)<<9 | uint16(h.RD&0x1)<<8 | uint16(h.RA&0x1)<<7 | uint16(h.Z&0x7)<<4 | uint16(h.RCODE&0xF)
	binary.BigEndian.PutUint16(buf[2:4], flags)
	binary.BigEndian.PutUint16(buf[4:6], h.QDCount)
	binary.BigEndian.PutUint16(buf[6:8], h.ANCount)
	binary.BigEndian.PutUint16(buf[8:10], h.NSCount)
	binary.BigEndian.PutUint16(buf[10:12], h.ARCount)
	return buf
}

func ParseDNSHeader(data []byte) (DNSHeader, error) {
	if len(data) < 12 {
		return DNSHeader{}, fmt.Errorf("buffer too short: need 12 bytes, got %d", len(data))
	}

	flags := binary.BigEndian.Uint16(data[2:4])
	return DNSHeader{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		QR:      byte((flags >> 15) & 0x1),
		OPCODE:  byte((flags >> 11) & 0xF),
		AA:      byte((flags >> 10) & 0x1),
		TC:      byte((flags >> 9) & 0x1),
		RD:      byte((flags >> 8) & 0x1),
		RA:      byte((flags >> 7) & 0x1),
		Z:       byte((flags >> 4) & 0x7),
		RCODE:   byte(flags & 0xF),
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
		NSCount: binary.BigEndian.Uint16(data[8:10]),
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}, nil
}

func ParseDNSName(data []byte, offset int) ([]byte, int, error) {
	if offset >= len(data) {
		return nil, offset, fmt.Errorf("name offset out of bounds: %d", offset)
	}

	name := make([]byte, 0, 64)
	nextOffset := offset
	jumped := false
	visited := map[int]bool{}

	for {
		if offset >= len(data) {
			return nil, nextOffset, fmt.Errorf("unterminated DNS name")
		}

		length := data[offset]

		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return nil, nextOffset, fmt.Errorf("truncated compressed DNS pointer")
			}

			pointer := int(length&0x3F)<<8 | int(data[offset+1])
			if pointer >= len(data) {
				return nil, nextOffset, fmt.Errorf("compressed DNS pointer out of bounds")
			}

			if visited[pointer] {
				return nil, nextOffset, fmt.Errorf("compressed DNS pointer loop detected")
			}
			visited[pointer] = true

			if !jumped {
				nextOffset = offset + 2
				jumped = true
			}

			offset = pointer
			continue
		}

		if length&0xC0 != 0 {
			return nil, nextOffset, fmt.Errorf("invalid DNS label length byte: %d", length)
		}

		offset++
		if length == 0 {
			name = append(name, 0x00)
			if !jumped {
				nextOffset = offset
			}
			break
		}

		if offset+int(length) > len(data) {
			return nil, nextOffset, fmt.Errorf("label exceeds packet length")
		}

		name = append(name, length)
		name = append(name, data[offset:offset+int(length)]...)
		offset += int(length)
	}

	return name, nextOffset, nil
}

func ParseDNSQuestion(data []byte, offset int) (DNSQuestion, int, error) {
	if offset >= len(data) {
		return DNSQuestion{}, offset, fmt.Errorf("question offset out of bounds: %d", offset)
	}

	name, nextOffset, err := ParseDNSName(data, offset)
	if err != nil {
		return DNSQuestion{}, offset, err
	}

	if nextOffset+4 > len(data) {
		return DNSQuestion{}, nextOffset, fmt.Errorf("question missing type/class")
	}

	q := DNSQuestion{
		Name:  name,
		Type:  binary.BigEndian.Uint16(data[nextOffset : nextOffset+2]),
		Class: binary.BigEndian.Uint16(data[nextOffset+2 : nextOffset+4]),
	}

	return q, nextOffset + 4, nil
}

func ParseDNSAnswer(data []byte, offset int) (DNSAnswer, int, error) {
	name, nextOffset, err := ParseDNSName(data, offset)
	if err != nil {
		return DNSAnswer{}, offset, err
	}

	if nextOffset+10 > len(data) {
		return DNSAnswer{}, nextOffset, fmt.Errorf("answer missing fixed fields")
	}

	rdLength := binary.BigEndian.Uint16(data[nextOffset+8 : nextOffset+10])
	rDataStart := nextOffset + 10
	rDataEnd := rDataStart + int(rdLength)
	if rDataEnd > len(data) {
		return DNSAnswer{}, nextOffset, fmt.Errorf("answer rdata exceeds packet length")
	}

	answer := DNSAnswer{
		Name:     name,
		Type:     binary.BigEndian.Uint16(data[nextOffset : nextOffset+2]),
		Class:    binary.BigEndian.Uint16(data[nextOffset+2 : nextOffset+4]),
		TTL:      binary.BigEndian.Uint32(data[nextOffset+4 : nextOffset+8]),
		RDLength: rdLength,
		RData:    append([]byte(nil), data[rDataStart:rDataEnd]...),
	}

	return answer, rDataEnd, nil
}

func parseQuestionsAndAnswers(data []byte, header DNSHeader) ([]DNSQuestion, []DNSAnswer, error) {
	offset := 12
	questions := make([]DNSQuestion, 0, header.QDCount)
	for i := 0; i < int(header.QDCount); i++ {
		question, nextOffset, err := ParseDNSQuestion(data, offset)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing DNS question %d: %w", i+1, err)
		}
		questions = append(questions, question)
		offset = nextOffset
	}

	answers := make([]DNSAnswer, 0, header.ANCount)
	for i := 0; i < int(header.ANCount); i++ {
		answer, nextOffset, err := ParseDNSAnswer(data, offset)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing DNS answer %d: %w", i+1, err)
		}
		answers = append(answers, answer)
		offset = nextOffset
	}

	return questions, answers, nil
}

func buildQueryPacket(requestHeader DNSHeader, question DNSQuestion) []byte {
	queryHeader := DNSHeader{
		ID:      requestHeader.ID,
		QR:      0,
		OPCODE:  requestHeader.OPCODE,
		AA:      0,
		TC:      0,
		RD:      requestHeader.RD,
		RA:      0,
		Z:       0,
		RCODE:   0,
		QDCount: 1,
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}

	packet := queryHeader.Marshal()
	packet = append(packet, question.Marshal()...)
	return packet
}

func (s *UDPServer) forwardAnswers(requestHeader DNSHeader, questions []DNSQuestion) ([]DNSAnswer, error) {
	resolverAddr, err := net.ResolveUDPAddr("udp", s.resolverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolving resolver address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, resolverAddr)
	if err != nil {
		return nil, fmt.Errorf("dialing resolver: %w", err)
	}
	defer conn.Close()

	allAnswers := make([]DNSAnswer, 0, len(questions))
	buf := make([]byte, 512)

	for i, question := range questions {
		queryPacket := buildQueryPacket(requestHeader, question)
		if _, err := conn.Write(queryPacket); err != nil {
			return nil, fmt.Errorf("forwarding question %d: %w", i+1, err)
		}

		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return nil, fmt.Errorf("setting resolver read deadline: %w", err)
		}

		n, err := conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("reading resolver response for question %d: %w", i+1, err)
		}

		respHeader, err := ParseDNSHeader(buf[:n])
		if err != nil {
			return nil, fmt.Errorf("parsing resolver header for question %d: %w", i+1, err)
		}

		_, answers, err := parseQuestionsAndAnswers(buf[:n], respHeader)
		if err != nil {
			return nil, fmt.Errorf("parsing resolver body for question %d: %w", i+1, err)
		}

		allAnswers = append(allAnswers, answers...)
	}

	return allAnswers, nil
}

func (q *DNSQuestion) Marshal() []byte {
	buf := make([]byte, 0, len(q.Name)+4)
	buf = append(buf, q.Name...)
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, q.Type)
	buf = append(buf, tmp...)
	binary.BigEndian.PutUint16(tmp, q.Class)
	buf = append(buf, tmp...)
	return buf
}

func (a *DNSAnswer) Marshal() []byte {
	buf := make([]byte, 0, len(a.Name)+10+len(a.RData))
	buf = append(buf, a.Name...)

	tmp2 := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp2, a.Type)
	buf = append(buf, tmp2...)
	binary.BigEndian.PutUint16(tmp2, a.Class)
	buf = append(buf, tmp2...)

	tmp4 := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp4, a.TTL)
	buf = append(buf, tmp4...)

	binary.BigEndian.PutUint16(tmp2, a.RDLength)
	buf = append(buf, tmp2...)
	buf = append(buf, a.RData...)

	return buf
}

type UDPServer struct {
	addr         string
	resolverAddr string
	conn         *net.UDPConn
}

func NewUDPServer(addr, resolverAddr string) *UDPServer {
	return &UDPServer{addr: addr, resolverAddr: resolverAddr}
}

func (s *UDPServer) Start() error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return fmt.Errorf("resolving address: %w", err)
	}

	s.conn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("binding to address: %w", err)
	}
	defer s.conn.Close()

	log.Printf("DNS server listening on %s", s.addr)

	buf := make([]byte, 512)
	for {
		size, source, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Error receiving data: %v", err)
			break
		}

		log.Printf("Received %d bytes from %s", size, source)

		if err := s.handleQuery(buf[:size], source); err != nil {
			log.Printf("Error handling query from %s: %v", source, err)
		}
	}
	return nil
}

func (s *UDPServer) handleQuery(data []byte, source *net.UDPAddr) error {
	header, err := ParseDNSHeader(data)
	if err != nil {
		return fmt.Errorf("parsing DNS header: %w", err)
	}

	questions, _, err := parseQuestionsAndAnswers(data, header)
	if err != nil {
		return fmt.Errorf("parsing DNS packet body: %w", err)
	}

	rcode := byte(0)
	if header.OPCODE != 0 {
		rcode = 4
	}

	respHeader := DNSHeader{
		ID:      header.ID,
		QR:      1, // Response
		OPCODE:  header.OPCODE,
		AA:      0, // Authoritative Answer
		TC:      0, // Not truncated
		RD:      header.RD,
		RA:      0, // Recursion not available
		Z:       0,
		RCODE:   rcode,
		QDCount: uint16(len(questions)),
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}

	response := respHeader.Marshal()
	for _, question := range questions {
		response = append(response, question.Marshal()...)
	}

	if rcode == 0 {
		answers := make([]DNSAnswer, 0, len(questions))
		if s.resolverAddr != "" {
			answers, err = s.forwardAnswers(header, questions)
			if err != nil {
				return err
			}
		} else {
			for _, question := range questions {
				answers = append(answers, DNSAnswer{
					Name:     question.Name,
					Type:     question.Type,
					Class:    question.Class,
					TTL:      60,
					RDLength: 4,
					RData:    []byte{8, 8, 8, 8},
				})
			}
		}

		respHeader.ANCount = uint16(len(answers))
		response = respHeader.Marshal()
		for _, question := range questions {
			response = append(response, question.Marshal()...)
		}
		for _, answer := range answers {
			response = append(response, answer.Marshal()...)
		}
	}

	_, err = s.conn.WriteToUDP(response, source)
	if err != nil {
		return fmt.Errorf("sending response: %w", err)
	}

	log.Printf("Sent response to %s (ID: %d, OPCODE: %d, RCODE: %d)",
		source, respHeader.ID, respHeader.OPCODE, respHeader.RCODE)
	return nil
}

// Ensures gofmt doesn't remove the "net" import in stage 1 (feel free to remove this!)
var _ = net.ListenUDP

func main() {
	resolverAddr := flag.String("resolver", "", "upstream DNS resolver address in ip:port form")
	flag.Parse()

	server := NewUDPServer("127.0.0.1:2053", *resolverAddr)
	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}

	// // You can use print statements as follows for debugging, they'll be visible when running tests.
	// fmt.Println("Logs from your program will appear here!")

	// /* ResolveUDPAddr returns an address of UDP end point.
	// The network must be a UDP network name.
	// If the host in the address parameter is not a literal IP address or the port is not a literal port number, ResolveUDPAddr resolves the address to an address of UDP end point. Otherwise, it parses the address as a pair of literal IP address and port number. The address parameter can use a host name, but this is not recommended, because it will return at most one of the host name's IP addresses. */

	// udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	// if err != nil {
	// 	fmt.Println("Failed to resolve UDP address:", err)
	// 	return
	// }

	// /*
	// 	ListenUDP acts like ListenPacket for UDP networks. The network must be a UDP network name; see func Dial for details.
	// 	If the IP field of laddr is nil or an unspecified IP address, ListenUDP listens on all available IP addresses of the local system except multicast IP addresses. If the Port field of laddr is 0, a port number is automatically chosen.
	// */
	// udpConn, err := net.ListenUDP("udp", udpAddr)
	// if err != nil {
	// 	fmt.Println("Failed to bind to address:", err)
	// 	return
	// }
	// defer udpConn.Close()
	// buf := make([]byte, 512)

	// for {
	// 	size, source, err := udpConn.ReadFromUDP(buf)
	// 	if err != nil {
	// 		fmt.Println("Error receiving data:", err)
	// 		break
	// 	}
	// 	receivedData := string(buf[:size])
	// 	fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

	// 	// Create an empty response
	// 	response := []byte{}
	// 	_, err = udpConn.WriteToUDP(response, source)
	// 	if err != nil {
	// 		fmt.Println("Failed to send response:", err)
	// 	}
	// }
}
