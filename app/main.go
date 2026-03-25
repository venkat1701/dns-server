package main

import (
	"fmt"
	"net"
)

// Ensures gofmt doesn't remove the "net" import in stage 1 (feel free to remove this!)
var _ = net.ListenUDP

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	/* ResolveUDPAddr returns an address of UDP end point.
	The network must be a UDP network name.
	If the host in the address parameter is not a literal IP address or the port is not a literal port number, ResolveUDPAddr resolves the address to an address of UDP end point. Otherwise, it parses the address as a pair of literal IP address and port number. The address parameter can use a host name, but this is not recommended, because it will return at most one of the host name's IP addresses. */

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	/*
		ListenUDP acts like ListenPacket for UDP networks. The network must be a UDP network name; see func Dial for details.
		If the IP field of laddr is nil or an unspecified IP address, ListenUDP listens on all available IP addresses of the local system except multicast IP addresses. If the Port field of laddr is 0, a port number is automatically chosen.
	*/
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()
	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}
		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		// Create an empty response
		response := []byte{}
		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
