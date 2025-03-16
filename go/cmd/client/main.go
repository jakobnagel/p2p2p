package main

import (
	"flag"
	"fmt"
	"net"

	"nagelbros.com/p2p2p/pkg/connection"
	"nagelbros.com/p2p2p/pkg/mdns"
)

func main() {
	flag.Parse()

	if flag.Arg(0) == "list-services" {
		listServices()
	}

	if flag.Arg(0) == "list" {
		addr := flag.Arg(1)
		if addr == "" {
			fmt.Printf("Usage: list <address>\n")
			return
		}

		list(addr)
	}
	// port := os.Getenv("PORT")
	// if port == "" {
	// 	port = "8080"
	// }

	// fmt.Printf("Message sent: %d\n", []byte("Poop"))
	// secConn.Send([]byte("Poop"))
}

func listServices() {
	fmt.Printf("Discovering services...\n")
	discovered, err := mdns.Discover()
	if err != nil {
		fmt.Printf("Could not discover services: %s", err)
		return
	}
	if len(discovered) == 0 {
		fmt.Printf("No services discovered\n")
		return
	}
	for i, service := range discovered {
		fmt.Printf("%d. ip: %s port: %d\n", i, service.AddrIPv4[0], service.Port)
	}
}

func list(addr string) {
	// establish connection
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("Could not establish connection with server: %s", err)
		return
	}
	defer conn.Close()

	secConn, err := connection.EstablishSecureConnection(conn, true)
	if err != nil {
		fmt.Printf("Could not establish secure connection: %s", err)
		return
	}

	secConn.Send([]byte("GIVE ME YOUR FILES"))
	secConn.Receive()
}
