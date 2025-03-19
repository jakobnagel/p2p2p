package main

import (
	"flag"
	"fmt"
	"net"

	"nagelbros.com/p2p2p/pkg/config"
	"nagelbros.com/p2p2p/pkg/mdns"
	"nagelbros.com/p2p2p/pkg/security"
)

func main() {
	flag.Parse()
	config.Init("client.env")

	command := flag.Arg(0)

	if command == "list-services" {
		listServices()
	}

	if command == "list" {
		addr := flag.Arg(1)
		if addr == "" {
			fmt.Printf("Usage: list <address>\n")
			return
		}

		list(addr)
	}
}

func listServices() {
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
		fmt.Printf("%d. %s:%d\n", i+1, service.AddrV4, service.Port)
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

	secConn, err := security.EstablishSecureConnection(conn, true)
	if err != nil {
		fmt.Printf("Could not establish secure connection: %s", err)
		return
	}

	secConn.Send([]byte("GIVE ME YOUR FILES"))
	secConn.Receive()
}
