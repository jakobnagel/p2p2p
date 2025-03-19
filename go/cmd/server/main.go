package main

import (
	"fmt"
	"net"
	"strconv"

	// "time"
	"os"

	"nagelbros.com/p2p2p/pkg/config"
	"nagelbros.com/p2p2p/pkg/mdns"
	"nagelbros.com/p2p2p/pkg/security"
	// "strings"
)

func main() {
	config.Init("server.env")

	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println("Error getting hostname: ", err)
		return
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		fmt.Println("Error converting port to integer: ", err)
		return
	}

	mdnsServer, err := mdns.Publish(hostname, portInt, "p2p2p server")
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	defer mdnsServer.Shutdown()

	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%s", port))
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	defer listener.Close()

	fmt.Printf("Server is listening on %s\n", listener.Addr().String())

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error: ", err)
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	secureConn, err := security.EstablishSecureConnection(conn, false)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	buff, err := secureConn.Receive()
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	fmt.Printf("Received from client: %d\n", buff)
}
