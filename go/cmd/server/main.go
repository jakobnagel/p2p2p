package main

import (
	"fmt"
	"net"
	"strconv"

	// "time"
	"os"

	"google.golang.org/protobuf/proto"
	"nagelbros.com/p2p2p/pkg/config"
	"nagelbros.com/p2p2p/pkg/io"
	"nagelbros.com/p2p2p/pkg/mdns"
	"nagelbros.com/p2p2p/pkg/security"
	"nagelbros.com/p2p2p/types/message"
	// "strings"
)

func init() {
	config.Init("server.env")
	os.MkdirAll(config.Cfg.FileDir, 0755)
}

func main() {
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

	msgEncoded, err := secureConn.Receive()
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	msg := &message.Message{}
	err = proto.Unmarshal(msgEncoded, msg)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	switch msg.Type {
	case message.MessageType_LIST_FILES:
		listFiles(secureConn)
	}
}

func listFiles(conn *security.SecureConnection) {
	files, err := io.GetFiles(config.Cfg.FileDir)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	fileMetadatas := make([]*message.FileMetadata, len(files))
	for i, file := range files {
		fileMetadatas[i] = &message.FileMetadata{Name: file}
	}
	msg := &message.FileList{Files: fileMetadatas}

	msgEncoded, err := proto.Marshal(msg)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	conn.Send(msgEncoded)
}
