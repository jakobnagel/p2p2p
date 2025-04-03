package main

import (
	"flag"
	"fmt"
	"net"
	"path"
	"strconv"

	// "time"
	"os"

	"nagelbros.com/p2p2p/pkg/config"
	"nagelbros.com/p2p2p/pkg/files"
	"nagelbros.com/p2p2p/pkg/io"
	"nagelbros.com/p2p2p/pkg/mdns"
	"nagelbros.com/p2p2p/pkg/message"
	"nagelbros.com/p2p2p/pkg/security"
	pb "nagelbros.com/p2p2p/types/message"
	// "strings"
)

var password string

func init() {
	flag.StringVar(&password, "password", io.UndefinedPassword, "password for encryption")
	flag.Parse()

	if password == io.UndefinedPassword {
		password = io.GetUserPassword()
	}
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

	secureConn, err := security.EstablishSecureConnection(conn)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	msg, err := secureConn.Receive()
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	switch msg.Payload.(type) {
	case *pb.WrappedMessage_FileListRequest:
		listFiles(secureConn)
	case *pb.WrappedMessage_FileDownloadRequest:
		sendFile(secureConn, msg.GetFileDownloadRequest().FileName)
	case *pb.WrappedMessage_FileUploadRequest:
		receiveFile(secureConn, msg.GetFileUploadRequest())
	}
}

func listFiles(conn *security.SecConn) {
	files, err := files.GetFiles(config.Cfg.FileDir, password)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	conn.Send(message.FileList(files))
}

func sendFile(conn *security.SecConn, fileName string) {
	consent := io.GetConsent(fmt.Sprintf("Do you want to send file %s to %s?", fileName, conn.Addr()))
	if !consent {
		errorMsg := message.ErrorMessage("User did not consent to send file")
		conn.Send(errorMsg)
		return
	}

	filePath := path.Join(config.Cfg.FileDir, fileName+".enc")

	plaintext, err := files.DecryptFromFile(filePath, password)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	conn.Send(message.FileData(fileName, plaintext))
}

func receiveFile(conn *security.SecConn, uploadFileReq *pb.FileUploadRequest) {
	fileName := uploadFileReq.FileName
	fileData := uploadFileReq.FileData

	if !files.VerifyFile(fileData, fileName) {
		errMsg := message.ErrorMessage("File hash does not match known file")
		conn.Send(errMsg)
		return
	}

	if !io.GetConsent(fmt.Sprintf("Do you want to receive file %s from %s", fileName, conn.Addr())) {
		errMsg := message.ErrorMessage("User did not consent to receive file")
		conn.Send(errMsg)
		return
	}

	err := files.EncryptToFile(fileData, path.Join(config.Cfg.FileDir, fileName+".enc"), password)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
}
