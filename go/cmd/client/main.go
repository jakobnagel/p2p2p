package main

import (
	"flag"
	"fmt"
	"net"
	"path"

	"nagelbros.com/p2p2p/pkg/config"
	"nagelbros.com/p2p2p/pkg/files"
	"nagelbros.com/p2p2p/pkg/io"
	"nagelbros.com/p2p2p/pkg/mdns"
	"nagelbros.com/p2p2p/pkg/message"
	"nagelbros.com/p2p2p/pkg/security"
	pb "nagelbros.com/p2p2p/types/message"
)

var command string
var password string
var host string
var addr *net.TCPAddr

func main() {
	var conn *security.SecConn

	// initiate connection to server
	if addr != nil {
		unsecConn, err := net.Dial("tcp4", addr.String())
		if err != nil {
			fmt.Printf("Could not establish connection with server: %s", err)
			return
		}
		defer unsecConn.Close()

		conn, err = security.EstablishSecureConnection(unsecConn)
		if err != nil {
			fmt.Printf("Could not establish secure connection: %s", err)
			return
		}
	}

	if command == "list-services" {
		listServices()
	}

	if command == "list-files" {
		if addr == nil {
			fmt.Printf("Usage: --host <host> list-files\n")
			return
		}

		listFiles(conn)
	}

	if command == "encrypt" {
		inFile := flag.Arg(1)
		if inFile == "" {
			fmt.Printf("Usage: encrypt --pass <pass> <input file>\n")
			return
		}

		encrypt(inFile, password)
	}

	if command == "decrypt" {
		inFile := flag.Arg(1)
		if inFile == "" {
			fmt.Printf("Usage: decrypt --pass <pass> <input file>\n")
			return
		}

		decrypt(inFile, password)
	}

	if command == "get-file" {
		fileName := flag.Arg(1)
		if addr == nil || password == io.UndefinedPassword || fileName == "" {
			fmt.Printf("Usage: --host <host> --pass <pass> get-file <file>\n")
			return
		}

		getFile(conn, fileName)
	}

	if command == "send-file" {
		fileName := flag.Arg(1)
		if addr == nil || password == io.UndefinedPassword || fileName == "" {
			fmt.Printf("Usage: --host <host> --pass <pass> send-file <file>\n")
			return
		}

		sendFile(conn, fileName)
	}
}

func init() {
	flag.StringVar(&password, "pass", io.UndefinedPassword, "pass to use for encryption")
	flag.StringVar(&host, "host", "", "hostname of the server")
	flag.Parse()

	if host != "" {
		var err error
		addr, err = mdns.GetAddrFromHost(host)
		if err != nil {
			fmt.Printf("Could not get address from host: %s", err)
			return
		}
	}
	command = flag.Arg(0)
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
		fmt.Printf("%d. %s\n", i+1, service.Host)
	}
}

func listFiles(conn *security.SecConn) {
	// send request
	msg := message.FileListRequest()

	err := conn.Send(msg)
	if err != nil {
		fmt.Printf("Could not send message: %s", err)
		return
	}

	resp, err := conn.Receive()
	if err != nil {
		fmt.Printf("Could not receive message: %s", err)
		return
	}
	fileList := resp.GetFileList().Files

	if len(fileList) == 0 {
		fmt.Printf("No files found\n")
	} else {
		for i, file := range fileList {
			// add to known files
			files.RegisterFile(file.Name, fmt.Sprintf("%x", file.Hash))
			fmt.Printf("%d. %s\n", i+1, file.Name)
		}
	}
}

func getFile(conn *security.SecConn, fileName string) {
	// send request
	msg := message.FileDownloadRequest(fileName)

	err := conn.Send(msg)
	if err != nil {
		fmt.Printf("Could not send message: %s", err)
		return
	}

	resp, err := conn.Receive()
	if err != nil {
		fmt.Printf("Could not receive message: %s", err)
		return
	}

	if resp.GetType() == pb.MessageType_ERROR {
		fmt.Printf("Could not receive message: %s\n", resp.GetError().Message)
		return
	}

	fileData := resp.GetFile().Data

	if !files.VerifyFile(fileData, fileName) {
		fmt.Printf("File hash does not match known file\n")
		return
	}

	err = files.EncryptToFile(fileData, path.Join(config.Cfg.FileDir, fileName+".enc"), password)
	if err != nil {
		fmt.Printf("Could not write file: %s", err)
		return
	}

	fmt.Printf("File received successfully\n")

}

func sendFile(conn *security.SecConn, fileName string) {
	fileData, err := files.DecryptFromFile(path.Join(config.Cfg.FileDir, fileName), password)
	if err != nil {
		fmt.Printf("Could not read file: %s", err)
		return
	}

	msg := message.FileUploadRequest(fileName, fileData)

	err = conn.Send(msg)
	if err != nil {
		fmt.Printf("Could not send message: %s", err)
		return
	}
}

func encrypt(inFile, pass string) {
	if pass == io.UndefinedPassword {
		pass = io.GetUserPassword()
	}
	outFile := path.Join(config.Cfg.FileDir, inFile+".enc")

	err := files.EncryptFromFileToFile(inFile, outFile, pass)
	if err != nil {
		fmt.Printf("Could not encrypt file: %s", err)
		return
	}

	fmt.Printf("File encrypted successfully\n")
}

func decrypt(inFile, pass string) {
	if pass == io.UndefinedPassword {
		pass = io.GetUserPassword()
	}

	err := files.DecryptFromFileToFile(path.Join(config.Cfg.FileDir, inFile+".enc"), inFile, pass)
	if err != nil {
		fmt.Printf("Could not decrypt file: %s", err)
		return
	}

	fmt.Printf("File decrypted successfully\n")
}
