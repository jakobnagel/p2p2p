package main

import (
	"flag"
	"fmt"
	"net"
	"path"

	"nagelbros.com/p2p2p/pkg/config"
	"nagelbros.com/p2p2p/pkg/io"
	"nagelbros.com/p2p2p/pkg/mdns"
	"nagelbros.com/p2p2p/pkg/security"
)

var password string

func main() {
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

	if command == "encrypt" {
		inFile := flag.Arg(1)
		if inFile == "" {
			fmt.Printf("Usage: encrypt <input file> --password <password>\n")
			return
		}

		encrypt(inFile, password)
	}
}

func init() {
	config.Init("client.env")
	flag.StringVar(&password, "password", io.UndefinedPassword, "password to use for encryption")
	flag.Parse()
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

func encrypt(inFile, password string) {
	if password == io.UndefinedPassword {
		password = io.GetUserPassword()
	}
	outFile := path.Join(config.Cfg.FileDir, inFile+".enc")

	err := security.EncryptFile(inFile, outFile, password)
	if err != nil {
		fmt.Printf("Could not encrypt file: %s", err)
		return
	}

	fmt.Printf("File encrypted successfully\n")
}
