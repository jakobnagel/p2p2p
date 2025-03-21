package mdns

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"nagelbros.com/p2p2p/pkg/config"
)

var knownHosts map[string]*net.TCPAddr = make(map[string]*net.TCPAddr)

// loads known hosts from file
func init() {
	file, err := os.Open(config.Cfg.KnownHostsFile)
	if os.IsNotExist(err) {
		os.Create(config.Cfg.KnownHostsFile)
		return
	}
	defer file.Close()

	r := bufio.NewReader(file)

	for {
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if err != nil { // EOF
			break
		}

		host, addr, found := strings.Cut(line, " ")
		if !found {
			continue
		}

		tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			continue
		}

		knownHosts[host] = tcpAddr
	}
}

func GetAddrFromHost(host string) (*net.TCPAddr, error) {
	if addr, found := knownHosts[host]; found {
		return addr, nil
	}

	// find address in mDNS services
	services, err := Discover() // will add to known hosts if found
	if err != nil {
		return nil, err
	}

	for _, service := range services {
		if service.Host == host {
			addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", service.AddrV4, service.Port))
			if err != nil {
				return nil, err
			}

			addHostToKnownHosts(host, addr)
			return addr, nil
		}
	}

	return nil, fmt.Errorf("could not find host in known hosts or mDNS services")
}

func addHostToKnownHosts(host string, addr *net.TCPAddr) error {
	file, err := os.OpenFile(config.Cfg.KnownHostsFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("%s %s\n", host, addr.String()))
	if err != nil {
		return err
	}

	knownHosts[host] = addr

	return nil
}
