package mdns

import (
	"fmt"
	"net"

	"nagelbros.com/p2p2p/pkg/logging"

	// "sync"
	"time"

	"github.com/hashicorp/mdns"
)

const serviceName = "_ppp._tcp.local."

func Publish(hostname string, port int, info string) (*mdns.Server, error) {
	service, err := mdns.NewMDNSService(hostname, serviceName, "", hostname+".", port, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create mDNS service: %s", err)
	}

	server, err := mdns.NewServer(&mdns.Config{Zone: service})
	if err != nil {
		return nil, fmt.Errorf("could not start mDNS server: %s", err)
	}

	return server, nil
}

func Discover() ([]*mdns.ServiceEntry, error) {
	var results []*mdns.ServiceEntry
	entriesCh := make(chan *mdns.ServiceEntry, 4)
	go func() {
		for e := range entriesCh {
			results = append(results, e)
		}

	}()

	err := mdns.Query(&mdns.QueryParam{
		Service:     serviceName,
		Timeout:     1 * time.Second,
		Entries:     entriesCh,
		DisableIPv6: true,
		Logger:      logging.NullLogger,
	})
	if err != nil {
		return nil, fmt.Errorf("could not query for mDNS services: %s", err)
	}

	for _, result := range results {
		if _, ok := knownHosts[result.Host]; !ok {
			addr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", result.AddrV4, result.Port))
			addHostToKnownHosts(result.Host, addr)
		}
	}

	return results, nil
}
