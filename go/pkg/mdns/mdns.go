package mdns

import (
	"fmt"
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
		Logger:      nil,
	})
	if err != nil {
		return nil, fmt.Errorf("could not query for mDNS services: %s", err)
	}

	return results, nil
}
