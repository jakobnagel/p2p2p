package mdns

import (
	"context"
	"fmt"
	"time"

	"github.com/grandcat/zeroconf"
)

func Publish(hostname string, port int, info string) (*zeroconf.Server, error) {
	server, err := zeroconf.Register(hostname, "_p2p2p._tcp", "", port, []string{info}, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create mDNS service: %s", err)
	}

	return server, nil
}

func Discover() ([]*zeroconf.ServiceEntry, error) {
	var results []*zeroconf.ServiceEntry
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil, fmt.Errorf("could not create mDNS resolver: %s", err)
	}

	entries := make(chan *zeroconf.ServiceEntry)
	go func(found <-chan *zeroconf.ServiceEntry) {
		for entry := range found {
			fmt.Printf("mDNS service discovered: %s:%d\n", entry.HostName, entry.Port)
			results = append(results, entry)
		}
	}(entries)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	err = resolver.Browse(ctx, "_p2p2p._tcp", "", entries)
	if err != nil {
		return nil, fmt.Errorf("could not browse for services: %s", err)
	}

	<-ctx.Done()
	return results, nil
}

// func Publish(hostname string, port int, info string) (*mdns.Server, error) {
// 	service, err := mdns.NewMDNSService(hostname, "_p2p2p.tcp", "", "", port, nil, []string{info})
// 	if err != nil {
// 		return nil, fmt.Errorf("could not create mDNS service: %s", err)
// 	}

// 	server, err := mdns.NewServer(&mdns.Config{Zone: service})
// 	if err != nil {
// 		return nil, fmt.Errorf("could not start mDNS server: %s", err)
// 	}

// 	return server, nil
// }

// func Discover() []*mdns.ServiceEntry {
// 	var results []*mdns.ServiceEntry
// 	entriesCh := make(chan *mdns.ServiceEntry, 4)
// 	var wg sync.WaitGroup

// 	wg.Add(1)
// 	go func() {
// 		defer wg.Done()
// 		for entry := range entriesCh {
// 			fmt.Printf("mDNS service discovered: %s:%d\n", entry.Host, entry.Port)
// 			results = append(results, entry)
// 		}
// 	}()

// 	mdns.Query(&mdns.QueryParam{
// 		Service:     "_p2p2p._tcp",
// 		Entries:     entriesCh,
// 		DisableIPv6: true,
// 		DisableIPv4: false,
// 	})

// 	fmt.Println("Waiting for mDNS discovery to complete...")
// 	wg.Wait()
// 	fmt.Println("mDNS discovery complete")
// 	return results
// }
