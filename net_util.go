package main

import (
	"fmt"
	"net"
)

func getInterfaceIPAddress(iface *net.Interface) (*net.IPNet, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, a := range addrs {
		switch a.(type) {
		case *net.IPNet:
			ipNet, _ := a.(*net.IPNet)
			if ip := ipNet.IP.To4(); ip != nil {
				return ipNet, nil
			}
		}
	}

	return nil, fmt.Errorf("Unable to get IP address for interface %s.", iface.Name)
}
