package main

import (
	"fmt"
	"net"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"github.com/Sirupsen/logrus"
)

func watch(iface *net.Interface) error {
	addr, err := getInterfaceIPAddress(iface)
	if err != nil {
		return err
	}

	if addr.IP.String() == "127.0.0.1" {
		return fmt.Errorf("Skipping %s (%s).", addr.String(), addr.IP)
	}

	Log.WithFields(logrus.Fields{
		"interface": iface.Name,
		"address":   addr.String(),
	}).Infof("Watching interface.")

	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}

	// This is a blocking call.
	process(handle, iface)

	Log.WithFields(logrus.Fields{
		"interface": iface.Name,
		"address":   addr.String(),
	}).Infof("Stopped watching interface.")

	return nil
}

func process(handle *pcap.Handle, iface *net.Interface) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-src.Packets():
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}

			handleARP(arpLayer.(*layers.ARP))

		}
	}
}

func handleARP(arp *layers.ARP) {
	switch arp.Operation {
	case 1: // This operation value defines an arp request.
		// For a standard ARP request:
		// - SourceHwAddress: This is the MAC address of the requestor.
		// - SourceProtAddress: This is the IP address of the requestor.
		// - DstHwAddress: This field is ignored. Basically, this is what an ARP request is actually requesting.
		// - DstProtAddress: This is the IP address for which the requestor would like the MAC address for (i.e. a reply).
		Log.WithFields(logrus.Fields{
			"Requestor MAC Address":  net.HardwareAddr(arp.SourceHwAddress).String(),
			"Requestor IP Address":   net.IP(arp.SourceProtAddress).String(),
			"Ignored MAC Address":    net.HardwareAddr(arp.DstHwAddress).String(),
			"Destination IP Address": net.IP(arp.DstProtAddress).String(),
		}).Infof("Recieved ARP request.")
	case 2: // This operation value defines an arp reply.
		// For an ARP reply:
		// - SourceHwAddress: This is the MAC address of the replier.
		// - SourceProtAddress: This is the IP address of the replier.
		// - DstHwAddress: This field indicates the address of the requesting host.
		// - DstProtAddress: This is the IP address of the requesting host.
		Log.WithFields(logrus.Fields{
			"Replier MAC Address":   net.HardwareAddr(arp.SourceHwAddress).String(),
			"Replier IP Address":    net.IP(arp.SourceProtAddress).String(),
			"Requestor MAC Address": net.HardwareAddr(arp.DstHwAddress).String(),
			"Requestor IP Address":  net.IP(arp.DstProtAddress).String(),
		}).Infof("Recieved ARP reply.")
	default:
		Log.Warnf("Unknown sender operation for ARP packet: %#v", *arp)
	}
}
