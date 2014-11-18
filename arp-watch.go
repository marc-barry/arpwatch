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
	processARP(handle, iface)

	Log.WithFields(logrus.Fields{
		"interface": iface.Name,
		"address":   addr.String(),
	}).Infof("Stopped watching interface.")

	return nil
}

func processARP(handle *pcap.Handle, iface *net.Interface) {
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

			arp := arpLayer.(*layers.ARP)

			Log.WithFields(logrus.Fields{
				"IP address":  net.IP(arp.SourceProtAddress).String(),
				"MAC address": net.HardwareAddr(arp.SourceHwAddress).String(),
			}).Infof("Recieved ARP.")
		}
	}
}
