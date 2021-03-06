package main

import (
	"fmt"
	"net"
	"time"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"github.com/Sirupsen/logrus"
)

var (
	requestARPStore    *ARPStore = NewARPStore()
	replyARPStore      *ARPStore = NewARPStore()
	gratuitousARPStore *ARPStore = NewARPStore()
)

const (
	GratuitousTargetMAC = "ff:ff:ff:ff:ff:ff"
)

func watch(iface net.Interface) error {
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

	IfaceList.Append(iface)

	// This is a blocking call.
	process(handle, iface)

	Log.WithFields(logrus.Fields{
		"interface": iface.Name,
		"address":   addr.String(),
	}).Infof("Stopped watching interface.")

	return nil
}

func process(handle *pcap.Handle, iface net.Interface) {
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

			handleARP(arpLayer.(*layers.ARP), iface)

		}
	}
}

func logARPData(arpData *ARPData, str string) {
	Log.WithFields(logrus.Fields{
		"Interface":          arpData.Interface.Name,
		"Operation":          arpData.Operation,
		"Sender MAC Address": arpData.SenderMACAddress,
		"Sender IP Address":  arpData.SenderIPAddress,
		"Target MAC Address": arpData.TargetMACAddress,
		"Target IP Address":  arpData.TargetIPAddress,
		"Time":               arpData.Time.String(),
	}).Infof(str)
}

func handleARP(arp *layers.ARP, iface net.Interface) {
	arpData := &ARPData{
		Interface:        iface,
		Operation:        arp.Operation,
		SenderMACAddress: net.HardwareAddr(arp.SourceHwAddress).String(),
		SenderIPAddress:  net.IP(arp.SourceProtAddress).String(),
		TargetMACAddress: net.HardwareAddr(arp.DstHwAddress).String(),
		TargetIPAddress:  net.IP(arp.DstProtAddress).String(),
		Time:             time.Now(),
	}

	switch arpData.Operation {
	case 1: // This operation value defines an arp request.
		// For a standard ARP request:
		// - SourceHwAddress: This is the MAC address of the requestor.
		// - SourceProtAddress: This is the IP address of the requestor.
		// - DstHwAddress: This field is ignored. Basically, this is what an ARP request is actually requesting.
		// - DstProtAddress: This is the IP address for which the requestor would like the MAC address for (i.e. a reply).

		// A gratuitous ARP request is a packet where the source and destination IP are both set to the IP of the machine
		// issuing the packet and the destination MAC is the broadcast address ff:ff:ff:ff:ff:ff.
		if (arpData.TargetMACAddress == GratuitousTargetMAC) && (arpData.SenderIPAddress == arpData.TargetIPAddress) {
			logARPData(arpData, "Received gratuitous ARP request.")

			if existingData, existed := gratuitousARPStore.PutARPData(arpData); existed {
				Log.Infof("Replacing existing gratuitous request: %+v", *existingData)
			}

			return
		}

		Log.WithFields(logrus.Fields{
			"Interface":              arpData.Interface.Name,
			"Requestor MAC Address":  arpData.SenderMACAddress,
			"Requestor IP Address":   arpData.SenderIPAddress,
			"Ignored MAC Address":    arpData.TargetMACAddress,
			"Destination IP Address": arpData.TargetIPAddress,
		}).Infof("Received ARP request.")

		if existingData, existed := requestARPStore.PutARPData(arpData); existed {
			Log.Infof("Replacing existing request: %+v", *existingData)
		}
	case 2: // This operation value defines an arp reply.
		// For an ARP reply:
		// - SourceHwAddress: This is the MAC address of the replier.
		// - SourceProtAddress: This is the IP address of the replier.
		// - DstHwAddress: This field indicates the address of the requesting host.
		// - DstProtAddress: This is the IP address of the requesting host.
		logARPData(arpData, "Received ARP reply.")

		if existingData, existed := replyARPStore.PutARPData(arpData); existed {
			Log.Infof("Replacing existing reply: %+v", *existingData)
		}
	default:
		Log.Warnf("Unknown sender operation for ARP packet: %+v", *arp)
	}
}
