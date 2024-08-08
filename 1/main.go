package main

import (
	"fmt"
	"log/slog"
	_ "net"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	devices, err := findDevices()
	if err != nil {
		slog.Error("Error finding devices", slog.String("error", err.Error()))
		return
	}

	var iface string
	var ok bool

	for _, name := range devices {
		if strings.Contains(name, os.Args[1]) {
			iface = name
			ok = true
			break
		}
	}

	if !ok {
		iface, ok = devices["eth0"]
	}
	if !ok {
		slog.Error("Error finding network interface")
		return
	}

	slog.Info("Using network interface", slog.String("interface", iface))

	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		slog.Error("Error opening pcap handle", slog.String("error", err.Error()))
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		applicationLayer := packet.ApplicationLayer()
		if applicationLayer != nil {
			if strings.Contains(string(applicationLayer.Payload()), "googlevideo.com") {
				repleacedStr := strings.ReplaceAll(
					string(applicationLayer.Payload()),
					"googlevideo.com",
					"gOogLevidEo.coM",
				)

				repleacedStr = strings.ReplaceAll(
					string(applicationLayer.Payload()),
					"Host",
					"hoST",
				)

				*packet.ApplicationLayer().(*gopacket.Payload) = []byte(repleacedStr)
			}
		}
	}
}

func findDevices() (map[string]string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	interfaces := make(map[string]string, len(devices))
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}

		interfaces[device.Name] = device.Name
	}

	fmt.Println()

	return interfaces, nil
}
