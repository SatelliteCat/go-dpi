package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log/slog"
	"math/rand"
	"strings"
	"time"
)

var (
	device       string = "\\Device\\NPF_{4527B693-CDDB-4B51-B1B1-A12FAAFCADE4}"
	snapshot_len int32  = 65536
	promiscuous  bool   = true
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
)

//func main() {
//	//_, err := windows.LoadLibrary("wpcap.dll")
//	//if err != nil {
//	//	log.Fatal("couldn't load WpcApi.dll")
//	//}
//
//	handle, err := pcap.OpenLive("\\Device\\NPF_{C8736017-F3C3-4373-94AC-9A34B7DAD998}", 65536, true, pcap.BlockForever)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer handle.Close()
//
//	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
//	for packet := range packetSource.Packets() {
//		// Process the packet here
//		fmt.Println(packet)
//	}
//}

func main() {
	//interfaces, err := net.Interfaces()
	//if err != nil {
	//	log.Fatal("error getting network interfaces: ", err)
	//}
	//
	//for _, iface := range interfaces {
	//	fmt.Println("Name: ", iface.Name)
	//	fmt.Println("Hardware Address: ", iface.HardwareAddr)
	//	fmt.Println("Flags: ", iface.Flags)
	//	fmt.Println("MTU: ", iface.MTU)
	//	fmt.Println("Index: ", iface.Index)
	//
	//	addrs, _ := iface.Addrs()
	//	for _, addr := range addrs {
	//		fmt.Println("Address: ", addr.String())
	//	}
	//
	//	fmt.Println("===========================")
	//}

	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, pcap.BlockForever)
	if err != nil {
		slog.Error("error opening device", slog.String("error", err.Error()))
		return
	}
	defer handle.Close()

	slog.Info("device opened")

	// Set filter
	filter := "tcp and port 80"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		slog.Error("error setting filter", slog.String("error", err.Error()))
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Decode the packet
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			slog.Info("IP packet received", slog.String("src", ip.SrcIP.String()), slog.String("dst", ip.DstIP.String()))
		}

		if modifyPacket(packet) {
			err = handle.WritePacketData(packet.Data())
			if err != nil {
				slog.Error("error writing modified packet", slog.String("error", err.Error()))
				continue
			}
		}
	}
}

func modifyPacket(packet gopacket.Packet) bool {
	// Check if the packet is an IPv4 packet
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return false
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// Check if the packet is a TCP packet
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	// Check if the packet is destined for googlevideo.com
	if string(ip.DstIP) != "googlevideo.com" {
		return false
	}

	// Check if the packet contains the Host header
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return false
	}
	payload := appLayer.Payload()
	if !strings.Contains(string(payload), "Host: googlevideo.com") {
		return false
	}

	// Perform the specified modifications
	performTCPFragmentation(tcp)
	replaceHostHeader(payload)
	addSpaceBetweenMethodAndURI(payload)
	mixCaseOfHostHeader(payload)
	sendFakePackets(ip, tcp)

	return true
}

func performTCPFragmentation(tcp *layers.TCP) {
	// TODO: Implement TCP-level fragmentation for first data packet
	// and TCP-level fragmentation for persistent (keep-alive) HTTP sessions
}

func replaceHostHeader(payload []byte) {
	payload = []byte(strings.ReplaceAll(string(payload), "Host: googlevideo.com", "hoSt: googlevideo.com"))
}

func addSpaceBetweenMethodAndURI(payload []byte) {
	// TODO: Implement adding additional space between HTTP Method (GET, POST etc) and URI
}

func mixCaseOfHostHeader(payload []byte) {
	hostIndex := strings.Index(string(payload), "hoSt: ")
	if hostIndex == -1 {
		return
	}
	hostStartIndex := hostIndex + len("hoSt: ")
	hostEndIndex := strings.Index(string(payload[hostStartIndex:]), "\r\n")
	if hostEndIndex == -1 {
		return
	}
	hostEndIndex += hostStartIndex
	host := string(payload[hostStartIndex:hostEndIndex])
	mixedCaseHost := make([]byte, len(host))
	for i, c := range host {
		if rand.Intn(2) == 0 {
			mixedCaseHost[i] = byte(c)
		} else {
			mixedCaseHost[i] = byte(c ^ 32)
		}
	}
	payload = append(payload[:hostStartIndex], mixedCaseHost...)
	payload = append(payload, payload[hostEndIndex:]...)
}

func sendFakePackets(ip *layers.IPv4, tcp *layers.TCP) {
	// TODO: Implement sending fake HTTP/HTTPS packets with low Time-To-Live value,
	// incorrect checksum or incorrect TCP Sequence/Acknowledgement numbers to fool DPI
	// and prevent delivering them to the destination
}
