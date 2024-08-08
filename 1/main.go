package main

import (
	"bufio"
	"fmt"
	"log"
	"log/slog"
	_ "net"
	"os/exec"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

func main() {
	intf, err := getNetworkInterfaces()
	if err != nil {
		slog.Error("Error getting network interfaces", slog.String("error", err.Error()))
		return
	}

	//findDevices()
	//return

	//for i, t := range intf {
	//	slog.Info("Network interface", slog.String("interface", i), slog.String("transport", t))
	//}

	slog.Info("Count interfaces", slog.Int("count", len(intf)))
	slog.Info("Starting packet capture")

	//iface := "\\Device\\Tcpip_{4527B693-CDDB-4B51-B1B1-A12FAAFCADE4}" // for windows command: getmac /fo csv /v
	//iface := "\\Device\\NPF_{4527B693-CDDB-4B51-B1B1-A12FAAFCADE4}" // for windows command: getmac /fo csv /v
	iface := strings.Replace(intf["Ethernet"], "Tcpip_", "NPF_", 1)

	slog.Info("Using network interface", slog.String("interface", iface))

	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		slog.Error("Error opening pcap handle", slog.String("error", err.Error()))
		return
	}
	defer handle.Close()

	streamPool := tcpassembly.NewStreamPool(streamFactory{})
	if nil == streamPool {
		slog.Error("Error creating stream pool")
		return
	}

	assembler := tcpassembly.NewAssembler(streamPool)
	if nil == assembler {
		slog.Error("Error creating assembler")
		return
	}

	//filter := "tcp and port 80"
	//err = handle.SetBPFFilter(filter)
	//if err != nil {
	//	slog.Error("Error setting BPF filter", slog.String("error", err.Error()))
	//	return
	//}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		applicationLayer := packet.ApplicationLayer()
		if applicationLayer != nil {
			//fmt.Println("Application layer/Payload found.")
			//fmt.Printf("%s\n", applicationLayer.Payload())

			// Search for a string inside the payload
			//if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			if strings.Contains(string(applicationLayer.Payload()), "googlevideo.com") {
				//fmt.Println("[googlevideo.com] found!")

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

		// Check for errors
		//if err := packet.ErrorLayer(); err != nil {
		//	fmt.Println("Error decoding some part of the packet:", err)
		//}

		//tcp, ok := packet.TransportLayer().(*layers.TCP)
		//if !ok {
		//	continue
		//}
		//
		//assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
	}
}

type streamFactory struct {
}

func (f streamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	return &packetHandler{}
}

type packetHandler struct {
	tcpassembly.Stream
	host string
}

func (h *packetHandler) ReassemblyComplete() {

}

func (h *packetHandler) Reassembled(reassembled []tcpassembly.Reassembly) {
	ra := make([]byte, 0, len(reassembled))
	for _, r := range reassembled {
		ra = append(ra, r.Bytes...)
	}

	packet := gopacket.NewPacket(ra, layers.LayerTypeIPv4, gopacket.Default)

	//if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
	//	return
	//}

	//if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
	//tcp := tcpLayer.(*layers.TCP)

	//if httpLayer := packet.Layer(layers.LayerTypeIPv4); httpLayer != nil {
	//if httpLayer := packet.Layer(layers.LayerTypeIPv4); httpLayer != nil {
	//http := httpLayer.(*layers.IPv4)
	//
	//if strings.EqualFold(http.Host, "googlevideo.com") {
	//	// Perform the specified actions here
	//	// For example, you can modify the TCP header, HTTP header, or send fake packets
	//	fmt.Println("Packet with Host: googlevideo.com found")
	//}

	// Check if the packet contains the Host header
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		//slog.Warn("Packet does not contain an application layer")
		return
	}

	//var payload gopacket.Payload
	//packetParser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &payload)

	//slog.Info("Packet data",
	//	slog.String("payload", string(appLayer.Payload())),
	//	slog.String("layer payload", string(appLayer.LayerPayload())),
	//	slog.String("layer contents", string(appLayer.LayerContents())),
	//)

	payload := appLayer.Payload()

	slog.Info("Has Header", slog.Bool("has", strings.Contains(string(payload), "Header")))

	//if !strings.Contains(string(payload), "Host: googlevideo.com") {
	if !strings.Contains(string(payload), "Host") {
		//slog.Warn("Packet does not contain [Host: googlevideo.com]")
		return
	}

	slog.Info("Packet with Host: googlevideo.com found")
	// Perform the specified actions here
	// For example, you can modify the TCP header, HTTP header, or send fake packets

	//}
}

func getNetworkInterfaces() (map[string]string, error) {
	cmd := exec.Command("getmac", "/fo", "csv", "/v")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	interfaces := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	headerFound := false
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "\"Connection Name\"") {
			headerFound = true
			continue
		}

		if headerFound {
			fields := strings.Split(line, ",")
			if len(fields) >= 4 {
				connectionName := strings.Trim(fields[0], "\"")
				physicalAddress := strings.Trim(fields[3], "\"")
				interfaces[connectionName] = physicalAddress
			}
		}
	}

	return interfaces, nil
}

func findDevices() {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Print device information
	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
}
