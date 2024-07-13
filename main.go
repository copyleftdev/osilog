package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

const (
	snapshotLen int32 = 1024
	promiscuous       = false
	timeout           = pcap.BlockForever
)

var (
	interfaceName string
	logLevels     string
	rootCmd       = &cobra.Command{
		Use:   "osilog",
		Short: "Network monitoring tool",
		Long:  `Network monitoring tool to capture and analyze network packets.`,
		Run:   run,
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&interfaceName, "interface", "i", "", "Network interface to capture packets from")
	rootCmd.PersistentFlags().StringVarP(&logLevels, "loglevels", "l", "info", "Log levels (info,warn,error)")
	rootCmd.MarkPersistentFlagRequired("interface")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) {
	// Configure Logrus with color coding and emojis
	logrus.SetFormatter(&prefixed.TextFormatter{
		FullTimestamp:   true,
		ForceColors:     true,
		ForceFormatting: true,
	})

	// Parse and set log levels
	logLevelMap := map[logrus.Level]bool{
		logrus.InfoLevel:  false,
		logrus.WarnLevel:  false,
		logrus.ErrorLevel: false,
	}

	levels := strings.Split(logLevels, ",")
	for _, level := range levels {
		switch strings.TrimSpace(level) {
		case "info":
			logLevelMap[logrus.InfoLevel] = true
		case "warn":
			logLevelMap[logrus.WarnLevel] = true
		case "error":
			logLevelMap[logrus.ErrorLevel] = true
		default:
			logrus.Fatalf("Unknown log level: %s", level)
		}
	}

	for level, enabled := range logLevelMap {
		if enabled {
			logrus.SetLevel(level)
			break
		}
	}

	// Open the network device
	handle, err := pcap.OpenLive(interfaceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		logrus.Fatal(err)
	}
	defer handle.Close()

	// Set the BPF filter for capturing TCP, UDP, ICMP, and ARP packets
	var filter = "tcp or udp or icmp or arp"
	if err := handle.SetBPFFilter(filter); err != nil {
		logrus.Fatal(err)
	}
	logrus.Infof("🛡️  Capturing on interface %s with filter %s", interfaceName, filter)

	// Use a packet source to read packets from the handle
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Process packets
	for packet := range packetSource.Packets() {
		processPacket(packet, logLevelMap)
	}
}

func processPacket(packet gopacket.Packet, logLevelMap map[logrus.Level]bool) {
	// Log packet metadata
	logrus.WithFields(logrus.Fields{
		"timestamp": packet.Metadata().Timestamp.Format(time.RFC3339),
		"length":    packet.Metadata().Length,
	}).Info("📦 Packet captured")

	// TCP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		logrus.WithFields(logrus.Fields{
			"src_ip":   packet.NetworkLayer().NetworkFlow().Src().String(),
			"dst_ip":   packet.NetworkLayer().NetworkFlow().Dst().String(),
			"src_port": tcp.SrcPort,
			"dst_port": tcp.DstPort,
		}).Info("🔵 TCP packet captured")

		// Log RST (Reset) flags
		if tcp.RST && logLevelMap[logrus.WarnLevel] {
			logrus.WithFields(logrus.Fields{
				"src_ip":   packet.NetworkLayer().NetworkFlow().Src().String(),
				"dst_ip":   packet.NetworkLayer().NetworkFlow().Dst().String(),
				"src_port": tcp.SrcPort,
				"dst_port": tcp.DstPort,
			}).Warn("🚨 TCP Reset (RST) detected")
		}

		// Log SYN (Synchronize) flags
		if tcp.SYN && logLevelMap[logrus.WarnLevel] {
			logrus.WithFields(logrus.Fields{
				"src_ip":   packet.NetworkLayer().NetworkFlow().Src().String(),
				"dst_ip":   packet.NetworkLayer().NetworkFlow().Dst().String(),
				"src_port": tcp.SrcPort,
				"dst_port": tcp.DstPort,
			}).Info("🔄 TCP Synchronize (SYN) detected")
		}
	}

	// ICMP layer
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		icmpType := icmpTypeToString(icmp.TypeCode.Type())
		if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoRequest && icmp.TypeCode.Type() != layers.ICMPv4TypeEchoReply && logLevelMap[logrus.WarnLevel] {
			logrus.WithFields(logrus.Fields{
				"src_ip": packet.NetworkLayer().NetworkFlow().Src().String(),
				"dst_ip": packet.NetworkLayer().NetworkFlow().Dst().String(),
				"type":   icmpType,
			}).Warn("🚨 ICMP error detected")
		}
	}

	// UDP layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		logrus.WithFields(logrus.Fields{
			"src_ip":   packet.NetworkLayer().NetworkFlow().Src().String(),
			"dst_ip":   packet.NetworkLayer().NetworkFlow().Dst().String(),
			"src_port": udp.SrcPort,
			"dst_port": udp.DstPort,
		}).Info("🟢 UDP packet captured")
	}

	// ARP layer
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)
		logrus.WithFields(logrus.Fields{
			"src_ip":  net.IP(arp.SourceProtAddress),
			"dst_ip":  net.IP(arp.DstProtAddress),
			"src_mac": net.HardwareAddr(arp.SourceHwAddress),
			"dst_mac": net.HardwareAddr(arp.DstHwAddress),
		}).Info("🟡 ARP packet captured")
	}
}

func icmpTypeToString(icmpType uint8) string {
	switch icmpType {
	case layers.ICMPv4TypeEchoReply:
		return "Echo Reply"
	case layers.ICMPv4TypeDestinationUnreachable:
		return "Destination Unreachable"
	case layers.ICMPv4TypeSourceQuench:
		return "Source Quench"
	case layers.ICMPv4TypeRedirect:
		return "Redirect"
	case layers.ICMPv4TypeEchoRequest:
		return "Echo Request"
	case layers.ICMPv4TypeTimeExceeded:
		return "Time Exceeded"
	case layers.ICMPv4TypeParameterProblem:
		return "Parameter Problem"
	case layers.ICMPv4TypeTimestampRequest:
		return "Timestamp Request"
	case layers.ICMPv4TypeTimestampReply:
		return "Timestamp Reply"
	case layers.ICMPv4TypeInfoRequest:
		return "Information Request"
	case layers.ICMPv4TypeInfoReply:
		return "Information Reply"
	case layers.ICMPv4TypeAddressMaskRequest:
		return "Address Mask Request"
	case layers.ICMPv4TypeAddressMaskReply:
		return "Address Mask Reply"
	default:
		return fmt.Sprintf("Unknown (%d)", icmpType)
	}
}
