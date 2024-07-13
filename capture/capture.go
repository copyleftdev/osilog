package capture

import (
	"net"
	"time"

	"github.com/copyleftdev/osilog/tls"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

const (
	snapshotLen int32 = 1024
	promiscuous       = false
	timeout           = pcap.BlockForever
)

// CaptureInterface is an interface for capturing packets
type CaptureInterface interface {
	OpenLive(device string, snaplen int32, promisc bool, timeout time.Duration) (CaptureHandle, error)
}

// CaptureHandle is an interface for a handle to capture packets
type CaptureHandle interface {
	SetBPFFilter(filter string) error
	Close()
	LinkType() layers.LinkType
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

type PcapWrapper struct{}

// OpenLive opens a device for live packet capture
func (p *PcapWrapper) OpenLive(device string, snaplen int32, promisc bool, timeout time.Duration) (CaptureHandle, error) {
	handle, err := pcap.OpenLive(device, snaplen, promisc, timeout)
	return handle, err
}

func CapturePackets(interfaceName string, capturer CaptureInterface) {
	handle, err := capturer.OpenLive(interfaceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		logrus.Fatal(err)
	}
	defer handle.Close()

	filter := "tcp or udp or icmp or arp"
	if err := handle.SetBPFFilter(filter); err != nil {
		logrus.Fatal(err)
	}
	logrus.Infof("🛡️  Capturing on interface %s with filter %s", interfaceName, filter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

func processPacket(packet gopacket.Packet) {
	logrus.WithFields(logrus.Fields{
		"timestamp": packet.Metadata().Timestamp.Format(time.RFC3339),
		"length":    packet.Metadata().Length,
	}).Info("📦 Packet captured")

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		logrus.WithFields(logrus.Fields{
			"src_ip":   packet.NetworkLayer().NetworkFlow().Src().String(),
			"dst_ip":   packet.NetworkLayer().NetworkFlow().Dst().String(),
			"src_port": tcp.SrcPort,
			"dst_port": tcp.DstPort,
		}).Info("🔵 TCP packet captured")

		if tcp.RST {
			logrus.WithFields(logrus.Fields{
				"src_ip":   packet.NetworkLayer().NetworkFlow().Src().String(),
				"dst_ip":   packet.NetworkLayer().NetworkFlow().Dst().String(),
				"src_port": tcp.SrcPort,
				"dst_port": tcp.DstPort,
			}).Warn("🚨 TCP Reset (RST) detected")
		}

		if tcp.SYN {
			logrus.WithFields(logrus.Fields{
				"src_ip":   packet.NetworkLayer().NetworkFlow().Src().String(),
				"dst_ip":   packet.NetworkLayer().NetworkFlow().Dst().String(),
				"src_port": tcp.SrcPort,
				"dst_port": tcp.DstPort,
			}).Info("🔄 TCP Synchronize (SYN) detected")
		}

		tls.CheckTLSIssues(packet)
	}

	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoRequest && icmp.TypeCode.Type() != layers.ICMPv4TypeEchoReply {
			logrus.WithFields(logrus.Fields{
				"src_ip": packet.NetworkLayer().NetworkFlow().Src().String(),
				"dst_ip": packet.NetworkLayer().NetworkFlow().Dst().String(),
			}).Warn("🚨 ICMP error detected")
		}
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		logrus.WithFields(logrus.Fields{
			"src_ip":   packet.NetworkLayer().NetworkFlow().Src().String(),
			"dst_ip":   packet.NetworkLayer().NetworkFlow().Dst().String(),
			"src_port": udp.SrcPort,
			"dst_port": udp.DstPort,
		}).Info("🟢 UDP packet captured")
	}

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
