package tls

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
)

// TLSRecordType represents the type of TLS record
type TLSRecordType uint8

const (
	// HandshakeTypeClientHello indicates a Client Hello message
	HandshakeTypeClientHello uint8 = 1
	// HandshakeTypeServerHello indicates a Server Hello message
	HandshakeTypeServerHello uint8 = 2
	// ContentTypeAlert indicates an alert message
	ContentTypeAlert TLSRecordType = 21
	// ContentTypeHandshake indicates a handshake message
	ContentTypeHandshake TLSRecordType = 22
)

// CheckTLSIssues inspects TCP packet payloads for TLS issues
func CheckTLSIssues(packet gopacket.Packet) {
	// Check if the packet contains a TCP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)

		// Check if the TCP packet has a payload
		if len(tcp.Payload) > 0 {
			checkTLSPayload(tcp.Payload, packet)
		}
	}
}

func checkTLSPayload(payload []byte, packet gopacket.Packet) {
	if len(payload) < 5 {
		return
	}

	recordType := TLSRecordType(payload[0])
	if recordType != ContentTypeAlert && recordType != ContentTypeHandshake {
		return
	}

	version := binary.BigEndian.Uint16(payload[1:3])
	if version < 0x0301 || version > 0x0304 { // TLS 1.0 - TLS 1.3
		return
	}

	length := binary.BigEndian.Uint16(payload[3:5])
	if len(payload) < int(5+length) {
		return
	}

	switch recordType {
	case ContentTypeAlert:
		logrus.WithFields(logrus.Fields{
			"src_ip": packet.NetworkLayer().NetworkFlow().Src().String(),
			"dst_ip": packet.NetworkLayer().NetworkFlow().Dst().String(),
		}).Error("🔒 TLS alert message detected")
	case ContentTypeHandshake:
		if len(payload) > 5 {
			handshakeType := payload[5]
			switch handshakeType {
			case HandshakeTypeClientHello:
				logrus.WithFields(logrus.Fields{
					"src_ip": packet.NetworkLayer().NetworkFlow().Src().String(),
					"dst_ip": packet.NetworkLayer().NetworkFlow().Dst().String(),
				}).Info("🔒 TLS Client Hello detected")
			case HandshakeTypeServerHello:
				logrus.WithFields(logrus.Fields{
					"src_ip": packet.NetworkLayer().NetworkFlow().Src().String(),
					"dst_ip": packet.NetworkLayer().NetworkFlow().Dst().String(),
				}).Info("🔒 TLS Server Hello detected")
			}
		}
	}
}
