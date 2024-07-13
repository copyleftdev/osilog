package tls

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/assert"
)

func TestTLSIssues(t *testing.T) {
	// Your test code here...
	handle, err := pcap.OpenOffline("../testdata/test_tls.pcap")
	assert.NoError(t, err)
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		CheckTLSIssues(packet)
		// Add assertions based on what you expect from CheckTLSIssues
	}
}
