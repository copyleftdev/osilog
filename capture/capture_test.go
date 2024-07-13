package capture

import (
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type MockCaptureHandle struct {
	CaptureHandle
}

func (m *MockCaptureHandle) SetBPFFilter(filter string) error {
	return nil
}

func (m *MockCaptureHandle) Close() {
}

func (m *MockCaptureHandle) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

func (m *MockCaptureHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return []byte{}, gopacket.CaptureInfo{}, nil
}

type MockCapturer struct{}

func (m *MockCapturer) OpenLive(device string, snaplen int32, promisc bool, timeout time.Duration) (CaptureHandle, error) {
	return &MockCaptureHandle{}, nil
}

func TestCapturePackets(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Skipping test because it requires root privileges")
	}

	mockCapturer := &MockCapturer{}
	CapturePackets("enp0s3", mockCapturer)
}
