package layers

import (
	"testing"

	"github.com/google/gopacket"
)

// The provided diameter packers are

var testPacketDiameterRequest = []byte{
	0x08, 0x00, 0x27, 0xf0, 0xa1, 0x70, 0x08, 0x00, 0x27, 0xd9, 0xb0, 0x9d, 0x08, 0x00, 0x45, 0x00,
	0x00, 0xfc, 0x3f, 0x08, 0x40, 0x00, 0x40, 0x06, 0xa7, 0x5c, 0xc0, 0xa8, 0x69, 0x28, 0xc0, 0xa8,
	0x69, 0x1e, 0x0b, 0x1c, 0x0f, 0x1c, 0x99, 0x6e, 0xf2, 0xca, 0xe4, 0x2e, 0x8e, 0x9b, 0x80, 0x18,
	0x02, 0xda, 0x36, 0x7d, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x00, 0x1a, 0xcd, 0xd4, 0x00, 0x01,
	0x33, 0x59, 0x01, 0x00, 0x00, 0xc8, 0x80, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x53, 0xca,
	0xfe, 0x6a, 0x7d, 0xc0, 0xa1, 0x1b, 0x00, 0x00, 0x01, 0x08, 0x40, 0x00, 0x00, 0x20, 0x6f, 0x70,
	0x65, 0x6e, 0x64, 0x69, 0x61, 0x6d, 0x2e, 0x65, 0x61, 0x70, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x62,
	0x65, 0x64, 0x2e, 0x61, 0x61, 0x61, 0x00, 0x00, 0x01, 0x28, 0x40, 0x00, 0x00, 0x17, 0x65, 0x61,
	0x70, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x62, 0x65, 0x64, 0x2e, 0x61, 0x61, 0x61, 0x00, 0x00, 0x00,
	0x01, 0x01, 0x40, 0x00, 0x00, 0x0e, 0x00, 0x01, 0xc0, 0xa8, 0x69, 0x28, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x0a, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0d, 0x00, 0x00,
	0x00, 0x15, 0x4f, 0x70, 0x65, 0x6e, 0x20, 0x44, 0x69, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x16, 0x40, 0x00, 0x00, 0x0c, 0x4b, 0xed, 0x17, 0xdc, 0x00, 0x00,
	0x01, 0x09, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x40, 0x00,
	0x00, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x02, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00,
	0x00, 0x05, 0x00, 0x00, 0x01, 0x0b, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x01, 0x2b, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
}

var testPacketDiameterAnswer = []byte{
	0x08, 0x00, 0x27, 0xd9, 0xb0, 0x9d, 0x08, 0x00, 0x27, 0xf0, 0xa1, 0x70, 0x08, 0x00, 0x45, 0x00,
	0x01, 0x00, 0xbd, 0xc3, 0x40, 0x00, 0x40, 0x06, 0x28, 0x9d, 0xc0, 0xa8, 0x69, 0x1e, 0xc0, 0xa8,
	0x69, 0x28, 0x0f, 0x1c, 0x0b, 0x1c, 0xe4, 0x2e, 0x8e, 0x9b, 0x99, 0x6e, 0xf3, 0x92, 0x80, 0x18,
	0x01, 0xad, 0xf8, 0x30, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x00, 0x01, 0x33, 0x61, 0x00, 0x1a,
	0xcd, 0xd4, 0x01, 0x00, 0x00, 0xcc, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x53, 0xca,
	0xfe, 0x6a, 0x7d, 0xc0, 0xa1, 0x1b, 0x00, 0x00, 0x01, 0x0c, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00,
	0x07, 0xd1, 0x00, 0x00, 0x01, 0x08, 0x40, 0x00, 0x00, 0x1a, 0x67, 0x77, 0x2e, 0x65, 0x61, 0x70,
	0x2e, 0x74, 0x65, 0x73, 0x74, 0x62, 0x65, 0x64, 0x2e, 0x61, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x28, 0x40, 0x00, 0x00, 0x17, 0x65, 0x61, 0x70, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x62, 0x65,
	0x64, 0x2e, 0x61, 0x61, 0x61, 0x00, 0x00, 0x00, 0x01, 0x16, 0x40, 0x00, 0x00, 0x0c, 0x4b, 0xed,
	0x16, 0x3e, 0x00, 0x00, 0x01, 0x01, 0x40, 0x00, 0x00, 0x0e, 0x00, 0x01, 0xc0, 0xa8, 0x69, 0x1e,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x0d, 0x00, 0x00, 0x00, 0x14, 0x66, 0x72, 0x65, 0x65, 0x44, 0x69, 0x61, 0x6d, 0x65, 0x74,
	0x65, 0x72, 0x00, 0x00, 0x01, 0x0b, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00,
	0x01, 0x2b, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x40, 0x00,
	0x00, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x03, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00,
	0x00, 0x03, 0x00, 0x00, 0x01, 0x02, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x05,
}

func TestPacketDiameterRequest(t *testing.T) {
	packet := gopacket.NewPacket(testPacketDiameterRequest, LinkTypeEthernet, gopacket.DecodeStreamsAsDatagrams)
	if packet.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", packet.ErrorLayer().Error())
	}
	checkLayers(packet, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeDiameter}, t)

	if d, ok := packet.Layer(LayerTypeDiameter).(*Diameter); ok {
		if d.Version != 1 {
			t.Errorf("Failed to decode Diameter Version expecting 1 got %d", d.Version)
		}

		if d.Flags != 128 {
			t.Errorf("Failed to decode Diameter Flags expecting 8 got %d", d.Flags)
		}

		if d.MessageLen != 200 {
			t.Errorf("Failed to decode Diameter Message Length expecting 200 got %d", d.MessageLen)
		}

		if d.CommandCode != 257 {
			t.Errorf("Failed to decode Diameter Command Code expecting 257 got %d", d.CommandCode)
		}

		if d.ApplicationID != 0 {
			t.Errorf("Failed to decode Diameter Application ID expecting 0 got %d", d.ApplicationID)
		}

		if d.HopByHopID != 1405812330 {
			t.Errorf("Failed to decode Diameter HopByHopID expecting 1405812330 got %d", d.HopByHopID)
		}

		if d.EndToEndID != 2109776155 {
			t.Errorf("Failed to decode Diameter EndToEndID expecting 2109776155 got %d", d.EndToEndID)
		}

		if len(d.AVPs) != 11 {
			t.Errorf("Failed to decode all AVPs expecting 11 found %d", len(d.AVPs))
		}

	}
}

func TestPacketDiameterAnswer(t *testing.T) {
	packet := gopacket.NewPacket(testPacketDiameterAnswer, LinkTypeEthernet, gopacket.DecodeStreamsAsDatagrams)
	if packet.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", packet.ErrorLayer().Error())
	}
	checkLayers(packet, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeDiameter}, t)

	if d, ok := packet.Layer(LayerTypeDiameter).(*Diameter); ok {
		if d.Version != 1 {
			t.Errorf("Failed to decode Diameter Version expecting 1 got %d", d.Version)
		}

		if d.Flags != 0 {
			t.Errorf("Failed to decode Diameter Flags expecting 0 got %d", d.Flags)
		}

		if d.MessageLen != 204 {
			t.Errorf("Failed to decode Diameter Message Length expecting 204 got %d", d.MessageLen)
		}

		if d.CommandCode != 257 {
			t.Errorf("Failed to decode Diameter Command Code expecting 257 got %d", d.CommandCode)
		}

		if d.ApplicationID != 0 {
			t.Errorf("Failed to decode Diameter Application ID expecting 0 got %d", d.ApplicationID)
		}

		if d.HopByHopID != 1405812330 {
			t.Errorf("Failed to decode Diameter HopByHopID expecting 1405812330 got %d", d.HopByHopID)
		}

		if d.EndToEndID != 2109776155 {
			t.Errorf("Failed to decode Diameter EndToEndID expecting 2109776155 got %d", d.EndToEndID)
		}

		if len(d.AVPs) != 12 {
			t.Errorf("Failed to decode all AVPs expecting 12 found %d", len(d.AVPs))
		}

	}
}
