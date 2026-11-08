package winhello

import (
	"slices"
	"testing"

	"github.com/telesma-app/ctap/credential"
)

func TestTransportFlags(t *testing.T) {
	for _, tt := range []struct {
		name       string
		flags      uint32
		transports []credential.AuthenticatorTransport
	}{
		{"none", 0, nil},
		{"USB", 0x01, []credential.AuthenticatorTransport{credential.AuthenticatorTransportUSB}},
		{"NFC", 0x02, []credential.AuthenticatorTransport{credential.AuthenticatorTransportNFC}},
		{"BLE", 0x04, []credential.AuthenticatorTransport{credential.AuthenticatorTransportBLE}},
		{"internal", 0x10, []credential.AuthenticatorTransport{credential.AuthenticatorTransportInternal}},
		{"hybrid", 0x20, []credential.AuthenticatorTransport{credential.AuthenticatorTransportHybrid}},
		{"smart_card", 0x40, []credential.AuthenticatorTransport{credential.AuthenticatorTransportSmartCard}},
		{"USB_and_NFC", 0x03, []credential.AuthenticatorTransport{credential.AuthenticatorTransportUSB, credential.AuthenticatorTransportNFC}},
		{"hybrid_and_smart_card", 0x60, []credential.AuthenticatorTransport{credential.AuthenticatorTransportHybrid, credential.AuthenticatorTransportSmartCard}},
		{"all", 0x77, []credential.AuthenticatorTransport{
			credential.AuthenticatorTransportUSB, credential.AuthenticatorTransportNFC,
			credential.AuthenticatorTransportBLE, credential.AuthenticatorTransportInternal,
			credential.AuthenticatorTransportHybrid, credential.AuthenticatorTransportSmartCard,
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := flagsToTransports(tt.flags); !slices.Equal(got, tt.transports) {
				t.Errorf("flagsToTransports(%#x) = %v, want %v", tt.flags, got, tt.transports)
			}

			if got := transportsToFlags(tt.transports); got != tt.flags {
				t.Errorf("transportsToFlags(%v) = %#x, want %#x", tt.transports, got, tt.flags)
			}
		})
	}
}
