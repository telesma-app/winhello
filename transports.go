package winhello

import "github.com/telesma-app/ctap/credential"

type WinHelloCTAPTransport uint32

const (
	WinHelloCTAPTransportUSB WinHelloCTAPTransport = 1 << iota
	WinHelloCTAPTransportNFC
	WinHelloCTAPTransportBLE
	WinHelloCTAPTransportTest
	WinHelloCTAPTransportInternal
	WinHelloCTAPTransportHybrid
	WinHelloCTAPTransportSmartCard
	WinHelloCTAPTransportFlagsMask WinHelloCTAPTransport = 0x0000007F
)

func transportsToFlags(transports []credential.AuthenticatorTransport) uint32 {
	var flags WinHelloCTAPTransport
	for _, transport := range transports {
		switch transport {
		case credential.AuthenticatorTransportUSB:
			flags |= WinHelloCTAPTransportUSB
		case credential.AuthenticatorTransportNFC:
			flags |= WinHelloCTAPTransportNFC
		case credential.AuthenticatorTransportBLE:
			flags |= WinHelloCTAPTransportBLE
		case credential.AuthenticatorTransportInternal:
			flags |= WinHelloCTAPTransportInternal
		case credential.AuthenticatorTransportHybrid:
			flags |= WinHelloCTAPTransportHybrid
		case credential.AuthenticatorTransportSmartCard:
			flags |= WinHelloCTAPTransportSmartCard
		}
	}
	return uint32(flags)
}

func flagsToTransports(flags uint32) []credential.AuthenticatorTransport {
	var transports []credential.AuthenticatorTransport
	for _, transport := range []struct {
		flag WinHelloCTAPTransport
		name credential.AuthenticatorTransport
	}{
		{WinHelloCTAPTransportUSB, credential.AuthenticatorTransportUSB},
		{WinHelloCTAPTransportNFC, credential.AuthenticatorTransportNFC},
		{WinHelloCTAPTransportBLE, credential.AuthenticatorTransportBLE},
		{WinHelloCTAPTransportInternal, credential.AuthenticatorTransportInternal},
		{WinHelloCTAPTransportHybrid, credential.AuthenticatorTransportHybrid},
		{WinHelloCTAPTransportSmartCard, credential.AuthenticatorTransportSmartCard},
	} {
		if flags&uint32(transport.flag) != 0 {
			transports = append(transports, transport.name)
		}
	}
	return transports
}
