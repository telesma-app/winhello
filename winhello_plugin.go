//go:build windows

package winhello

import (
	"bytes"
	"crypto"
	"errors"
	"unsafe"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/winhello/internal/utils"
	"golang.org/x/sys/windows"
)

var (
	procWebAuthNPluginGetAuthenticatorState                   = modWebAuthn.NewProc("WebAuthNPluginGetAuthenticatorState")
	procWebAuthNPluginAddAuthenticator                        = modWebAuthn.NewProc("WebAuthNPluginAddAuthenticator")
	procWebAuthNPluginFreeAddAuthenticatorResponse            = modWebAuthn.NewProc("WebAuthNPluginFreeAddAuthenticatorResponse")
	procWebAuthNPluginRemoveAuthenticator                     = modWebAuthn.NewProc("WebAuthNPluginRemoveAuthenticator")
	procWebAuthNPluginUpdateAuthenticatorDetails              = modWebAuthn.NewProc("WebAuthNPluginUpdateAuthenticatorDetails")
	procWebAuthNPluginAuthenticatorAddCredentials             = modWebAuthn.NewProc("WebAuthNPluginAuthenticatorAddCredentials")
	procWebAuthNPluginAuthenticatorRemoveCredentials          = modWebAuthn.NewProc("WebAuthNPluginAuthenticatorRemoveCredentials")
	procWebAuthNPluginAuthenticatorRemoveAllCredentials       = modWebAuthn.NewProc("WebAuthNPluginAuthenticatorRemoveAllCredentials")
	procWebAuthNPluginAuthenticatorGetAllCredentials          = modWebAuthn.NewProc("WebAuthNPluginAuthenticatorGetAllCredentials")
	procWebAuthNPluginAuthenticatorFreeCredentialDetailsArray = modWebAuthn.NewProc("WebAuthNPluginAuthenticatorFreeCredentialDetailsArray")
	procWebAuthNPluginPerformUserVerification                 = modWebAuthn.NewProc("WebAuthNPluginPerformUserVerification")
	procWebAuthNPluginFreeUserVerificationResponse            = modWebAuthn.NewProc("WebAuthNPluginFreeUserVerificationResponse")
	procWebAuthNPluginGetUserVerificationCount                = modWebAuthn.NewProc("WebAuthNPluginGetUserVerificationCount")
	procWebAuthNPluginGetUserVerificationPublicKey            = modWebAuthn.NewProc("WebAuthNPluginGetUserVerificationPublicKey")
	procWebAuthNPluginGetOperationSigningPublicKey            = modWebAuthn.NewProc("WebAuthNPluginGetOperationSigningPublicKey")
	procWebAuthNPluginFreePublicKeyResponse                   = modWebAuthn.NewProc("WebAuthNPluginFreePublicKeyResponse")
	procWebAuthNEncodeMakeCredentialResponse                  = modWebAuthn.NewProc("WebAuthNEncodeMakeCredentialResponse")
	procWebAuthNDecodeMakeCredentialRequest                   = modWebAuthn.NewProc("WebAuthNDecodeMakeCredentialRequest")
	procWebAuthNFreeDecodedMakeCredentialRequest              = modWebAuthn.NewProc("WebAuthNFreeDecodedMakeCredentialRequest")
	procWebAuthNDecodeGetAssertionRequest                     = modWebAuthn.NewProc("WebAuthNDecodeGetAssertionRequest")
	procWebAuthNFreeDecodedGetAssertionRequest                = modWebAuthn.NewProc("WebAuthNFreeDecodedGetAssertionRequest")
	procWebAuthNEncodeGetAssertionResponse                    = modWebAuthn.NewProc("WebAuthNEncodeGetAssertionResponse")
	procWebAuthNPluginRegisterStatusChangeCallback            = modWebAuthn.NewProc("WebAuthNPluginRegisterStatusChangeCallback")
	procWebAuthNPluginUnregisterStatusChangeCallback          = modWebAuthn.NewProc("WebAuthNPluginUnregisterStatusChangeCallback")
)

type PluginAuthenticatorState int32

const (
	PluginAuthenticatorStateDisabled = iota
	PluginAuthenticatorStateEnabled
)

func PluginGetAuthenticatorState(clsid string) (PluginAuthenticatorState, error) {
	if err := requireWebAuthn(procWebAuthNPluginGetAuthenticatorState); err != nil {
		return 0, err
	}

	rclsid, err := windows.GUIDFromString(clsid)
	if err != nil {
		return 0, err
	}

	var state PluginAuthenticatorState
	r1, _, _ := procWebAuthNPluginGetAuthenticatorState.Call(
		uintptr(unsafe.Pointer(&rclsid)),
		uintptr(unsafe.Pointer(&state)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return 0, windows.Errno(hr)
	}

	return state, nil
}

type PluginAddAuthenticatorOptions struct {
	AuthenticatorName string // required
	CLSID             string // required
	PluginRPID        string // required, MSDN is wrong
	LightThemeLogoSvg string
	DarkThemeLogoSvg  string
	AuthenticatorInfo *protocol.AuthenticatorGetInfoResponse
	SupportedRPIDs    []string
}

func PluginAddAuthenticator(winHelloOpts *PluginAddAuthenticatorOptions) ([]byte, error) {
	if err := requireWebAuthn(procWebAuthNPluginAddAuthenticator, procWebAuthNPluginFreeAddAuthenticatorResponse); err != nil {
		return nil, err
	}

	authenticatorNamePtr, err := windows.UTF16PtrFromString(winHelloOpts.AuthenticatorName)
	if err != nil {
		return nil, err
	}

	opts := &_WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS{
		PwszAuthenticatorName: authenticatorNamePtr,
	}

	if winHelloOpts.PluginRPID != "" {
		opts.PwszPluginRpId, err = windows.UTF16PtrFromString(winHelloOpts.PluginRPID)
		if err != nil {
			return nil, err
		}
	}
	if winHelloOpts.LightThemeLogoSvg != "" {
		opts.PwszLightThemeLogoSvg, err = windows.UTF16PtrFromString(winHelloOpts.LightThemeLogoSvg)
		if err != nil {
			return nil, err
		}
	}
	if winHelloOpts.DarkThemeLogoSvg != "" {
		opts.PwszDarkThemeLogoSvg, err = windows.UTF16PtrFromString(winHelloOpts.DarkThemeLogoSvg)
		if err != nil {
			return nil, err
		}
	}

	clsid, err := windows.GUIDFromString(winHelloOpts.CLSID)
	if err != nil {
		return nil, err
	}
	opts.Rclsid = (*_GUID)(&clsid)

	encMode, _ := cbor.CTAP2EncOptions().EncMode()
	authenticatorInfo, err := encMode.Marshal(winHelloOpts.AuthenticatorInfo)
	if err != nil {
		return nil, err
	}

	opts.CbAuthenticatorInfo = uint32(len(authenticatorInfo))
	opts.PbAuthenticatorInfo = unsafe.SliceData(authenticatorInfo)

	if winHelloOpts.SupportedRPIDs != nil && len(winHelloOpts.SupportedRPIDs) > 0 {
		supportedRPIDs := make([]*uint16, len(winHelloOpts.SupportedRPIDs))
		for i, rp := range winHelloOpts.SupportedRPIDs {
			supportedRPIDs[i] = windows.StringToUTF16Ptr(rp)
		}

		opts.CSupportedRpIds = uint32(len(supportedRPIDs))
		opts.PpwszSupportedRpIds = unsafe.SliceData(supportedRPIDs)
	}

	var addAuthenticatorResponsePtr *_WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE
	r1, _, _ := procWebAuthNPluginAddAuthenticator.Call(
		uintptr(unsafe.Pointer(opts)),
		uintptr(unsafe.Pointer(&addAuthenticatorResponsePtr)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return nil, windows.Errno(hr)
	}

	defer procWebAuthNPluginFreeAddAuthenticatorResponse.Call(uintptr(unsafe.Pointer(addAuthenticatorResponsePtr))) //nolint:errcheck // Native function returns void.

	opSignPubKey := bytes.Clone(unsafe.Slice(
		addAuthenticatorResponsePtr.PbOpSignPubKey,
		addAuthenticatorResponsePtr.CbOpSignPubKey,
	))

	return opSignPubKey, nil
}

func PluginRemoveAuthenticator(clsid string) error {
	if err := requireWebAuthn(procWebAuthNPluginRemoveAuthenticator); err != nil {
		return err
	}

	rclsid, err := windows.GUIDFromString(clsid)
	if err != nil {
		return err
	}

	r1, _, _ := procWebAuthNPluginRemoveAuthenticator.Call(
		uintptr(unsafe.Pointer(&rclsid)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return windows.Errno(hr)
	}

	return nil
}

type PluginUpdateAuthenticatorDetailsOptions struct {
	AuthenticatorName string
	CLSID             string
	NewCLSID          string
	LightThemeLogoSvg string
	DarkThemeLogoSvg  string
	AuthenticatorInfo *protocol.AuthenticatorGetInfoResponse
	SupportedRPIDs    []string
}

func PluginUpdateAuthenticatorDetails(winHelloOpts *PluginUpdateAuthenticatorDetailsOptions) error {
	if err := requireWebAuthn(procWebAuthNPluginUpdateAuthenticatorDetails); err != nil {
		return err
	}

	authenticatorNamePtr, err := windows.UTF16PtrFromString(winHelloOpts.AuthenticatorName)
	if err != nil {
		return err
	}

	opts := &_WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS{
		PwszAuthenticatorName: authenticatorNamePtr,
	}

	if winHelloOpts.LightThemeLogoSvg != "" {
		opts.PwszLightThemeLogoSvg, err = windows.UTF16PtrFromString(winHelloOpts.LightThemeLogoSvg)
		if err != nil {
			return err
		}
	}
	if winHelloOpts.DarkThemeLogoSvg != "" {
		opts.PwszDarkThemeLogoSvg, err = windows.UTF16PtrFromString(winHelloOpts.DarkThemeLogoSvg)
		if err != nil {
			return err
		}
	}

	clsid, err := windows.GUIDFromString(winHelloOpts.CLSID)
	if err != nil {
		return err
	}
	opts.Rclsid = (*_GUID)(&clsid)
	if winHelloOpts.NewCLSID != "" {
		newCLSID, err := windows.GUIDFromString(winHelloOpts.NewCLSID)
		if err != nil {
			return err
		}
		opts.RclsidNew = (*_GUID)(&newCLSID)
	}

	encMode, _ := cbor.CTAP2EncOptions().EncMode()
	authenticatorInfo, err := encMode.Marshal(winHelloOpts.AuthenticatorInfo)
	if err != nil {
		return err
	}

	opts.CbAuthenticatorInfo = uint32(len(authenticatorInfo))
	opts.PbAuthenticatorInfo = unsafe.SliceData(authenticatorInfo)

	if winHelloOpts.SupportedRPIDs != nil && len(winHelloOpts.SupportedRPIDs) > 0 {
		supportedRPIDs := make([]*uint16, len(winHelloOpts.SupportedRPIDs))
		for i, rp := range winHelloOpts.SupportedRPIDs {
			supportedRPIDs[i] = windows.StringToUTF16Ptr(rp)
		}

		opts.CSupportedRpIds = uint32(len(supportedRPIDs))
		opts.PpwszSupportedRpIds = unsafe.SliceData(supportedRPIDs)
	}

	r1, _, _ := procWebAuthNPluginUpdateAuthenticatorDetails.Call(
		uintptr(unsafe.Pointer(opts)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return windows.Errno(hr)
	}

	return nil
}

type PluginCredentialDetail struct {
	CredentialID    []byte
	RPID            string
	RPName          string
	UserID          []byte
	UserName        string
	UserDisplayName string
}

func PluginAuthenticatorAddCredentials(clsid string, credentials []*PluginCredentialDetail) error {
	if err := requireWebAuthn(procWebAuthNPluginAuthenticatorAddCredentials); err != nil {
		return err
	}

	rclsid, err := windows.GUIDFromString(clsid)
	if err != nil {
		return err
	}

	pCredDetails := make([]*_WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS, len(credentials))
	for i, cred := range credentials {
		pCredDetails[i] = &_WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS{
			CbCredentialId:      uint32(len(cred.CredentialID)),
			PbCredentialId:      unsafe.SliceData(cred.CredentialID),
			PwszRpId:            windows.StringToUTF16Ptr(cred.RPID),
			PwszRpName:          windows.StringToUTF16Ptr(cred.RPName),
			CbUserId:            uint32(len(cred.UserID)),
			PbUserId:            unsafe.SliceData(cred.UserID),
			PwszUserName:        windows.StringToUTF16Ptr(cred.UserName),
			PwszUserDisplayName: windows.StringToUTF16Ptr(cred.UserDisplayName),
		}
	}

	r1, _, _ := procWebAuthNPluginAuthenticatorAddCredentials.Call(
		uintptr(unsafe.Pointer(&rclsid)),
		uintptr(len(pCredDetails)),
		uintptr(unsafe.Pointer(pCredDetails[0])),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return windows.Errno(hr)
	}

	return nil
}

func PluginAuthenticatorRemoveCredentials(clsid string, credentials []*PluginCredentialDetail) error {
	if err := requireWebAuthn(procWebAuthNPluginAuthenticatorRemoveCredentials); err != nil {
		return err
	}

	rclsid, err := windows.GUIDFromString(clsid)
	if err != nil {
		return err
	}

	pCredDetails := make([]*_WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS, len(credentials))
	for i, cred := range credentials {
		pCredDetails[i] = &_WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS{
			CbCredentialId:      uint32(len(cred.CredentialID)),
			PbCredentialId:      unsafe.SliceData(cred.CredentialID),
			PwszRpId:            windows.StringToUTF16Ptr(cred.RPID),
			PwszRpName:          windows.StringToUTF16Ptr(cred.RPName),
			CbUserId:            uint32(len(cred.UserID)),
			PbUserId:            unsafe.SliceData(cred.UserID),
			PwszUserName:        windows.StringToUTF16Ptr(cred.UserName),
			PwszUserDisplayName: windows.StringToUTF16Ptr(cred.UserDisplayName),
		}
	}

	r1, _, _ := procWebAuthNPluginAuthenticatorRemoveCredentials.Call(
		uintptr(unsafe.Pointer(&rclsid)),
		uintptr(len(pCredDetails)),
		uintptr(unsafe.Pointer(pCredDetails[0])),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return windows.Errno(hr)
	}

	return nil
}

func PluginAuthenticatorRemoveAllCredentials(clsid string) error {
	if err := requireWebAuthn(procWebAuthNPluginAuthenticatorRemoveAllCredentials); err != nil {
		return err
	}

	rclsid, err := windows.GUIDFromString(clsid)
	if err != nil {
		return err
	}

	r1, _, _ := procWebAuthNPluginAuthenticatorRemoveAllCredentials.Call(
		uintptr(unsafe.Pointer(&rclsid)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return windows.Errno(hr)
	}

	return nil
}

func PluginAuthenticatorGetAllCredentials(clsid string) ([]*PluginCredentialDetail, error) {
	if err := requireWebAuthn(procWebAuthNPluginAuthenticatorGetAllCredentials, procWebAuthNPluginAuthenticatorFreeCredentialDetailsArray); err != nil {
		return nil, err
	}

	rclsid, err := windows.GUIDFromString(clsid)
	if err != nil {
		return nil, err
	}

	var (
		cCredDetails uint32
		pCredDetails *_WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS
	)
	r1, _, _ := procWebAuthNPluginAuthenticatorGetAllCredentials.Call(
		uintptr(unsafe.Pointer(&rclsid)),
		uintptr(unsafe.Pointer(&cCredDetails)),
		uintptr(unsafe.Pointer(&pCredDetails)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return nil, windows.Errno(hr)
	}

	rawCredDetails := unsafe.Slice(pCredDetails, cCredDetails)
	credDetails := make([]*PluginCredentialDetail, cCredDetails)
	for i, rawCredDetail := range rawCredDetails {
		credDetails[i] = &PluginCredentialDetail{
			CredentialID:    bytes.Clone(unsafe.Slice(rawCredDetail.PbCredentialId, rawCredDetail.CbCredentialId)),
			RPID:            windows.UTF16PtrToString(rawCredDetail.PwszRpId),
			RPName:          windows.UTF16PtrToString(rawCredDetail.PwszRpName),
			UserID:          bytes.Clone(unsafe.Slice(rawCredDetail.PbUserId, rawCredDetail.CbUserId)),
			UserName:        windows.UTF16PtrToString(rawCredDetail.PwszUserName),
			UserDisplayName: windows.UTF16PtrToString(rawCredDetail.PwszUserDisplayName),
		}
	}

	procWebAuthNPluginAuthenticatorFreeCredentialDetailsArray.Call(
		uintptr(cCredDetails),
		uintptr(unsafe.Pointer(pCredDetails)),
	) //nolint:errcheck // Native function returns void.

	return credDetails, nil
}

type PluginUserVerificationRequestOptions struct {
	WindowHandle  windows.HWND
	TransactionID string
	Username      string
	DisplayHint   string
}

func PluginPerformUserVerification(winHelloOpts *PluginUserVerificationRequestOptions) ([]byte, error) {
	if err := requireWebAuthn(procWebAuthNPluginPerformUserVerification, procWebAuthNPluginFreeUserVerificationResponse); err != nil {
		return nil, err
	}

	guidTransactionID, err := windows.GUIDFromString(winHelloOpts.TransactionID)
	if err != nil {
		return nil, err
	}

	userVerificationRequest := &_WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST{
		Hwnd:               uintptr(winHelloOpts.WindowHandle),
		RguidTransactionId: (*_GUID)(&guidTransactionID),
		PwszUsername:       windows.StringToUTF16Ptr(winHelloOpts.Username),
		PwszDisplayHint:    windows.StringToUTF16Ptr(winHelloOpts.DisplayHint),
	}

	var (
		cbResponse uint32
		pbResponse *byte
	)
	r1, _, _ := procWebAuthNPluginPerformUserVerification.Call(
		uintptr(unsafe.Pointer(userVerificationRequest)),
		uintptr(unsafe.Pointer(&cbResponse)),
		uintptr(unsafe.Pointer(&pbResponse)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return nil, windows.Errno(hr)
	}

	defer procWebAuthNPluginFreeUserVerificationResponse.Call(uintptr(unsafe.Pointer(pbResponse))) //nolint:errcheck // Native function returns void.

	return bytes.Clone(unsafe.Slice(pbResponse, cbResponse)), nil
}

func PluginGetUserVerificationCount(clsid string) (uint32, error) {
	if err := requireWebAuthn(procWebAuthNPluginGetUserVerificationCount); err != nil {
		return 0, err
	}

	rclsid, err := windows.GUIDFromString(clsid)
	if err != nil {
		return 0, err
	}

	var count uint32
	r1, _, _ := procWebAuthNPluginGetUserVerificationCount.Call(
		uintptr(unsafe.Pointer(&rclsid)),
		uintptr(unsafe.Pointer(&count)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return 0, windows.Errno(hr)
	}

	return count, nil
}

func PluginGetUserVerificationPublicKey(clsid string) (crypto.PublicKey, error) {
	if err := requireWebAuthn(procWebAuthNPluginGetUserVerificationPublicKey, procWebAuthNPluginFreePublicKeyResponse); err != nil {
		return nil, err
	}

	rclsid, err := windows.GUIDFromString(clsid)
	if err != nil {
		return nil, err
	}

	var (
		cbPublicKey uint32
		pPublicKey  *byte
	)
	r1, _, _ := procWebAuthNPluginGetUserVerificationPublicKey.Call(
		uintptr(unsafe.Pointer(&rclsid)),
		uintptr(unsafe.Pointer(&cbPublicKey)),
		uintptr(unsafe.Pointer(&pPublicKey)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return nil, windows.Errno(hr)
	}

	pubKeyBytes := bytes.Clone(unsafe.Slice(pPublicKey, cbPublicKey))

	procWebAuthNPluginFreePublicKeyResponse.Call(
		uintptr(unsafe.Pointer(pPublicKey)),
	) //nolint:errcheck // Native function returns void.

	pubKey, err := utils.PublicKeyFromCNGECBlob(pubKeyBytes)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

func PluginGetOperationSigningPublicKey(clsid string) (crypto.PublicKey, error) {
	if err := requireWebAuthn(procWebAuthNPluginGetOperationSigningPublicKey, procWebAuthNPluginFreePublicKeyResponse); err != nil {
		return nil, err
	}

	rclsid, err := windows.GUIDFromString(clsid)
	if err != nil {
		return nil, err
	}

	var (
		cbPublicKey uint32
		pPublicKey  *byte
	)
	r1, _, _ := procWebAuthNPluginGetOperationSigningPublicKey.Call(
		uintptr(unsafe.Pointer(&rclsid)),
		uintptr(unsafe.Pointer(&cbPublicKey)),
		uintptr(unsafe.Pointer(&pPublicKey)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return nil, windows.Errno(hr)
	}

	pubKeyBytes := bytes.Clone(unsafe.Slice(pPublicKey, cbPublicKey))

	procWebAuthNPluginFreePublicKeyResponse.Call(
		uintptr(unsafe.Pointer(pPublicKey)),
	) //nolint:errcheck // Native function returns void.

	pubKey, err := utils.PublicKeyFromCNGECBlob(pubKeyBytes)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

func PluginEncodeMakeCredentialResponse(decodedResponse *WinHelloMakeCredentialResponse) ([]byte, error) {
	if err := requireWebAuthn(procWebAuthNEncodeMakeCredentialResponse); err != nil {
		return nil, err
	}

	pCredAttestation := new(_WEBAUTHN_CREDENTIAL_ATTESTATION)
	pCredAttestation.DwVersion = currVer.credentialAttestation

	if decodedResponse.AuthenticatorMakeCredentialResponse == nil {
		return nil, errors.New("invalid make credential response")
	}

	// Attestation format type
	if decodedResponse.Format != "" {
		pCredAttestation.PwszFormatType, _ = windows.UTF16PtrFromString(string(decodedResponse.Format))
	} else {
		pCredAttestation.PwszFormatType, _ = windows.UTF16PtrFromString(string(attestation.AttestationStatementFormatIdentifierNone))
	}

	// Authenticator data
	if decodedResponse.AuthDataRaw != nil {
		pCredAttestation.CbAuthenticatorData = uint32(len(decodedResponse.AuthDataRaw))
		pCredAttestation.PbAuthenticatorData = unsafe.SliceData(decodedResponse.AuthDataRaw)
	}

	// CBOR attestation information
	if decodedResponse.AttestationStatement == nil {
		pCredAttestation.DwAttestationDecodeType = uint32(WinHelloAttestationDecodeNone)
	} else {
		encMode, _ := cbor.CTAP2EncOptions().EncMode()
		attStt, err := encMode.Marshal(decodedResponse.AttestationStatement)
		if err != nil {
			return nil, err
		}
		pCredAttestation.CbAttestation = uint32(len(attStt))
		pCredAttestation.PbAttestation = unsafe.SliceData(attStt)
		pCredAttestation.DwAttestationDecodeType = uint32(WinHelloAttestationDecodeCommon)

		var commonAttestation *_WEBAUTHN_COMMON_ATTESTATION

		if att, ok := decodedResponse.PackedAttestationStatementFormat(); ok {
			x509Chain := make([]_WEBAUTHN_X5C, len(att.X509Chain))
			for i, x5c := range att.X509Chain {
				x509Chain[i] = _WEBAUTHN_X5C{
					CbData: uint32(len(x5c)),
					PbData: unsafe.SliceData(x5c),
				}
			}

			commonAttestation = &_WEBAUTHN_COMMON_ATTESTATION{
				DwVersion:   currVer.commonAttestation,
				LAlg:        int32(att.Algorithm),
				CbSignature: uint32(len(att.Signature)),
				PbSignature: unsafe.SliceData(att.Signature),
				CX5c:        uint32(len(x509Chain)),
				PX5c:        unsafe.SliceData(x509Chain),
			}
		}

		if att, ok := decodedResponse.FIDOU2FAttestationStatementFormat(); ok {
			x509Chain := make([]_WEBAUTHN_X5C, len(att.X509Chain))
			for i, x5c := range att.X509Chain {
				x509Chain[i] = _WEBAUTHN_X5C{
					CbData: uint32(len(x5c)),
					PbData: unsafe.SliceData(x5c),
				}
			}

			commonAttestation = &_WEBAUTHN_COMMON_ATTESTATION{
				DwVersion:   currVer.commonAttestation,
				LAlg:        int32(cose.AlgorithmES256),
				CbSignature: uint32(len(att.Signature)),
				PbSignature: unsafe.SliceData(att.Signature),
				CX5c:        uint32(len(x509Chain)),
				PX5c:        unsafe.SliceData(x509Chain),
			}
		}

		if att, ok := decodedResponse.TPMAttestationStatementFormat(); ok {
			x509Chain := make([]_WEBAUTHN_X5C, len(att.X509Chain))
			for i, x5c := range att.X509Chain {
				x509Chain[i] = _WEBAUTHN_X5C{
					CbData: uint32(len(x5c)),
					PbData: unsafe.SliceData(x5c),
				}
			}

			commonAttestation = &_WEBAUTHN_COMMON_ATTESTATION{
				DwVersion:   currVer.commonAttestation,
				LAlg:        int32(att.Algorithm),
				CbSignature: uint32(len(att.Signature)),
				PbSignature: unsafe.SliceData(att.Signature),
				CX5c:        uint32(len(x509Chain)),
				PX5c:        unsafe.SliceData(x509Chain),
				PwszVer:     windows.StringToUTF16Ptr(att.Version),
				CbCertInfo:  uint32(len(att.CertInfo)),
				PbCertInfo:  unsafe.SliceData(att.CertInfo),
				CbPubArea:   uint32(len(att.PubArea)),
				PbPubArea:   unsafe.SliceData(att.PubArea),
			}
		}

		pCredAttestation.PvAttestationDecode = (*byte)(unsafe.Pointer(commonAttestation))
	}

	// The Credential ID bytes extracted from the Authenticator Data.
	if decodedResponse.AuthData != nil && decodedResponse.AuthData.AttestedCredentialData != nil {
		pCredAttestation.CbCredentialId = uint32(len(decodedResponse.AuthData.AttestedCredentialData.CredentialID))
		pCredAttestation.PbCredentialId = unsafe.SliceData(decodedResponse.AuthData.AttestedCredentialData.CredentialID)
	}
	// Fallback
	if decodedResponse.CredentialID != nil {
		pCredAttestation.CbCredentialId = uint32(len(decodedResponse.CredentialID))
		pCredAttestation.PbCredentialId = unsafe.SliceData(decodedResponse.CredentialID)
	}

	var (
		cbResp uint32
		pbRest *byte
	)

	r1, _, _ := procWebAuthNEncodeMakeCredentialResponse.Call(
		uintptr(unsafe.Pointer(pCredAttestation)),
		uintptr(unsafe.Pointer(&cbResp)),
		uintptr(unsafe.Pointer(&pbRest)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return nil, windows.Errno(hr)
	}

	// For some reason there is no Free method for this byte buffer.
	// I am not sure why, but it will probably leak.

	return bytes.Clone(unsafe.Slice(pbRest, cbResp)), nil
}

func PluginDecodeMakeCredentialRequest(encodedRequest []byte) (*MakeCredentialRequest, error) {
	if err := requireWebAuthn(procWebAuthNDecodeMakeCredentialRequest, procWebAuthNFreeDecodedMakeCredentialRequest); err != nil {
		return nil, err
	}

	var decodedRequest *_WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST

	r1, _, _ := procWebAuthNDecodeMakeCredentialRequest.Call(
		uintptr(len(encodedRequest)),
		uintptr(unsafe.Pointer(unsafe.SliceData(encodedRequest))),
		uintptr(unsafe.Pointer(&decodedRequest)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return nil, windows.Errno(hr)
	}

	defer procWebAuthNFreeDecodedMakeCredentialRequest.Call(uintptr(unsafe.Pointer(decodedRequest))) //nolint:errcheck // Native function returns void.

	return decodedRequest.ToMakeCredentialRequest()
}

func PluginDecodeGetAssertionRequest(encodedRequest []byte) (*CTAPCBORGetAssertionRequest, error) {
	if err := requireWebAuthn(procWebAuthNDecodeGetAssertionRequest, procWebAuthNFreeDecodedGetAssertionRequest); err != nil {
		return nil, err
	}

	var decodedRequest *_WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST

	r1, _, _ := procWebAuthNDecodeGetAssertionRequest.Call(
		uintptr(len(encodedRequest)),
		uintptr(unsafe.Pointer(unsafe.SliceData(encodedRequest))),
		uintptr(unsafe.Pointer(&decodedRequest)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return nil, windows.Errno(hr)
	}

	defer procWebAuthNFreeDecodedGetAssertionRequest.Call(uintptr(unsafe.Pointer(decodedRequest))) //nolint:errcheck // Native function returns void.

	return decodedRequest.ToGetAssertionRequest()
}

func PluginEncodeGetAssertionResponse(decodedResponse *CTAPCBORGetAssertionResponse) ([]byte, error) {
	if err := requireWebAuthn(procWebAuthNEncodeGetAssertionResponse); err != nil {
		return nil, err
	}

	if decodedResponse.WinHelloGetAssertionResponse == nil {
		return nil, errors.New("invalid get assertion response")
	}

	pGetAssertionResponse := new(_WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE)

	pGetAssertionResponse.WebAuthNAssertion = _WEBAUTHN_ASSERTION{
		DwVersion:           currVer.assertion,
		CbAuthenticatorData: uint32(len(decodedResponse.AuthDataRaw)),
		PbAuthenticatorData: unsafe.SliceData(decodedResponse.AuthDataRaw),
		CbSignature:         uint32(len(decodedResponse.Signature)),
		PbSignature:         unsafe.SliceData(decodedResponse.Signature),
		Credential: _WEBAUTHN_CREDENTIAL{
			DwVersion:          currVer.credential,
			CbId:               uint32(len(decodedResponse.Credential.ID)),
			PbId:               unsafe.SliceData(decodedResponse.Credential.ID),
			PwszCredentialType: windows.StringToUTF16Ptr(string(decodedResponse.Credential.Type)),
		},
		Extensions:                   _WEBAUTHN_EXTENSIONS{},
		CbCredLargeBlob:              uint32(len(decodedResponse.CredLargeBlob)),
		PbCredLargeBlob:              unsafe.SliceData(decodedResponse.CredLargeBlob),
		DwCredLargeBlobStatus:        uint32(decodedResponse.CredLargeBlobStatus),
		DwUsedTransport:              transportsToFlags(decodedResponse.UsedTransport),
		CbClientDataJSON:             uint32(len(decodedResponse.ClientDataJSON)),
		PbClientDataJSON:             unsafe.SliceData(decodedResponse.ClientDataJSON),
		CbAuthenticationResponseJSON: uint32(len(decodedResponse.AuthenticationResponseJSON)),
		PbAuthenticationResponseJSON: unsafe.SliceData(decodedResponse.AuthenticationResponseJSON),
	}

	if decodedResponse.User != nil {
		pGetAssertionResponse.WebAuthNAssertion.CbUserId = uint32(len(decodedResponse.User.ID))
		pGetAssertionResponse.WebAuthNAssertion.PbUserId = unsafe.SliceData(decodedResponse.User.ID)
	}

	if decodedResponse.hmacSecret != nil {
		pGetAssertionResponse.WebAuthNAssertion.PHmacSecret = &_WEBAUTHN_HMAC_SECRET_SALT{
			CbFirst:  uint32(len(decodedResponse.hmacSecret.First)),
			PbFirst:  unsafe.SliceData(decodedResponse.hmacSecret.First),
			CbSecond: uint32(len(decodedResponse.hmacSecret.Second)),
			PbSecond: unsafe.SliceData(decodedResponse.hmacSecret.Second),
		}
	}

	if decodedResponse.UnsignedExtensionOutputs != nil {
		encMode, _ := cbor.CTAP2EncOptions().EncMode()
		unsignedExtensionOutputs, err := encMode.Marshal(decodedResponse.UnsignedExtensionOutputs)
		if err != nil {
			return nil, err
		}
		pGetAssertionResponse.CbUnsignedExtensionOutputs = uint32(len(unsignedExtensionOutputs))
		pGetAssertionResponse.PbUnsignedExtensionOutputs = unsafe.SliceData(unsignedExtensionOutputs)
	}

	if decodedResponse.UserInformation != nil {
		pGetAssertionResponse.PUserInformation = &_WEBAUTHN_USER_ENTITY_INFORMATION{
			DwVersion:       currVer.userEntityInformation,
			CbId:            uint32(len(decodedResponse.UserInformation.ID)),
			PbId:            unsafe.SliceData(decodedResponse.UserInformation.ID),
			PwszName:        windows.StringToUTF16Ptr(decodedResponse.UserInformation.Name),
			PwszIcon:        windows.StringToUTF16Ptr(decodedResponse.UserInformation.Icon),
			PwszDisplayName: windows.StringToUTF16Ptr(decodedResponse.UserInformation.DisplayName),
		}
	}

	pGetAssertionResponse.DwNumberOfCredentials = uint32(decodedResponse.NumberOfCredentials)
	pGetAssertionResponse.LUserSelected = int32(decodedResponse.UserSelected)

	if decodedResponse.LargeBlobKey != nil {
		pGetAssertionResponse.CbLargeBlobKey = uint32(len(decodedResponse.LargeBlobKey))
		pGetAssertionResponse.PbLargeBlobKey = unsafe.SliceData(decodedResponse.LargeBlobKey)
	}

	// Priority over UnsignedExtensionOutputs inside WebAuthNAssertion
	if decodedResponse.UnsignedExtensionOutputsRaw != nil {
		pGetAssertionResponse.CbUnsignedExtensionOutputs = uint32(len(decodedResponse.UnsignedExtensionOutputsRaw))
		pGetAssertionResponse.PbUnsignedExtensionOutputs = unsafe.SliceData(decodedResponse.UnsignedExtensionOutputsRaw)
	}

	var (
		cbResp uint32
		pbResp *byte
	)

	r1, _, _ := procWebAuthNEncodeGetAssertionResponse.Call(
		uintptr(unsafe.Pointer(pGetAssertionResponse)),
		uintptr(unsafe.Pointer(&cbResp)),
		uintptr(unsafe.Pointer(&pbResp)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return nil, windows.Errno(hr)
	}

	// For some reason there is no Free method for this byte buffer.
	// I am not sure why, but it will probably leak.

	return bytes.Clone(unsafe.Slice(pbResp, cbResp)), nil
}
