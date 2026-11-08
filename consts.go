//go:build windows

package winhello

import (
	"bytes"
	"time"
	"unsafe"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/webauthn"
	"golang.org/x/sys/windows"
)

type WinHelloHashAlgorithm string

const (
	WinHelloHashAlgorithmSHA256 WinHelloHashAlgorithm = "SHA-256"
	WinHelloHashAlgorithmSHA384 WinHelloHashAlgorithm = "SHA-384"
	WinHelloHashAlgorithmSHA512 WinHelloHashAlgorithm = "SHA-512"
)

type WinHelloCOSEAlgorithm int32

const (
	WinHelloCOSEAlgorithmEcdsaP256WithSHA256 WinHelloCOSEAlgorithm = -7
	WinHelloCOSEAlgorithmEcdsaP384WithSHA384 WinHelloCOSEAlgorithm = -35
	WinHelloCOSEAlgorithmEcdsaP521WithSHA512 WinHelloCOSEAlgorithm = -36

	WinHelloCOSEAlgorithmRSASSAPKCS1V15WithSHA256 WinHelloCOSEAlgorithm = -257
	WinHelloCOSEAlgorithmRSASSAPKCS1V15WithSHA384 WinHelloCOSEAlgorithm = -258
	WinHelloCOSEAlgorithmRSASSAPKCS1V15WithSHA512 WinHelloCOSEAlgorithm = -259

	WinHelloCOSEAlgorithmRSAPSSWithSHA256 WinHelloCOSEAlgorithm = -37
	WinHelloCOSEAlgorithmRSAPSSWithSHA384 WinHelloCOSEAlgorithm = -38
	WinHelloCOSEAlgorithmRSAPSSWithSHA512 WinHelloCOSEAlgorithm = -39
)

type WinHelloUserVerification uint32

const (
	WinHelloUserVerificationAny WinHelloUserVerification = iota
	WinHelloUserVerificationOptional
	WinHelloUserVerificationOptionalWithCredentialIDList
	WinHelloUserVerificationRequired
)

type WinHelloAuthenticatorAttachment uint32

const (
	WinHelloAuthenticatorAttachmentAny WinHelloAuthenticatorAttachment = iota
	WinHelloAuthenticatorAttachmentPlatform
	WinHelloAuthenticatorAttachmentCrossPlatform
	WinHelloAuthenticatorAttachmentCrossPlatformU2FV2
)

type WinHelloUserVerificationRequirement uint32

const (
	WinHelloUserVerificationRequirementAny WinHelloUserVerificationRequirement = iota
	WinHelloUserVerificationRequirementRequired
	WinHelloUserVerificationRequirementPreferred
	WinHelloUserVerificationRequirementDiscouraged
)

type WinHelloAttestationConveyancePreference uint32

const (
	WinHelloAttestationConveyancePreferenceAny WinHelloAttestationConveyancePreference = iota
	WinHelloAttestationConveyancePreferenceNone
	WinHelloAttestationConveyancePreferenceIndirect
	WinHelloAttestationConveyancePreferenceDirect
)

type WinHelloEnterpriseAttestation uint32

const (
	WinHelloEnterpriseAttestationNone WinHelloEnterpriseAttestation = iota
	WinHelloEnterpriseAttestationVendorFacilitated
	WinHelloEnterpriseAttestationPlatformManaged
)

type WinHelloLargeBlobSupport uint32

const (
	WinHelloLargeBlobSupportNone WinHelloLargeBlobSupport = iota
	WinHelloLargeBlobSupportRequired
	WinHelloLargeBlobSupportPreferred
)

type WinHelloCredentialLargeBlobOperation uint32

const (
	WinHelloCredentialLargeBlobOperationNone WinHelloCredentialLargeBlobOperation = iota
	WinHelloCredentialLargeBlobOperationGet
	WinHelloCredentialLargeBlobOperationSet
	WinHelloCredentialLargeBlobOperationDelete
)

const WinHelloAuthenticatorHMACSecretValuesFlag = 0x00100000

type WinHelloAttestationDecodeType uint32

const (
	WinHelloAttestationDecodeNone WinHelloAttestationDecodeType = iota
	WinHelloAttestationDecodeCommon
)

type WinHelloCredentialLargeBlobStatus uint32

const (
	WinHelloCredentialLargeBlobStatusNone WinHelloCredentialLargeBlobStatus = iota
	WinHelloCredentialLargeBlobStatusSuccess
	WinHelloCredentialLargeBlobStatusNotSupported
	WinHelloCredentialLargeBlobStatusInvalidData
	WinHelloCredentialLargeBlobStatusInvalidParameter
	WinHelloCredentialLargeBlobStatusNotFound
	WinHelloCredentialLargeBlobStatusMultipleCredentials
	WinHelloCredentialLargeBlobStatusLackOfSpace
	WinHelloCredentialLargeBlobStatusPlatformError
	WinHelloCredentialLargeBlobStatusAuthenticatorError
)

type AuthenticatorGetAssertionOptions struct {
	Timeout                               time.Duration
	AuthenticatorAttachment               WinHelloAuthenticatorAttachment
	UserVerificationRequirement           WinHelloUserVerificationRequirement
	U2FAppID                              string
	CancellationID                        *windows.GUID
	CredentialLargeBlobOperation          WinHelloCredentialLargeBlobOperation
	CredentialLargeBlob                   []byte
	BrowserInPrivateMode                  bool
	AutoFill                              bool
	JsonExt                               []byte
	CredentialHints                       []credential.PublicKeyCredentialHint
	RemoteWebOrigin                       string
	PublicKeyCredentialRequestOptionsJSON []byte
	AuthenticatorID                       []byte
}

type WinHelloGetAssertionResponse struct {
	*protocol.AuthenticatorGetAssertionResponse
	CredLargeBlob              []byte
	CredLargeBlobStatus        WinHelloCredentialLargeBlobStatus
	UsedTransport              []credential.AuthenticatorTransport
	ClientDataJSON             []byte
	AuthenticationResponseJSON []byte
	// U2FAppIDUsed reports whether Windows used the requested U2F AppID instead of rpID.
	U2FAppIDUsed bool
	hmacSecret   *webauthn.AuthenticationExtensionsPRFValues
}

func (a *_WEBAUTHN_ASSERTION) ToGetAssertionResponse(extInputs *webauthn.GetAuthenticationExtensionsClientInputs) (
	*WinHelloGetAssertionResponse,
	error,
) {
	authDataRaw := bytes.Clone(unsafe.Slice(a.PbAuthenticatorData, a.CbAuthenticatorData))

	authData, err := protocol.ParseGetAssertionAuthData(authDataRaw)
	if err != nil {
		return nil, err
	}

	resp := &protocol.AuthenticatorGetAssertionResponse{
		Credential: credential.PublicKeyCredentialDescriptor{
			Type: credential.PublicKeyCredentialType(windows.UTF16PtrToString(a.Credential.PwszCredentialType)),
			ID:   bytes.Clone(unsafe.Slice(a.Credential.PbId, a.Credential.CbId)),
		},
		AuthData:    &authData,
		AuthDataRaw: authDataRaw,
		Signature:   bytes.Clone(unsafe.Slice(a.PbSignature, a.CbSignature)),
	}

	userID := bytes.Clone(unsafe.Slice(a.PbUserId, a.CbUserId))
	if len(userID) > 0 {
		resp.User = &credential.PublicKeyCredentialUserEntity{
			ID: userID,
		}
	}

	winHelloResp := &WinHelloGetAssertionResponse{
		AuthenticatorGetAssertionResponse: resp,
	}

	if a.DwVersion >= 2 {
		winHelloResp.CredLargeBlob = bytes.Clone(unsafe.Slice(a.PbCredLargeBlob, a.CbCredLargeBlob))
		winHelloResp.CredLargeBlobStatus = WinHelloCredentialLargeBlobStatus(a.DwCredLargeBlobStatus)
	}

	if a.DwVersion >= 3 && a.PHmacSecret != nil {
		winHelloResp.hmacSecret = &webauthn.AuthenticationExtensionsPRFValues{
			First:  bytes.Clone(unsafe.Slice(a.PHmacSecret.PbFirst, a.PHmacSecret.CbFirst)),
			Second: bytes.Clone(unsafe.Slice(a.PHmacSecret.PbSecond, a.PHmacSecret.CbSecond)),
		}
	}

	if a.DwVersion >= 4 {
		winHelloResp.UsedTransport = flagsToTransports(a.DwUsedTransport)
	}

	if a.DwVersion >= 5 {
		unsignedExtensionOutputsRaw := bytes.Clone(unsafe.Slice(a.PbUnsignedExtensionOutputs, a.CbUnsignedExtensionOutputs))
		if len(unsignedExtensionOutputsRaw) > 0 {
			if err := cbor.Unmarshal(unsignedExtensionOutputsRaw, &resp.UnsignedExtensionOutputs); err != nil {
				return nil, err
			}
		}
	}

	if a.DwVersion >= 6 {
		clientDataJSONRaw := bytes.Clone(unsafe.Slice(a.PbClientDataJSON, a.CbClientDataJSON))
		if len(clientDataJSONRaw) > 0 {
			winHelloResp.ClientDataJSON = clientDataJSONRaw
		}

		authenticationResponseJSONRaw := bytes.Clone(unsafe.Slice(a.PbAuthenticationResponseJSON, a.CbAuthenticationResponseJSON))
		if len(authenticationResponseJSONRaw) > 0 {
			winHelloResp.AuthenticationResponseJSON = authenticationResponseJSONRaw
		}
	}

	winHelloResp.ExtensionOutputs = new(webauthn.GetAuthenticationExtensionsClientOutputs)

	if extInputs != nil && extInputs.LargeBlobInputs != nil {
		blob := extInputs.LargeBlob

		success := a.DwVersion >= 2 && winHelloResp.CredLargeBlobStatus == WinHelloCredentialLargeBlobStatusSuccess
		if blob.Read != nil && *blob.Read {
			winHelloResp.ExtensionOutputs.LargeBlobOutputs = &webauthn.LargeBlobOutputs{}
			if success {
				// Keep a successful empty read distinct from a missing blob.
				winHelloResp.ExtensionOutputs.LargeBlob.Blob = append([]byte{}, winHelloResp.CredLargeBlob...)
			}
		} else if blob.Write != nil {
			winHelloResp.ExtensionOutputs.LargeBlobOutputs = &webauthn.LargeBlobOutputs{
				LargeBlob: webauthn.AuthenticationExtensionsLargeBlobOutputs{Written: new(success)},
			}
		}
	}

	if extInputs != nil && winHelloResp.hmacSecret != nil {
		if extInputs.GetHMACSecretInputs != nil {
			winHelloResp.ExtensionOutputs.GetHMACSecretOutputs = &webauthn.GetHMACSecretOutputs{
				HMACGetSecret: webauthn.HMACGetSecretOutput{
					Output1: winHelloResp.hmacSecret.First,
					Output2: winHelloResp.hmacSecret.Second,
				},
			}
		}

		if extInputs.PRFInputs != nil {
			winHelloResp.ExtensionOutputs.GetPRFOutputs = &webauthn.GetPRFOutputs{
				PRF: webauthn.GetAuthenticationExtensionsPRFOutputs{
					Results: webauthn.AuthenticationExtensionsPRFValues{
						First:  winHelloResp.hmacSecret.First,
						Second: winHelloResp.hmacSecret.Second,
					},
				},
			}
		}
	}

	if winHelloResp.AuthData.Extensions != nil && winHelloResp.AuthData.Extensions.CredBlob != nil {
		winHelloResp.ExtensionOutputs.GetCredentialBlobOutputs = &webauthn.GetCredentialBlobOutputs{
			GetCredBlob: winHelloResp.AuthData.Extensions.CredBlob,
		}
	}

	if a.DwVersion >= 2 {
		for _, ext := range unsafe.Slice(a.Extensions.PExtensions, a.Extensions.CExtensions) {
			switch windows.UTF16PtrToString(ext.PwszExtensionIdentifier) {
			case string(extension.ExtensionIdentifierCredentialBlob):
				blob := (*_WEBAUTHN_CRED_BLOB_EXTENSION)(unsafe.Pointer(ext.PvExtension))
				winHelloResp.ExtensionOutputs.GetCredentialBlobOutputs = &webauthn.GetCredentialBlobOutputs{
					GetCredBlob: bytes.Clone(unsafe.Slice(blob.PbCredBlob, blob.CbCredBlob)),
				}
			}
		}
	}

	return winHelloResp, nil
}

type AuthenticatorMakeCredentialOptions struct {
	Timeout                                time.Duration
	AuthenticatorAttachment                WinHelloAuthenticatorAttachment
	RequireResidentKey                     bool
	UserVerificationRequirement            WinHelloUserVerificationRequirement
	AttestationConveyancePreference        WinHelloAttestationConveyancePreference
	CancellationID                         *windows.GUID
	EnterpriseAttestation                  WinHelloEnterpriseAttestation
	LargeBlobSupport                       WinHelloLargeBlobSupport
	PreferResidentKey                      bool
	BrowserInPrivateMode                   bool
	JsonExt                                []byte
	CredentialHints                        []credential.PublicKeyCredentialHint
	ThirdPartyPayment                      bool
	RemoteWebOrigin                        string
	PublicKeyCredentialCreationOptionsJSON []byte
	AuthenticatorID                        []byte
}

type WinHelloMakeCredentialResponse struct {
	*protocol.AuthenticatorMakeCredentialResponse
	CredentialID             []byte
	UsedTransport            []credential.AuthenticatorTransport
	LargeBlobSupported       bool
	ResidentKey              bool
	PRFEnabled               bool
	HMACSecret               *webauthn.AuthenticationExtensionsPRFValues
	ThirdPartyPayment        bool
	Transports               []credential.AuthenticatorTransport
	ClientDataJSON           []byte
	RegistrationResponseJSON []byte
}

func (a *_WEBAUTHN_CREDENTIAL_ATTESTATION) ToMakeCredentialResponse(extInputs *webauthn.CreateAuthenticationExtensionsClientInputs) (*WinHelloMakeCredentialResponse, error) {
	authDataRaw := bytes.Clone(unsafe.Slice(a.PbAuthenticatorData, a.CbAuthenticatorData))

	authData, err := protocol.ParseMakeCredentialAuthData(authDataRaw)
	if err != nil {
		return nil, err
	}

	resp := &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifier(windows.UTF16PtrToString(a.PwszFormatType)),
		AuthData:    &authData,
		AuthDataRaw: authDataRaw,
	}

	attestationRaw := bytes.Clone(unsafe.Slice(a.PbAttestation, a.CbAttestation))
	if resp.Format != attestation.AttestationStatementFormatIdentifierNone &&
		len(attestationRaw) > 0 {
		if err := cbor.Unmarshal(attestationRaw, &resp.AttestationStatement); err != nil {
			return nil, err
		}
	}

	winHelloResp := &WinHelloMakeCredentialResponse{
		AuthenticatorMakeCredentialResponse: resp,
		CredentialID:                        bytes.Clone(unsafe.Slice(a.PbCredentialId, a.CbCredentialId)),
	}

	if a.DwVersion >= 3 {
		winHelloResp.UsedTransport = flagsToTransports(a.DwUsedTransport)
	}

	if a.DwVersion >= 4 {
		winHelloResp.EnterpriseAttestation = int32ToBool(a.BEpAtt)
		winHelloResp.LargeBlobSupported = int32ToBool(a.BLargeBlobSupported)
		winHelloResp.ResidentKey = int32ToBool(a.BResidentKey)
	}

	if a.DwVersion >= 5 {
		winHelloResp.PRFEnabled = int32ToBool(a.BPrfEnabled)
	}

	if a.DwVersion >= 6 {
		unsignedExtensionOutputsRaw := bytes.Clone(unsafe.Slice(a.PbUnsignedExtensionOutputs, a.CbUnsignedExtensionOutputs))
		if len(unsignedExtensionOutputsRaw) > 0 {
			if err := cbor.Unmarshal(unsignedExtensionOutputsRaw, &resp.UnsignedExtensionOutputs); err != nil {
				return nil, err
			}
		}
	}

	if a.DwVersion >= 7 {
		if a.PHmacSecret != nil {
			winHelloResp.HMACSecret = &webauthn.AuthenticationExtensionsPRFValues{
				First:  bytes.Clone(unsafe.Slice(a.PHmacSecret.PbFirst, a.PHmacSecret.CbFirst)),
				Second: bytes.Clone(unsafe.Slice(a.PHmacSecret.PbSecond, a.PHmacSecret.CbSecond)),
			}
		}

		winHelloResp.ThirdPartyPayment = int32ToBool(a.BThirdPartyPayment)
	}

	if a.DwVersion >= 8 {
		winHelloResp.Transports = flagsToTransports(a.DwTransports)

		clientDataJSONRaw := bytes.Clone(unsafe.Slice(a.PbClientDataJSON, a.CbClientDataJSON))
		if len(clientDataJSONRaw) > 0 {
			winHelloResp.ClientDataJSON = clientDataJSONRaw
		}

		registrationResponseJSONRaw := bytes.Clone(unsafe.Slice(a.PbRegistrationResponseJSON, a.CbRegistrationResponseJSON))
		if len(registrationResponseJSONRaw) > 0 {
			winHelloResp.RegistrationResponseJSON = registrationResponseJSONRaw
		}
	}

	winHelloResp.ExtensionOutputs = new(webauthn.CreateAuthenticationExtensionsClientOutputs)
	if extInputs != nil && extInputs.LargeBlobInputs != nil {
		winHelloResp.ExtensionOutputs.LargeBlobOutputs = &webauthn.LargeBlobOutputs{
			LargeBlob: webauthn.AuthenticationExtensionsLargeBlobOutputs{Supported: new(winHelloResp.LargeBlobSupported)},
		}
	}

	if extInputs != nil && extInputs.CreateCredentialPropertiesInputs != nil && extInputs.CredentialProperties {
		winHelloResp.ExtensionOutputs.CreateCredentialPropertiesOutputs = &webauthn.CreateCredentialPropertiesOutputs{}
		if a.DwVersion >= 4 {
			winHelloResp.ExtensionOutputs.CredentialProperties.ResidentKey = new(winHelloResp.ResidentKey)
		}
	}

	if extInputs != nil && extInputs.PRFInputs != nil {
		prf := &webauthn.CreatePRFOutputs{
			PRF: webauthn.CreateAuthenticationExtensionsPRFOutputs{Enabled: winHelloResp.PRFEnabled},
		}
		if winHelloResp.HMACSecret != nil {
			prf.PRF.Results = *winHelloResp.HMACSecret
		}

		winHelloResp.ExtensionOutputs.CreatePRFOutputs = prf
	}

	if extInputs != nil && extInputs.CreateHMACSecretMCInputs != nil && winHelloResp.HMACSecret != nil {
		winHelloResp.ExtensionOutputs.CreateHMACSecretMCOutputs = &webauthn.CreateHMACSecretMCOutputs{
			HMACGetSecret: webauthn.HMACGetSecretOutput{
				Output1: winHelloResp.HMACSecret.First,
				Output2: winHelloResp.HMACSecret.Second,
			},
		}
	}

	if winHelloResp.AuthData.Extensions != nil {
		if winHelloResp.AuthData.Extensions.CreateCredBlobOutput != nil {
			winHelloResp.ExtensionOutputs.CreateCredentialBlobOutputs = &webauthn.CreateCredentialBlobOutputs{
				CredBlob: winHelloResp.AuthData.Extensions.CredBlob,
			}
		}

		if winHelloResp.AuthData.Extensions.CreateHMACSecretOutput != nil {
			winHelloResp.ExtensionOutputs.CreateHMACSecretOutputs = &webauthn.CreateHMACSecretOutputs{
				HMACCreateSecret: winHelloResp.AuthData.Extensions.CreateHMACSecretOutput.HMACSecret,
			}
		}
	}

	if a.DwVersion >= 2 {
		for _, ext := range unsafe.Slice(a.Extensions.PExtensions, a.Extensions.CExtensions) {
			switch windows.UTF16PtrToString(ext.PwszExtensionIdentifier) {
			case string(extension.ExtensionIdentifierHMACSecret):
				winHelloResp.ExtensionOutputs.CreateHMACSecretOutputs = &webauthn.CreateHMACSecretOutputs{
					HMACCreateSecret: int32ToBool(*(*int32)(unsafe.Pointer(ext.PvExtension))),
				}
			case string(extension.ExtensionIdentifierCredentialBlob):
				winHelloResp.ExtensionOutputs.CreateCredentialBlobOutputs = &webauthn.CreateCredentialBlobOutputs{
					CredBlob: int32ToBool(*(*int32)(unsafe.Pointer(ext.PvExtension))),
				}
			}
		}
	}

	return winHelloResp, nil
}
