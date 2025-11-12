//go:build windows

package winhello

import (
	"bytes"
	"unsafe"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	"golang.org/x/sys/windows"
)

type MakeCredentialRequest struct {
	*protocol.AuthenticatorMakeCredentialRequest
	RawRPID              []byte
	EmptyPinAuth         bool
	HMACSecretExt        int32
	PRFExt               int32
	HMACSecretSaltValues []byte
	LargeBlobKeyExt      int32
	LargeBlobSupport     uint32
	JSONExt              []byte
}

func (r *_WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST) ToMakeCredentialRequest() (*MakeCredentialRequest, error) {
	// Client Data Hash
	req := &MakeCredentialRequest{
		AuthenticatorMakeCredentialRequest: &protocol.AuthenticatorMakeCredentialRequest{
			ClientDataHash:        bytes.Clone(unsafe.Slice(r.PbClientDataHash, r.CbClientDataHash)),
			PinUvAuthParam:        bytes.Clone(unsafe.Slice(r.PbPinAuth, r.CbPinAuth)),
			PinUvAuthProtocol:     protocol.PinUvAuthProtocol(r.DwPinProtocol),
			EnterpriseAttestation: uint(r.DwEnterpriseAttestation),
		},
		RawRPID:              bytes.Clone(unsafe.Slice(r.PbRpId, r.CbRpId)),
		EmptyPinAuth:         int32ToBool(r.FEmptyPinAuth),
		HMACSecretExt:        r.LHmacSecretExt,
		PRFExt:               r.LPrfExt,
		HMACSecretSaltValues: bytes.Clone(unsafe.Slice(r.PbHmacSecretSaltValues, r.CbHmacSecretSaltValues)),
		LargeBlobKeyExt:      r.LLargeBlobKeyExt,
		LargeBlobSupport:     r.DwLargeBlobSupport,
		JSONExt:              bytes.Clone(unsafe.Slice(r.PbJsonExt, r.CbJsonExt)),
	}

	// RP Information
	if r.PRpInformation != nil {
		req.RP = credential.PublicKeyCredentialRpEntity{
			ID:   windows.UTF16PtrToString(r.PRpInformation.PwszId),
			Name: windows.UTF16PtrToString(r.PRpInformation.PwszName),
		}
	}

	// User Information
	if r.PUserInformation != nil {
		req.User = credential.PublicKeyCredentialUserEntity{
			ID:          bytes.Clone(unsafe.Slice(r.PUserInformation.PbId, r.PUserInformation.CbId)),
			Name:        windows.UTF16PtrToString(r.PUserInformation.PwszName),
			DisplayName: windows.UTF16PtrToString(r.PUserInformation.PwszDisplayName),
			Icon:        windows.UTF16PtrToString(r.PUserInformation.PwszIcon),
		}
	}

	// Crypto Parameters
	if r.WebAuthNCredentialParameters.CCredentialParameters > 0 {
		req.PubKeyCredParams = make([]credential.PublicKeyCredentialParameters, r.WebAuthNCredentialParameters.CCredentialParameters)
		credParams := unsafe.Slice(r.WebAuthNCredentialParameters.PCredentialParameters, r.WebAuthNCredentialParameters.CCredentialParameters)

		for i := range credParams {
			req.PubKeyCredParams[i].Type = credential.PublicKeyCredentialType(windows.UTF16PtrToString(credParams[i].PwszCredentialType))
			req.PubKeyCredParams[i].Algorithm = cose.Algorithm(credParams[i].LAlg)
		}
	}

	// Credentials used for exclusion
	if r.CredentialList.CCredentials > 0 {
		req.ExcludeList = make([]credential.PublicKeyCredentialDescriptor, r.CredentialList.CCredentials)
		for i, cred := range unsafe.Slice(r.CredentialList.PpCredentials, r.CredentialList.CCredentials) {
			req.ExcludeList[i].Type = credential.PublicKeyCredentialType(windows.UTF16PtrToString(cred.PwszCredentialType))
			req.ExcludeList[i].ID = bytes.Clone(unsafe.Slice(cred.PbId, cred.CbId))
			req.ExcludeList[i].Transports = flagsToTransports(cred.DwTransports)
		}
	}

	// Optional extensions to parse when performing the operation.
	if r.CbCborExtensionsMap != 0 {
		if err := cbor.Unmarshal(unsafe.Slice(r.PbCborExtensionsMap, r.CbCborExtensionsMap), &req.Extensions); err != nil {
			return nil, err
		}
	}

	// Authenticator Options
	if r.PAuthenticatorOptions != nil {
		req.Options = make(map[protocol.Option]bool)

		setOption := func(typ protocol.Option, opt int32) {
			switch opt {
			case +1:
				req.Options[typ] = true
			case 0:
				// option isn't defined
			case -1:
				req.Options[typ] = false
			}
		}

		setOption(protocol.OptionUserPresence, r.PAuthenticatorOptions.LUp)
		setOption(protocol.OptionUserVerification, r.PAuthenticatorOptions.LUv)
		setOption(protocol.OptionResidentKeys, r.PAuthenticatorOptions.LRequireResidentKey)
	}

	// "hmac-secret": true extension
	req.Extensions.CreateHMACSecretInput = protocol.CreateHMACSecretInput{
		HMACSecret: int32ToBool(r.LHmacSecretExt),
	}

	// "hmac-secret-mc" extension
	if r.PHmacSecretMcExtension != nil {
		req.Extensions.CreateHMACSecretMCInput = protocol.CreateHMACSecretMCInput{
			HMACSecret: protocol.HMACSecret{
				SaltEnc:  bytes.Clone(unsafe.Slice(r.PHmacSecretMcExtension.PbEncryptedSalt, r.PHmacSecretMcExtension.CbEncryptedSalt)),
				SaltAuth: bytes.Clone(unsafe.Slice(r.PHmacSecretMcExtension.PbSaltAuth, r.PHmacSecretMcExtension.CbSaltAuth)),
			},
		}

		if r.PHmacSecretMcExtension.PKeyAgreement != nil {
			// It seems Windows doesn't support the Octet Key Pair key type.
			req.Extensions.CreateHMACSecretMCInput.HMACSecret.KeyAgreement = cose.Key{
				cose.KeyParameterKty:    r.PHmacSecretMcExtension.PKeyAgreement.LKty,
				cose.KeyParameterAlg:    r.PHmacSecretMcExtension.PKeyAgreement.LAlg,
				cose.EC2KeyParameterCrv: r.PHmacSecretMcExtension.PKeyAgreement.LCrv,
				cose.EC2KeyParameterX:   bytes.Clone(unsafe.Slice(r.PHmacSecretMcExtension.PKeyAgreement.PbX, r.PHmacSecretMcExtension.PKeyAgreement.CbX)),
				cose.EC2KeyParameterY:   bytes.Clone(unsafe.Slice(r.PHmacSecretMcExtension.PKeyAgreement.PbY, r.PHmacSecretMcExtension.PKeyAgreement.CbY)),
			}
		}
	}

	// "credProtect" extension
	req.Extensions.CreateCredProtectInput = protocol.CreateCredProtectInput{
		CredProtect: int(r.DwCredProtect),
	}

	// "credBlob" extension
	req.Extensions.CreateCredBlobInput = protocol.CreateCredBlobInput{
		CredBlob: bytes.Clone(unsafe.Slice(r.PbCredBlobExt, r.CbCredBlobExt)),
	}

	// "minPinLength" extension
	req.Extensions.CreateMinPinLengthInput = protocol.CreateMinPinLengthInput{
		MinPinLength: int32ToBool(r.LMinPinLengthExt),
	}

	return req, nil
}

type CTAPCBORGetAssertionRequest struct {
	*protocol.AuthenticatorGetAssertionRequest
	RawRPID                   []byte
	EmptyPinAuth              bool
	HMACSecretSaltValues      []byte
	LargeBlobKeyExt           int32
	CredLargeBlobOperation    uint32
	CredLargeBlobCompressed   []byte
	CredLargeBlobOriginalSize uint32
	JSONExt                   []byte
}

func (r *_WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST) ToGetAssertionRequest() (*CTAPCBORGetAssertionRequest, error) {
	req := &CTAPCBORGetAssertionRequest{
		AuthenticatorGetAssertionRequest: &protocol.AuthenticatorGetAssertionRequest{
			RPID:              windows.UTF16PtrToString(r.PwszRpId),
			ClientDataHash:    bytes.Clone(unsafe.Slice(r.PbClientDataHash, r.CbClientDataHash)),
			PinUvAuthParam:    bytes.Clone(unsafe.Slice(r.PbPinAuth, r.CbPinAuth)),
			PinUvAuthProtocol: protocol.PinUvAuthProtocol(r.DwPinProtocol),
		},
		RawRPID:                   bytes.Clone(unsafe.Slice(r.PbRpId, r.CbRpId)),
		EmptyPinAuth:              int32ToBool(r.FEmptyPinAuth),
		HMACSecretSaltValues:      bytes.Clone(unsafe.Slice(r.PbHmacSecretSaltValues, r.CbHmacSecretSaltValues)),
		LargeBlobKeyExt:           r.LLargeBlobKeyExt,
		CredLargeBlobOperation:    r.DwCredLargeBlobOperation,
		CredLargeBlobCompressed:   bytes.Clone(unsafe.Slice(r.PbCredLargeBlobCompressed, r.CbCredLargeBlobCompressed)),
		CredLargeBlobOriginalSize: r.DwCredLargeBlobOriginalSize,
		JSONExt:                   bytes.Clone(unsafe.Slice(r.PbJsonExt, r.CbJsonExt)),
	}

	// Credentials used for inclusion
	if r.CredentialList.CCredentials > 0 {
		req.AllowList = make([]credential.PublicKeyCredentialDescriptor, r.CredentialList.CCredentials)
		for i, cred := range unsafe.Slice(r.CredentialList.PpCredentials, r.CredentialList.CCredentials) {
			req.AllowList[i].Type = credential.PublicKeyCredentialType(windows.UTF16PtrToString(cred.PwszCredentialType))
			req.AllowList[i].ID = bytes.Clone(unsafe.Slice(cred.PbId, cred.CbId))
			req.AllowList[i].Transports = flagsToTransports(cred.DwTransports)
		}
	}

	// Optional extensions to parse when performing the operation.
	if r.CbCborExtensionsMap != 0 {
		if err := cbor.Unmarshal(unsafe.Slice(r.PbCborExtensionsMap, r.CbCborExtensionsMap), &req.Extensions); err != nil {
			return nil, err
		}
	}

	// HMAC Salt Extension (Optional)
	if r.PHmacSaltExtension != nil {
		req.Extensions.GetHMACSecretInput = protocol.GetHMACSecretInput{
			HMACSecret: protocol.HMACSecret{
				SaltEnc:  bytes.Clone(unsafe.Slice(r.PHmacSaltExtension.PbEncryptedSalt, r.PHmacSaltExtension.CbEncryptedSalt)),
				SaltAuth: bytes.Clone(unsafe.Slice(r.PHmacSaltExtension.PbSaltAuth, r.PHmacSaltExtension.CbSaltAuth)),
			},
		}

		if r.PHmacSaltExtension.PKeyAgreement != nil {
			// It seems Windows doesn't support the Octet Key Pair key type.
			req.Extensions.GetHMACSecretInput.HMACSecret.KeyAgreement = cose.Key{
				cose.KeyParameterKty:    r.PHmacSaltExtension.PKeyAgreement.LKty,
				cose.KeyParameterAlg:    r.PHmacSaltExtension.PKeyAgreement.LAlg,
				cose.EC2KeyParameterCrv: r.PHmacSaltExtension.PKeyAgreement.LCrv,
				cose.EC2KeyParameterX:   bytes.Clone(unsafe.Slice(r.PHmacSaltExtension.PKeyAgreement.PbX, r.PHmacSaltExtension.PKeyAgreement.CbX)),
				cose.EC2KeyParameterY:   bytes.Clone(unsafe.Slice(r.PHmacSaltExtension.PKeyAgreement.PbY, r.PHmacSaltExtension.PKeyAgreement.CbY)),
			}
		}
	}

	// "credBlob" extension
	req.Extensions.GetCredBlobInput = protocol.GetCredBlobInput{
		CredBlob: int32ToBool(r.LCredBlobExt),
	}

	// Authenticator Options
	if r.PAuthenticatorOptions != nil {
		req.Options = make(map[protocol.Option]bool)

		setOption := func(typ protocol.Option, opt int32) {
			switch opt {
			case +1:
				req.Options[typ] = true
			case 0:
				// option isn't defined
			case -1:
				req.Options[typ] = false
			}
		}

		setOption(protocol.OptionUserPresence, r.PAuthenticatorOptions.LUp)
		setOption(protocol.OptionUserVerification, r.PAuthenticatorOptions.LUv)
		setOption(protocol.OptionResidentKeys, r.PAuthenticatorOptions.LRequireResidentKey)
	}

	return req, nil
}

type CTAPCBORGetAssertionResponse struct {
	*WinHelloGetAssertionResponse
	UserInformation             *credential.PublicKeyCredentialUserEntity
	NumberOfCredentials         uint
	UserSelected                int
	LargeBlobKey                []byte
	UnsignedExtensionOutputsRaw []byte
}
