//go:build windows

//go:generate powershell -Command "go tool cgo -godefs types_webauthn.go | Set-Content -Path ztypes_webauthn.go -Encoding UTF8"
package winhello

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"unsafe"

	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/webauthn"
	"golang.org/x/sys/windows"
)

var (
	modWebAuthn                                               = windows.NewLazySystemDLL("webauthn.dll")
	procWebAuthNGetApiVersionNumber                           = modWebAuthn.NewProc("WebAuthNGetApiVersionNumber")
	procWebAuthNIsUserVerifyingPlatformAuthenticatorAvailable = modWebAuthn.NewProc("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable")
	procWebAuthNAuthenticatorMakeCredential                   = modWebAuthn.NewProc("WebAuthNAuthenticatorMakeCredential")
	procWebAuthNAuthenticatorGetAssertion                     = modWebAuthn.NewProc("WebAuthNAuthenticatorGetAssertion")
	procWebAuthNFreeCredentialAttestation                     = modWebAuthn.NewProc("WebAuthNFreeCredentialAttestation")
	procWebAuthNFreeAssertion                                 = modWebAuthn.NewProc("WebAuthNFreeAssertion")
	procWebAuthNGetCancellationId                             = modWebAuthn.NewProc("WebAuthNGetCancellationId")
	procWebAuthNCancelCurrentOperation                        = modWebAuthn.NewProc("WebAuthNCancelCurrentOperation")
	procWebAuthNGetPlatformCredentialList                     = modWebAuthn.NewProc("WebAuthNGetPlatformCredentialList")
	procWebAuthNFreePlatformCredentialList                    = modWebAuthn.NewProc("WebAuthNFreePlatformCredentialList")
	procWebAuthNDeletePlatformCredential                      = modWebAuthn.NewProc("WebAuthNDeletePlatformCredential")
	procWebAuthNGetAuthenticatorList                          = modWebAuthn.NewProc("WebAuthNGetAuthenticatorList")
	procWebAuthNFreeAuthenticatorList                         = modWebAuthn.NewProc("WebAuthNFreeAuthenticatorList")
	procWebAuthNGetErrorName                                  = modWebAuthn.NewProc("WebAuthNGetErrorName")
	procWebAuthNGetW3CExceptionDOMError                       = modWebAuthn.NewProc("WebAuthNGetW3CExceptionDOMError")
	currVer                                                   = availableVersions(APIVersionNumber())
)

// GetAssertion authenticates with a credential for rpID.
// extInputs and winHelloOpts may be nil to use the default options.
func GetAssertion(
	hWnd windows.HWND,
	rpID string,
	clientData []byte,
	allowList []credential.PublicKeyCredentialDescriptor,
	extInputs *webauthn.GetAuthenticationExtensionsClientInputs,
	winHelloOpts *AuthenticatorGetAssertionOptions,
) (*WinHelloGetAssertionResponse, error) {
	opts, err := getAssertionOptions(allowList, extInputs, winHelloOpts)
	if err != nil {
		return nil, err
	}

	var assertionPtr *_WEBAUTHN_ASSERTION

	r1, _, _ := procWebAuthNAuthenticatorGetAssertion.Call(
		uintptr(hWnd),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(rpID))),
		uintptr(unsafe.Pointer(&_WEBAUTHN_CLIENT_DATA{
			DwVersion:        currVer.clientData,
			CbClientDataJSON: uint32(len(clientData)),
			PbClientDataJSON: unsafe.SliceData(clientData),
			PwszHashAlgId:    windows.StringToUTF16Ptr("SHA-256"),
		})),
		uintptr(unsafe.Pointer(opts)),
		uintptr(unsafe.Pointer(&assertionPtr)),
	)
	if hr := windows.Errno(uint32(r1)); hr != 0 {
		return nil, hr
	}

	defer procWebAuthNFreeAssertion.Call(uintptr(unsafe.Pointer(assertionPtr)))

	resp, err := assertionPtr.ToGetAssertionResponse(extInputs)
	if err != nil {
		return nil, err
	}
	if opts.PbU2fAppId != nil {
		resp.U2FAppIDUsed = int32ToBool(*opts.PbU2fAppId)
	}
	return resp, nil
}

func getAssertionOptions(
	allowList []credential.PublicKeyCredentialDescriptor,
	extInputs *webauthn.GetAuthenticationExtensionsClientInputs,
	winHelloOpts *AuthenticatorGetAssertionOptions,
) (*_WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS, error) {
	if winHelloOpts == nil {
		winHelloOpts = &AuthenticatorGetAssertionOptions{}
	}

	opts := &_WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS{
		DwVersion:                               currVer.authenticatorGetAssertionOptions,
		DwTimeoutMilliseconds:                   uint32(winHelloOpts.Timeout.Milliseconds()),
		CredentialList:                          _WEBAUTHN_CREDENTIALS{}, // basically deprecated, baseline supports pAllowCredentialList
		DwAuthenticatorAttachment:               uint32(winHelloOpts.AuthenticatorAttachment),
		DwUserVerificationRequirement:           uint32(winHelloOpts.UserVerificationRequirement),
		DwFlags:                                 0, // user only in version 8 for PRF Global Eval
		DwCredLargeBlobOperation:                uint32(winHelloOpts.CredentialLargeBlobOperation),
		CbCredLargeBlob:                         uint32(len(winHelloOpts.CredentialLargeBlob)),
		PbCredLargeBlob:                         unsafe.SliceData(winHelloOpts.CredentialLargeBlob),
		BBrowserInPrivateMode:                   boolToInt32(winHelloOpts.BrowserInPrivateMode),
		BAutoFill:                               boolToInt32(winHelloOpts.AutoFill),
		CbJsonExt:                               uint32(len(winHelloOpts.JsonExt)),
		PbJsonExt:                               unsafe.SliceData(winHelloOpts.JsonExt),
		CbPublicKeyCredentialRequestOptionsJSON: uint32(len(winHelloOpts.PublicKeyCredentialRequestOptionsJSON)),
		PbPublicKeyCredentialRequestOptionsJSON: unsafe.SliceData(winHelloOpts.PublicKeyCredentialRequestOptionsJSON),
		CbAuthenticatorId:                       uint32(len(winHelloOpts.AuthenticatorID)),
		PbAuthenticatorId:                       unsafe.SliceData(winHelloOpts.AuthenticatorID),
	}

	credExList := make([]*_WEBAUTHN_CREDENTIAL_EX, len(allowList))
	for i, ex := range allowList {
		credExList[i] = &_WEBAUTHN_CREDENTIAL_EX{
			DwVersion:          currVer.credentialEx,
			CbId:               uint32(len(ex.ID)),
			PbId:               unsafe.SliceData(ex.ID),
			PwszCredentialType: windows.StringToUTF16Ptr(string(ex.Type)),
			DwTransports:       transportsToFlags(ex.Transports),
		}
	}
	if len(credExList) > 0 {
		opts.PAllowCredentialList = &_WEBAUTHN_CREDENTIAL_LIST{
			CCredentials:  uint32(len(credExList)),
			PpCredentials: unsafe.SliceData(credExList),
		}
	}

	if winHelloOpts.CancellationID != nil {
		opts.PCancellationId = &_GUID{
			Data1: winHelloOpts.CancellationID.Data1,
			Data2: winHelloOpts.CancellationID.Data2,
			Data3: winHelloOpts.CancellationID.Data3,
			Data4: winHelloOpts.CancellationID.Data4,
		}
	}

	if winHelloOpts.U2FAppID != "" {
		opts.PwszU2fAppId = windows.StringToUTF16Ptr(winHelloOpts.U2FAppID)
		opts.PbU2fAppId = new(int32)
	}

	if winHelloOpts.CredentialHints != nil {
		credHints := make([]*uint16, len(winHelloOpts.CredentialHints))
		for i, hint := range winHelloOpts.CredentialHints {
			credHints[i] = windows.StringToUTF16Ptr(string(hint))
		}

		opts.CCredentialHints = uint32(len(credHints))
		opts.PpwszCredentialHints = unsafe.SliceData(credHints)
	}

	if winHelloOpts.RemoteWebOrigin != "" {
		opts.PwszRemoteWebOrigin = windows.StringToUTF16Ptr(winHelloOpts.RemoteWebOrigin)
	}

	if extInputs != nil {
		exts := make([]_WEBAUTHN_EXTENSION, 0)

		// credBlob
		if extInputs.GetCredentialBlobInputs != nil && extInputs.GetCredentialBlobInputs.GetCredBlob {
			ext := _WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(extension.ExtensionIdentifierCredentialBlob)),
			}

			credBlob := boolToInt32(extInputs.GetCredentialBlobInputs.GetCredBlob)
			ext.CbExtension = uint32(unsafe.Sizeof(credBlob))
			ext.PvExtension = (*byte)(unsafe.Pointer(&credBlob))
			exts = append(exts, ext)
		}

		// check that only hmac-secret or prf was supplied
		if extInputs.GetHMACSecretInputs != nil && extInputs.PRFInputs != nil {
			return nil, errors.New("you cannot use hmac-secret and prf extensions at the same time")
		}

		// hmac-secret
		if extInputs.GetHMACSecretInputs != nil && extInputs.GetHMACSecretInputs.HMACGetSecret.Salt1 != nil {
			opts.PHmacSecretSaltValues = new(_WEBAUTHN_HMAC_SECRET_SALT_VALUES)
			opts.PHmacSecretSaltValues.PGlobalHmacSalt = &_WEBAUTHN_HMAC_SECRET_SALT{
				CbFirst:  uint32(len(extInputs.GetHMACSecretInputs.HMACGetSecret.Salt1)),
				PbFirst:  unsafe.SliceData(extInputs.GetHMACSecretInputs.HMACGetSecret.Salt1),
				CbSecond: uint32(len(extInputs.GetHMACSecretInputs.HMACGetSecret.Salt2)),
				PbSecond: unsafe.SliceData(extInputs.GetHMACSecretInputs.HMACGetSecret.Salt2),
			}
			opts.DwFlags |= WinHelloAuthenticatorHMACSecretValuesFlag
		}

		// prf
		if extInputs.PRFInputs != nil {
			opts.PHmacSecretSaltValues = new(_WEBAUTHN_HMAC_SECRET_SALT_VALUES)

			if !extInputs.PRFInputs.PRF.Eval.IsZero() {
				opts.PHmacSecretSaltValues.PGlobalHmacSalt = &_WEBAUTHN_HMAC_SECRET_SALT{
					CbFirst:  uint32(len(extInputs.PRFInputs.PRF.Eval.First)),
					PbFirst:  unsafe.SliceData(extInputs.PRFInputs.PRF.Eval.First),
					CbSecond: uint32(len(extInputs.PRFInputs.PRF.Eval.Second)),
					PbSecond: unsafe.SliceData(extInputs.PRFInputs.PRF.Eval.Second),
				}
			}

			var credWithHMACSecretSaltList []_WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT
			for credIDStr, values := range extInputs.PRFInputs.PRF.EvalByCredential {
				credID, err := base64.RawURLEncoding.DecodeString(credIDStr)
				if err != nil {
					return nil, fmt.Errorf("failed to decode credential ID: %w", err)
				}

				credWithHMACSecretSaltList = append(credWithHMACSecretSaltList, _WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT{
					CbCredID: uint32(len(credID)),
					PbCredID: unsafe.SliceData(credID),
					PHmacSecretSalt: &_WEBAUTHN_HMAC_SECRET_SALT{
						CbFirst:  uint32(len(values.First)),
						PbFirst:  unsafe.SliceData(values.First),
						CbSecond: uint32(len(values.Second)),
						PbSecond: unsafe.SliceData(values.Second),
					},
				})
			}

			opts.PHmacSecretSaltValues.CCredWithHmacSecretSaltList = uint32(len(credWithHMACSecretSaltList))
			opts.PHmacSecretSaltValues.PCredWithHmacSecretSaltList = unsafe.SliceData(credWithHMACSecretSaltList)
		}

		opts.Extensions = _WEBAUTHN_EXTENSIONS{
			CExtensions: uint32(len(exts)),
			PExtensions: unsafe.SliceData(exts),
		}
	}

	return opts, nil
}

// MakeCredential creates a credential for rp and user.
// extInputs and winHelloOpts may be nil to use the default options.
func MakeCredential(
	hWnd windows.HWND,
	clientData []byte,
	rp credential.PublicKeyCredentialRpEntity,
	user credential.PublicKeyCredentialUserEntity,
	pubKeyCredParams []credential.PublicKeyCredentialParameters,
	excludeList []credential.PublicKeyCredentialDescriptor,
	extInputs *webauthn.CreateAuthenticationExtensionsClientInputs,
	winHelloOpts *AuthenticatorMakeCredentialOptions,
) (*WinHelloMakeCredentialResponse, error) {
	coseCredentialParams := make([]_WEBAUTHN_COSE_CREDENTIAL_PARAMETER, len(pubKeyCredParams))
	for i, param := range pubKeyCredParams {
		coseCredentialParams[i] = _WEBAUTHN_COSE_CREDENTIAL_PARAMETER{
			DwVersion:          currVer.coseCredentialParameter,
			PwszCredentialType: windows.StringToUTF16Ptr(string(param.Type)),
			LAlg:               int32(param.Algorithm),
		}
	}

	opts := makeCredentialOptions(excludeList, extInputs, winHelloOpts)

	var credAttestationPtr *_WEBAUTHN_CREDENTIAL_ATTESTATION

	r1, _, _ := procWebAuthNAuthenticatorMakeCredential.Call(
		uintptr(hWnd),
		uintptr(unsafe.Pointer(&_WEBAUTHN_RP_ENTITY_INFORMATION{
			DwVersion: currVer.rpEntityInformation,
			PwszId:    windows.StringToUTF16Ptr(rp.ID),
			PwszName:  windows.StringToUTF16Ptr(rp.Name),
		})),
		uintptr(unsafe.Pointer(&_WEBAUTHN_USER_ENTITY_INFORMATION{
			DwVersion:       currVer.userEntityInformation,
			CbId:            uint32(len(user.ID)),
			PbId:            unsafe.SliceData(user.ID),
			PwszName:        windows.StringToUTF16Ptr(user.Name),
			PwszDisplayName: windows.StringToUTF16Ptr(user.DisplayName),
		})),
		uintptr(unsafe.Pointer(&_WEBAUTHN_COSE_CREDENTIAL_PARAMETERS{
			CCredentialParameters: uint32(len(coseCredentialParams)),
			PCredentialParameters: unsafe.SliceData(coseCredentialParams),
		})),
		uintptr(unsafe.Pointer(&_WEBAUTHN_CLIENT_DATA{
			DwVersion:        currVer.clientData,
			CbClientDataJSON: uint32(len(clientData)),
			PbClientDataJSON: unsafe.SliceData(clientData),
			PwszHashAlgId:    windows.StringToUTF16Ptr("SHA-256"),
		})),
		uintptr(unsafe.Pointer(opts)),
		uintptr(unsafe.Pointer(&credAttestationPtr)),
	)
	if hr := windows.Errno(uint32(r1)); hr != 0 {
		return nil, hr
	}

	defer procWebAuthNFreeCredentialAttestation.Call(uintptr(unsafe.Pointer(credAttestationPtr)))

	return credAttestationPtr.ToMakeCredentialResponse(extInputs)
}

func makeCredentialOptions(
	excludeList []credential.PublicKeyCredentialDescriptor,
	extInputs *webauthn.CreateAuthenticationExtensionsClientInputs,
	winHelloOpts *AuthenticatorMakeCredentialOptions,
) *_WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
	if winHelloOpts == nil {
		winHelloOpts = &AuthenticatorMakeCredentialOptions{}
	}

	opts := &_WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS{
		DwVersion:                                currVer.authenticatorMakeCredentialOptions,
		DwTimeoutMilliseconds:                    uint32(winHelloOpts.Timeout.Milliseconds()),
		CredentialList:                           _WEBAUTHN_CREDENTIALS{}, // basically deprecated, baseline supports pExcludeCredentialList
		DwAuthenticatorAttachment:                uint32(winHelloOpts.AuthenticatorAttachment),
		BRequireResidentKey:                      boolToInt32(winHelloOpts.RequireResidentKey),
		DwUserVerificationRequirement:            uint32(winHelloOpts.UserVerificationRequirement),
		DwAttestationConveyancePreference:        uint32(winHelloOpts.AttestationConveyancePreference),
		DwFlags:                                  0, // user only in version 8 for PRF Global Eval
		DwEnterpriseAttestation:                  uint32(winHelloOpts.EnterpriseAttestation),
		DwLargeBlobSupport:                       uint32(winHelloOpts.LargeBlobSupport),
		BPreferResidentKey:                       boolToInt32(winHelloOpts.PreferResidentKey),
		BBrowserInPrivateMode:                    boolToInt32(winHelloOpts.BrowserInPrivateMode),
		CbJsonExt:                                uint32(len(winHelloOpts.JsonExt)),
		PbJsonExt:                                unsafe.SliceData(winHelloOpts.JsonExt),
		BThirdPartyPayment:                       boolToInt32(winHelloOpts.ThirdPartyPayment),
		CbPublicKeyCredentialCreationOptionsJSON: uint32(len(winHelloOpts.PublicKeyCredentialCreationOptionsJSON)),
		PbPublicKeyCredentialCreationOptionsJSON: unsafe.SliceData(winHelloOpts.PublicKeyCredentialCreationOptionsJSON),
		CbAuthenticatorId:                        uint32(len(winHelloOpts.AuthenticatorID)),
		PbAuthenticatorId:                        unsafe.SliceData(winHelloOpts.AuthenticatorID),
	}

	credExList := make([]*_WEBAUTHN_CREDENTIAL_EX, len(excludeList))
	for i, ex := range excludeList {
		credExList[i] = &_WEBAUTHN_CREDENTIAL_EX{
			DwVersion:          currVer.credentialEx,
			CbId:               uint32(len(ex.ID)),
			PbId:               unsafe.SliceData(ex.ID),
			PwszCredentialType: windows.StringToUTF16Ptr(string(ex.Type)),
			DwTransports:       transportsToFlags(ex.Transports),
		}
	}
	if len(credExList) > 0 {
		opts.PExcludeCredentialList = &_WEBAUTHN_CREDENTIAL_LIST{
			CCredentials:  uint32(len(credExList)),
			PpCredentials: unsafe.SliceData(credExList),
		}
	}

	if winHelloOpts.CancellationID != nil {
		opts.PCancellationId = &_GUID{
			Data1: winHelloOpts.CancellationID.Data1,
			Data2: winHelloOpts.CancellationID.Data2,
			Data3: winHelloOpts.CancellationID.Data3,
			Data4: winHelloOpts.CancellationID.Data4,
		}
	}

	if winHelloOpts.CredentialHints != nil {
		credHints := make([]*uint16, len(winHelloOpts.CredentialHints))
		for i, hint := range winHelloOpts.CredentialHints {
			credHints[i] = windows.StringToUTF16Ptr(string(hint))
		}

		opts.CCredentialHints = uint32(len(credHints))
		opts.PpwszCredentialHints = unsafe.SliceData(credHints)
	}

	if winHelloOpts.RemoteWebOrigin != "" {
		opts.PwszRemoteWebOrigin = windows.StringToUTF16Ptr(winHelloOpts.RemoteWebOrigin)
	}

	if extInputs != nil {
		exts := make([]_WEBAUTHN_EXTENSION, 0)

		// hmac-secret
		if extInputs.CreateHMACSecretInputs != nil && extInputs.CreateHMACSecretInputs.HMACCreateSecret {
			ext := _WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(extension.ExtensionIdentifierHMACSecret)),
			}

			hmacSecret := boolToInt32(extInputs.CreateHMACSecretInputs.HMACCreateSecret)
			ext.CbExtension = uint32(unsafe.Sizeof(hmacSecret))
			ext.PvExtension = (*byte)(unsafe.Pointer(&hmacSecret))
			exts = append(exts, ext)
		}

		// hmac-secret-mc
		if extInputs.CreateHMACSecretMCInputs != nil {
			opts.BEnablePrf = boolToInt32(true)
			opts.PPRFGlobalEval = &_WEBAUTHN_HMAC_SECRET_SALT{
				CbFirst:  uint32(len(extInputs.CreateHMACSecretMCInputs.HMACGetSecret.Salt1)),
				PbFirst:  unsafe.SliceData(extInputs.CreateHMACSecretMCInputs.HMACGetSecret.Salt1),
				CbSecond: uint32(len(extInputs.CreateHMACSecretMCInputs.HMACGetSecret.Salt2)),
				PbSecond: unsafe.SliceData(extInputs.CreateHMACSecretMCInputs.HMACGetSecret.Salt2),
			}
			opts.DwFlags |= WinHelloAuthenticatorHMACSecretValuesFlag
		}

		// prf
		if extInputs.PRFInputs != nil {
			opts.BEnablePrf = boolToInt32(true)
			if !extInputs.PRFInputs.PRF.Eval.IsZero() {
				opts.PPRFGlobalEval = &_WEBAUTHN_HMAC_SECRET_SALT{
					CbFirst:  uint32(len(extInputs.PRFInputs.PRF.Eval.First)),
					PbFirst:  unsafe.SliceData(extInputs.PRFInputs.PRF.Eval.First),
					CbSecond: uint32(len(extInputs.PRFInputs.PRF.Eval.Second)),
					PbSecond: unsafe.SliceData(extInputs.PRFInputs.PRF.Eval.Second),
				}
			}
		}

		// credProtect
		if extInputs.CreateCredentialProtectionInputs != nil {
			ext := _WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(extension.ExtensionIdentifierCredentialProtection)),
			}

			credProtectValue := WinHelloUserVerificationAny
			switch extInputs.CreateCredentialProtectionInputs.CredentialProtectionPolicy {
			case extension.CredentialProtectionPolicyUserVerificationOptional:
				credProtectValue = WinHelloUserVerificationOptional
			case extension.CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList:
				credProtectValue = WinHelloUserVerificationOptionalWithCredentialIDList
			case extension.CredentialProtectionPolicyUserVerificationRequired:
				credProtectValue = WinHelloUserVerificationRequired
			}

			credProtect := _WEBAUTHN_CRED_PROTECT_EXTENSION_IN{
				DwCredProtect:       uint32(credProtectValue),
				BRequireCredProtect: boolToInt32(extInputs.CreateCredentialProtectionInputs.EnforceCredentialProtectionPolicy),
			}

			ext.CbExtension = uint32(unsafe.Sizeof(credProtect))
			ext.PvExtension = (*byte)(unsafe.Pointer(&credProtect))
			exts = append(exts, ext)
		}

		// credBlob
		if extInputs.CreateCredentialBlobInputs != nil && extInputs.CreateCredentialBlobInputs.CredBlob != nil {
			ext := _WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(extension.ExtensionIdentifierCredentialBlob)),
			}

			credBlob := _WEBAUTHN_CRED_BLOB_EXTENSION{
				CbCredBlob: uint32(len(extInputs.CreateCredentialBlobInputs.CredBlob)),
				PbCredBlob: unsafe.SliceData(extInputs.CreateCredentialBlobInputs.CredBlob),
			}

			ext.CbExtension = uint32(unsafe.Sizeof(credBlob))
			ext.PvExtension = (*byte)(unsafe.Pointer(&credBlob))
			exts = append(exts, ext)
		}

		// minPinLength
		if extInputs.CreateMinPinLengthInputs != nil && extInputs.CreateMinPinLengthInputs.MinPinLength {
			ext := _WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(extension.ExtensionIdentifierMinPinLength)),
			}

			minPinLength := boolToInt32(extInputs.CreateMinPinLengthInputs.MinPinLength)
			ext.CbExtension = uint32(unsafe.Sizeof(minPinLength))
			ext.PvExtension = (*byte)(unsafe.Pointer(&minPinLength))
			exts = append(exts, ext)
		}

		opts.Extensions = _WEBAUTHN_EXTENSIONS{
			CExtensions: uint32(len(exts)),
			PExtensions: unsafe.SliceData(exts),
		}
	}

	return opts
}

// CancelCurrentOperation cancels the operation using an ID obtained from CancellationID.
func CancelCurrentOperation(cancellationID *windows.GUID) error {
	r1, _, _ := procWebAuthNCancelCurrentOperation.Call(
		uintptr(unsafe.Pointer(cancellationID)),
	)
	if hr := windows.Errno(uint32(r1)); hr != 0 {
		return hr
	}

	return nil
}

func DeletePlatformCredential(credentialID []byte) error {
	if err := procWebAuthNDeletePlatformCredential.Find(); err != nil {
		return err
	}
	r1, _, _ := procWebAuthNDeletePlatformCredential.Call(
		uintptr(len(credentialID)),
		uintptr(unsafe.Pointer(&credentialID[0])),
	)
	if hr := windows.Errno(uint32(r1)); hr != 0 {
		return hr
	}

	return nil
}

func APIVersionNumber() uint32 {
	r1, _, _ := procWebAuthNGetApiVersionNumber.Call()
	return uint32(r1)
}

func CancellationID() (*windows.GUID, error) {
	var cancellationIDPtr windows.GUID

	r1, _, _ := procWebAuthNGetCancellationId.Call(
		uintptr(unsafe.Pointer(&cancellationIDPtr)),
	)
	if hr := windows.Errno(uint32(r1)); hr != 0 {
		return nil, hr
	}

	return &cancellationIDPtr, nil
}

func ErrorName(hr windows.Handle) string {
	r1, _, _ := procWebAuthNGetErrorName.Call(uintptr(hr))
	// The return value points to static UTF-16 data owned by webauthn.dll.
	return windows.UTF16PtrToString(*(**uint16)(unsafe.Pointer(&r1)))
}

type WebAuthnCredentialDetails struct {
	CredentialID      []byte
	RP                credential.PublicKeyCredentialRpEntity
	User              credential.PublicKeyCredentialUserEntity
	Removable         bool
	BackedUp          bool
	AuthenticatorName string
	AuthenticatorLogo []byte
	ThirdPartyPayment bool
	Transports        []credential.AuthenticatorTransport
}

func PlatformCredentialList(rpID string, browserInPrivateMode bool) ([]*WebAuthnCredentialDetails, error) {
	if err := procWebAuthNGetPlatformCredentialList.Find(); err != nil {
		return nil, err
	}
	var rpIDPtr *uint16
	if rpID != "" {
		rpIDPtr = windows.StringToUTF16Ptr(rpID)
	}

	var credDetailsListPtr *_WEBAUTHN_CREDENTIAL_DETAILS_LIST

	r1, _, _ := procWebAuthNGetPlatformCredentialList.Call(
		uintptr(unsafe.Pointer(&_WEBAUTHN_GET_CREDENTIALS_OPTIONS{
			DwVersion:             currVer.getCredentialsOptions,
			PwszRpId:              rpIDPtr,
			BBrowserInPrivateMode: boolToInt32(browserInPrivateMode),
		})),
		uintptr(unsafe.Pointer(&credDetailsListPtr)),
	)
	if hr := windows.Errno(uint32(r1)); hr != 0 {
		return nil, hr
	}

	defer procWebAuthNFreePlatformCredentialList.Call(uintptr(unsafe.Pointer(credDetailsListPtr)))
	credListDetails := unsafe.Slice(credDetailsListPtr.PpCredentialDetails, credDetailsListPtr.CCredentialDetails)

	list := make([]*WebAuthnCredentialDetails, len(credListDetails))
	for i, cred := range credListDetails {
		credID := bytes.Clone(unsafe.Slice(cred.PbCredentialID, cred.CbCredentialID))

		list[i] = &WebAuthnCredentialDetails{
			CredentialID: credID,
			RP: credential.PublicKeyCredentialRpEntity{
				ID:   windows.UTF16PtrToString(cred.PRpInformation.PwszId),
				Name: windows.UTF16PtrToString(cred.PRpInformation.PwszName),
			},
			User: credential.PublicKeyCredentialUserEntity{
				ID:          bytes.Clone(unsafe.Slice(cred.PUserInformation.PbId, cred.PUserInformation.CbId)),
				DisplayName: windows.UTF16PtrToString(cred.PUserInformation.PwszDisplayName),
				Name:        windows.UTF16PtrToString(cred.PUserInformation.PwszName),
			},
			Removable: int32ToBool(cred.BRemovable),
		}

		if cred.DwVersion >= 2 {
			list[i].BackedUp = int32ToBool(cred.BBackedUp)
		}

		if cred.DwVersion >= 3 {
			list[i].AuthenticatorName = windows.UTF16PtrToString(cred.PwszAuthenticatorName)
			list[i].AuthenticatorLogo = bytes.Clone(unsafe.Slice(cred.PbAuthenticatorLogo, cred.CbAuthenticatorLogo))
			list[i].ThirdPartyPayment = int32ToBool(cred.BThirdPartyPayment)
		}

		if cred.DwVersion >= 4 {
			list[i].Transports = flagsToTransports(cred.DwTransports)
		}
	}

	return list, nil
}

type WebAuthnAuthenticatorDetails struct {
	ID     []byte
	Name   string
	Logo   []byte
	Locked bool
}

func AuthenticatorList() ([]*WebAuthnAuthenticatorDetails, error) {
	if err := procWebAuthNGetAuthenticatorList.Find(); err != nil {
		return nil, err
	}
	var authenticatorListPtr *_WEBAUTHN_AUTHENTICATOR_DETAILS_LIST

	r1, _, _ := procWebAuthNGetAuthenticatorList.Call(
		uintptr(unsafe.Pointer(&_WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS{
			DwVersion: currVer.authenticatorDetails,
		})),
		uintptr(unsafe.Pointer(&authenticatorListPtr)),
	)
	if hr := windows.Errno(uint32(r1)); hr != 0 {
		return nil, hr
	}

	defer procWebAuthNFreeAuthenticatorList.Call(uintptr(unsafe.Pointer(authenticatorListPtr)))
	authenticatorListDetails := unsafe.Slice(
		authenticatorListPtr.PpAuthenticatorDetails,
		authenticatorListPtr.CAuthenticatorDetails,
	)

	list := make([]*WebAuthnAuthenticatorDetails, len(authenticatorListDetails))
	for i, cred := range authenticatorListDetails {
		authenticatorID := bytes.Clone(unsafe.Slice(cred.PbAuthenticatorId, cred.CbAuthenticatorId))
		authenticatorLogo := bytes.Clone(unsafe.Slice(cred.PbAuthenticatorLogo, cred.CbAuthenticatorLogo))

		list[i] = &WebAuthnAuthenticatorDetails{
			ID:     authenticatorID,
			Name:   windows.UTF16PtrToString(cred.PwszAuthenticatorName),
			Logo:   authenticatorLogo,
			Locked: int32ToBool(cred.BLocked),
		}
	}

	return list, nil
}

// W3CExceptionDOMError maps a WebAuthn HRESULT to its W3C DOM exception code.
func W3CExceptionDOMError(hr windows.Handle) windows.Handle {
	r1, _, _ := procWebAuthNGetW3CExceptionDOMError.Call(
		uintptr(hr),
	)
	return windows.Handle(uint32(r1))
}

func IsUserVerifyingPlatformAuthenticatorAvailable() (bool, error) {
	var isAvailable int32

	r1, _, _ := procWebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.Call(
		uintptr(unsafe.Pointer(&isAvailable)),
	)
	if hr := windows.Errno(uint32(r1)); hr != 0 {
		return false, hr
	}

	return int32ToBool(isAvailable), nil
}
