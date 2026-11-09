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

// Resolve every required entry point before starting an operation, including
// its cleanup function so a missing export cannot leak native allocations.
func requireWebAuthn(procs ...*windows.LazyProc) error {
	if err := procWebAuthNGetApiVersionNumber.Find(); err != nil {
		return fmt.Errorf("cannot use Windows WebAuthn API: %w: %w", errors.ErrUnsupported, err)
	}

	if APIVersionNumber() == 0 {
		return fmt.Errorf("cannot use Windows WebAuthn API: %w", errors.ErrUnsupported)
	}

	for _, proc := range procs {
		if err := proc.Find(); err != nil {
			return fmt.Errorf("%s is unavailable: %w: %w", proc.Name, errors.ErrUnsupported, err)
		}
	}

	return nil
}

// GetAssertion authenticates with a credential for rpID.
// extInputs and winHelloOpts may be nil to use the default options.
// Unavailable APIs and unsupported client extensions return an error wrapping errors.ErrUnsupported.
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

	if err := requireWebAuthn(procWebAuthNAuthenticatorGetAssertion, procWebAuthNFreeAssertion); err != nil {
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

	defer procWebAuthNFreeAssertion.Call(uintptr(unsafe.Pointer(assertionPtr))) //nolint:errcheck // Native function returns void; GetLastError is not meaningful.

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
	if err := validateGetAssertionExtensions(extInputs, allowList, winHelloOpts); err != nil {
		return nil, err
	}

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

	opts.PCancellationId = (*_GUID)(winHelloOpts.CancellationID)

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

		if extInputs.LargeBlobInputs != nil {
			blob := extInputs.LargeBlob
			if blob.Read != nil && *blob.Read {
				opts.DwCredLargeBlobOperation = uint32(WinHelloCredentialLargeBlobOperationGet)
			} else if blob.Write != nil {
				opts.DwCredLargeBlobOperation = uint32(WinHelloCredentialLargeBlobOperationSet)
				opts.CbCredLargeBlob = uint32(len(blob.Write))
				opts.PbCredLargeBlob = unsafe.SliceData(blob.Write)
			}
		}

		// credBlob
		if extInputs.GetCredentialBlobInputs != nil && extInputs.GetCredBlob {
			ext := _WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(extension.ExtensionIdentifierCredentialBlob)),
			}

			credBlob := boolToInt32(extInputs.GetCredBlob)
			ext.CbExtension = uint32(unsafe.Sizeof(credBlob))
			ext.PvExtension = (*byte)(unsafe.Pointer(&credBlob))
			exts = append(exts, ext)
		}

		// hmac-secret
		if extInputs.GetHMACSecretInputs != nil && extInputs.HMACGetSecret.Salt1 != nil {
			opts.PHmacSecretSaltValues = new(_WEBAUTHN_HMAC_SECRET_SALT_VALUES)
			opts.PHmacSecretSaltValues.PGlobalHmacSalt = &_WEBAUTHN_HMAC_SECRET_SALT{
				CbFirst:  uint32(len(extInputs.HMACGetSecret.Salt1)),
				PbFirst:  unsafe.SliceData(extInputs.HMACGetSecret.Salt1),
				CbSecond: uint32(len(extInputs.HMACGetSecret.Salt2)),
				PbSecond: unsafe.SliceData(extInputs.HMACGetSecret.Salt2),
			}
			opts.DwFlags |= WinHelloAuthenticatorHMACSecretValuesFlag
		}

		// prf
		if extInputs.PRFInputs != nil {
			opts.PHmacSecretSaltValues = new(_WEBAUTHN_HMAC_SECRET_SALT_VALUES)

			if !extInputs.PRF.Eval.IsZero() {
				opts.PHmacSecretSaltValues.PGlobalHmacSalt = &_WEBAUTHN_HMAC_SECRET_SALT{
					CbFirst:  uint32(len(extInputs.PRF.Eval.First)),
					PbFirst:  unsafe.SliceData(extInputs.PRF.Eval.First),
					CbSecond: uint32(len(extInputs.PRF.Eval.Second)),
					PbSecond: unsafe.SliceData(extInputs.PRF.Eval.Second),
				}
			}

			var credWithHMACSecretSaltList []_WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT

			for credIDStr, values := range extInputs.PRF.EvalByCredential {
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
// Unavailable APIs and unsupported client extensions return an error wrapping errors.ErrUnsupported.
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
	if err := validateMakeCredentialExtensions(extInputs, winHelloOpts); err != nil {
		return nil, err
	}

	if err := requireWebAuthn(procWebAuthNAuthenticatorMakeCredential, procWebAuthNFreeCredentialAttestation); err != nil {
		return nil, err
	}

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

	defer procWebAuthNFreeCredentialAttestation.Call(uintptr(unsafe.Pointer(credAttestationPtr))) //nolint:errcheck // Native function returns void; GetLastError is not meaningful.

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

	opts.PCancellationId = (*_GUID)(winHelloOpts.CancellationID)

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

		// Windows rejects dwLargeBlobSupport=preferred/required unless bRequireResidentKey is TRUE.
		// https://learn.microsoft.com/en-us/windows/win32/api/webauthn/ns-webauthn-webauthn_authenticator_make_credential_options#members
		if extInputs.LargeBlobInputs != nil && winHelloOpts.RequireResidentKey {
			opts.DwLargeBlobSupport = uint32(WinHelloLargeBlobSupportPreferred)
			if extInputs.LargeBlob.Support == extension.LargeBlobSupportRequired {
				opts.DwLargeBlobSupport = uint32(WinHelloLargeBlobSupportRequired)
			}
		}

		if extInputs.PaymentInputs != nil && extInputs.Payment.IsPayment {
			opts.BThirdPartyPayment = boolToInt32(true)
		}

		// hmac-secret
		if extInputs.CreateHMACSecretInputs != nil && extInputs.HMACCreateSecret {
			ext := _WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(extension.ExtensionIdentifierHMACSecret)),
			}

			hmacSecret := boolToInt32(extInputs.HMACCreateSecret)
			ext.CbExtension = uint32(unsafe.Sizeof(hmacSecret))
			ext.PvExtension = (*byte)(unsafe.Pointer(&hmacSecret))
			exts = append(exts, ext)
		}

		// hmac-secret-mc
		if extInputs.CreateHMACSecretMCInputs != nil {
			opts.BEnablePrf = boolToInt32(true)
			opts.PPRFGlobalEval = &_WEBAUTHN_HMAC_SECRET_SALT{
				CbFirst:  uint32(len(extInputs.HMACGetSecret.Salt1)),
				PbFirst:  unsafe.SliceData(extInputs.HMACGetSecret.Salt1),
				CbSecond: uint32(len(extInputs.HMACGetSecret.Salt2)),
				PbSecond: unsafe.SliceData(extInputs.HMACGetSecret.Salt2),
			}
			opts.DwFlags |= WinHelloAuthenticatorHMACSecretValuesFlag
		}

		// prf
		if extInputs.PRFInputs != nil {
			opts.BEnablePrf = boolToInt32(true)
			if !extInputs.PRF.Eval.IsZero() {
				opts.PPRFGlobalEval = &_WEBAUTHN_HMAC_SECRET_SALT{
					CbFirst:  uint32(len(extInputs.PRF.Eval.First)),
					PbFirst:  unsafe.SliceData(extInputs.PRF.Eval.First),
					CbSecond: uint32(len(extInputs.PRF.Eval.Second)),
					PbSecond: unsafe.SliceData(extInputs.PRF.Eval.Second),
				}
			}
		}

		// credProtect
		if extInputs.CreateCredentialProtectionInputs != nil {
			ext := _WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(extension.ExtensionIdentifierCredentialProtection)),
			}

			credProtectValue := WinHelloUserVerificationAny

			switch extInputs.CredentialProtectionPolicy {
			case extension.CredentialProtectionPolicyUserVerificationOptional:
				credProtectValue = WinHelloUserVerificationOptional
			case extension.CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList:
				credProtectValue = WinHelloUserVerificationOptionalWithCredentialIDList
			case extension.CredentialProtectionPolicyUserVerificationRequired:
				credProtectValue = WinHelloUserVerificationRequired
			}

			credProtect := _WEBAUTHN_CRED_PROTECT_EXTENSION_IN{
				DwCredProtect:       uint32(credProtectValue),
				BRequireCredProtect: boolToInt32(extInputs.EnforceCredentialProtectionPolicy),
			}

			ext.CbExtension = uint32(unsafe.Sizeof(credProtect))
			ext.PvExtension = (*byte)(unsafe.Pointer(&credProtect))
			exts = append(exts, ext)
		}

		// credBlob
		if extInputs.CreateCredentialBlobInputs != nil && extInputs.CredBlob != nil {
			ext := _WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(extension.ExtensionIdentifierCredentialBlob)),
			}

			credBlob := _WEBAUTHN_CRED_BLOB_EXTENSION{
				CbCredBlob: uint32(len(extInputs.CredBlob)),
				PbCredBlob: unsafe.SliceData(extInputs.CredBlob),
			}

			ext.CbExtension = uint32(unsafe.Sizeof(credBlob))
			ext.PvExtension = (*byte)(unsafe.Pointer(&credBlob))
			exts = append(exts, ext)
		}

		// minPinLength
		if extInputs.CreateMinPinLengthInputs != nil && extInputs.MinPinLength {
			ext := _WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(extension.ExtensionIdentifierMinPinLength)),
			}

			minPinLength := boolToInt32(extInputs.MinPinLength)
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
// It returns an error wrapping errors.ErrUnsupported if the API is unavailable.
func CancelCurrentOperation(cancellationID *windows.GUID) error {
	if err := requireWebAuthn(procWebAuthNCancelCurrentOperation); err != nil {
		return err
	}

	r1, _, _ := procWebAuthNCancelCurrentOperation.Call(
		uintptr(unsafe.Pointer(cancellationID)),
	)
	if hr := windows.Errno(uint32(r1)); hr != 0 {
		return hr
	}

	return nil
}

// DeletePlatformCredential deletes the platform credential with the given ID.
// It returns an error wrapping errors.ErrUnsupported if the API is unavailable.
func DeletePlatformCredential(credentialID []byte) error {
	if err := requireWebAuthn(procWebAuthNDeletePlatformCredential); err != nil {
		return err
	}

	r1, _, _ := procWebAuthNDeletePlatformCredential.Call(
		uintptr(len(credentialID)),
		uintptr(unsafe.Pointer(unsafe.SliceData(credentialID))),
	)
	if hr := windows.Errno(uint32(r1)); hr != 0 {
		return hr
	}

	return nil
}

// APIVersionNumber returns the Windows WebAuthn API version, or 0 if unavailable.
func APIVersionNumber() uint32 {
	if err := procWebAuthNGetApiVersionNumber.Find(); err != nil {
		return 0
	}

	r1, _, _ := procWebAuthNGetApiVersionNumber.Call()

	return uint32(r1)
}

// CancellationID obtains an ID for cancelling a WebAuthn operation.
// It returns an error wrapping errors.ErrUnsupported if the API is unavailable.
func CancellationID() (*windows.GUID, error) {
	if err := requireWebAuthn(procWebAuthNGetCancellationId); err != nil {
		return nil, err
	}

	var cancellationIDPtr windows.GUID

	r1, _, _ := procWebAuthNGetCancellationId.Call(
		uintptr(unsafe.Pointer(&cancellationIDPtr)),
	)
	if hr := windows.Errno(uint32(r1)); hr != 0 {
		return nil, hr
	}

	return &cancellationIDPtr, nil
}

// ErrorName returns the WebAuthn error name, or the hexadecimal HRESULT if the API is unavailable.
func ErrorName(hr windows.Handle) string {
	if err := requireWebAuthn(procWebAuthNGetErrorName); err != nil {
		return fmt.Sprintf("HRESULT 0x%08X", uint32(hr))
	}

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

// PlatformCredentialList lists platform credentials, optionally filtered by RP ID.
// It returns an error wrapping errors.ErrUnsupported if the API is unavailable.
func PlatformCredentialList(rpID string, browserInPrivateMode bool) ([]*WebAuthnCredentialDetails, error) {
	if err := requireWebAuthn(procWebAuthNGetPlatformCredentialList, procWebAuthNFreePlatformCredentialList); err != nil {
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

	defer procWebAuthNFreePlatformCredentialList.Call(uintptr(unsafe.Pointer(credDetailsListPtr))) //nolint:errcheck // Native function returns void; GetLastError is not meaningful.

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

// AuthenticatorList lists the available authenticators.
// It returns an error wrapping errors.ErrUnsupported if the API is unavailable.
func AuthenticatorList() ([]*WebAuthnAuthenticatorDetails, error) {
	if err := requireWebAuthn(procWebAuthNGetAuthenticatorList, procWebAuthNFreeAuthenticatorList); err != nil {
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

	defer procWebAuthNFreeAuthenticatorList.Call(uintptr(unsafe.Pointer(authenticatorListPtr))) //nolint:errcheck // Native function returns void; GetLastError is not meaningful.

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
// It returns hr unchanged if the API is unavailable.
func W3CExceptionDOMError(hr windows.Handle) windows.Handle {
	if err := requireWebAuthn(procWebAuthNGetW3CExceptionDOMError); err != nil {
		return hr
	}

	r1, _, _ := procWebAuthNGetW3CExceptionDOMError.Call(
		uintptr(hr),
	)

	return windows.Handle(uint32(r1))
}

// IsUserVerifyingPlatformAuthenticatorAvailable reports whether Windows Hello is available.
// It returns an error wrapping errors.ErrUnsupported if the API is unavailable.
func IsUserVerifyingPlatformAuthenticatorAvailable() (bool, error) {
	if err := requireWebAuthn(procWebAuthNIsUserVerifyingPlatformAuthenticatorAvailable); err != nil {
		return false, err
	}

	var isAvailable int32

	r1, _, _ := procWebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.Call(
		uintptr(unsafe.Pointer(&isAvailable)),
	)
	if hr := windows.Errno(uint32(r1)); hr != 0 {
		return false, hr
	}

	return int32ToBool(isAvailable), nil
}
