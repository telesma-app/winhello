package winhello

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/webauthn"
)

// Match ctap's client input validation. Device capabilities, PIN/UV, PRF
// hashing and large-blob storage are handled by Windows, not by this adapter.
func validateMakeCredentialExtensions(inputs *webauthn.CreateAuthenticationExtensionsClientInputs, opts *AuthenticatorMakeCredentialOptions) error {
	if inputs == nil {
		return nil
	}

	if inputs.PreviewSignInputs != nil {
		return fmt.Errorf("previewSign has no Windows WebAuthn API 9 binding: %w", errors.ErrUnsupported)
	}

	if inputs.CreatePinComplexityPolicyInputs != nil && inputs.PinComplexityPolicy {
		return fmt.Errorf("pinComplexityPolicy has no Windows WebAuthn API 9 binding: %w", errors.ErrUnsupported)
	}

	if inputs.CreateHMACSecretMCInputs != nil {
		if inputs.PRFInputs != nil {
			return errors.New("hmac-secret-mc and prf cannot be requested together")
		}

		if err := validateHMACSalts(inputs.HMACGetSecret); err != nil {
			return err
		}
	}

	if inputs.PRFInputs != nil {
		if inputs.PRF.EvalByCredential != nil {
			return errors.New("prf.evalByCredential is only valid for GetAssertion")
		}

		if err := validatePRFValues(inputs.PRF.Eval, false); err != nil {
			return err
		}
	}

	if inputs.CreateCredentialProtectionInputs != nil {
		switch inputs.CredentialProtectionPolicy {
		case extension.CredentialProtectionPolicyUserVerificationOptional,
			extension.CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList,
			extension.CredentialProtectionPolicyUserVerificationRequired:
		default:
			return errors.New("invalid credentialProtectionPolicy")
		}
	}

	if inputs.LargeBlobInputs != nil {
		blob := inputs.LargeBlob
		if blob.Read != nil || blob.Write != nil {
			return errors.New("largeBlob.read and largeBlob.write are only valid for GetAssertion")
		}

		switch blob.Support {
		case "", extension.LargeBlobSupportPreferred, extension.LargeBlobSupportRequired:
		default:
			return errors.New("largeBlob.support must be preferred or required")
		}

		if opts != nil && opts.LargeBlobSupport != WinHelloLargeBlobSupportNone {
			return errors.New("largeBlob extension conflicts with Windows LargeBlobSupport option")
		}

		if blob.Support == extension.LargeBlobSupportRequired && (opts == nil || !opts.RequireResidentKey) {
			return fmt.Errorf("required largeBlob support needs RequireResidentKey on Windows: %w", errors.ErrUnsupported)
		}
	}

	return nil
}

func validateGetAssertionExtensions(inputs *webauthn.GetAuthenticationExtensionsClientInputs, allowList []credential.PublicKeyCredentialDescriptor, opts *AuthenticatorGetAssertionOptions) error {
	if inputs == nil {
		return nil
	}

	if inputs.PreviewSignInputs != nil {
		return fmt.Errorf("previewSign has no Windows WebAuthn API 9 binding: %w", errors.ErrUnsupported)
	}

	if inputs.PaymentInputs != nil && inputs.Payment.IsPayment {
		return fmt.Errorf("payment for GetAssertion has no Windows WebAuthn API 9 binding: %w", errors.ErrUnsupported)
	}

	if inputs.GetHMACSecretInputs != nil {
		if inputs.PRFInputs != nil {
			return errors.New("hmac-secret and prf cannot be requested together")
		}

		if err := validateHMACSalts(inputs.HMACGetSecret); err != nil {
			return err
		}
	}

	if inputs.PRFInputs != nil {
		if err := validatePRFValues(inputs.PRF.Eval, false); err != nil {
			return err
		}

		if len(inputs.PRF.EvalByCredential) > 0 && len(allowList) == 0 {
			return errors.New("prf.evalByCredential requires a non-empty allowList")
		}

		allowed := make(map[string]bool, len(allowList))
		for _, cred := range allowList {
			allowed[base64.RawURLEncoding.EncodeToString(cred.ID)] = true
		}

		for encodedID, values := range inputs.PRF.EvalByCredential {
			id, err := base64.RawURLEncoding.Strict().DecodeString(encodedID)
			if err != nil || encodedID == "" || base64.RawURLEncoding.EncodeToString(id) != encodedID {
				return errors.New("prf.evalByCredential requires canonical base64url credential IDs")
			}

			if !allowed[encodedID] {
				return errors.New("prf.evalByCredential credential ID is not present in allowList")
			}

			if err := validatePRFValues(values, true); err != nil {
				return err
			}
		}
	}

	if inputs.LargeBlobInputs != nil {
		blob := inputs.LargeBlob
		if blob.Support != "" {
			return errors.New("largeBlob.support is only valid for MakeCredential")
		}

		if blob.Read != nil && blob.Write != nil {
			return errors.New("largeBlob.read and largeBlob.write cannot be requested together")
		}

		if blob.Write != nil && len(allowList) != 1 {
			return errors.New("largeBlob.write requires exactly one allowed credential")
		}

		if opts != nil && (opts.CredentialLargeBlobOperation != WinHelloCredentialLargeBlobOperationNone || opts.CredentialLargeBlob != nil) {
			return errors.New("largeBlob extension conflicts with Windows CredentialLargeBlob options")
		}
	}

	return nil
}

func validatePRFValues(values webauthn.AuthenticationExtensionsPRFValues, required bool) error {
	// An empty but present input is valid; only nil means the member is absent.
	if values.First == nil && (required || values.Second != nil) {
		return errors.New("prf.first is required when an evaluation is supplied")
	}

	return nil
}

func validateHMACSalts(values webauthn.HMACGetSecretInput) error {
	if len(values.Salt1) != 32 {
		return errors.New("hmac-secret salt1 must be exactly 32 bytes")
	}

	if values.Salt2 != nil && len(values.Salt2) != 32 {
		return errors.New("hmac-secret salt2 must be exactly 32 bytes when present")
	}

	return nil
}
