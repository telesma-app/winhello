//go:build windows

package pluginauthenticator

import (
	"fmt"

	"github.com/telesma-app/winhello"
	"github.com/telesma-app/winhello/internal/utils"
	"golang.org/x/sys/windows"
)

// Operation holds the Windows transaction for a verified request. It is valid
// for synchronous use during the Handler method that received it.
type Operation struct {
	clsid       string
	window      windows.HWND
	transaction windows.GUID
	encoded     []byte
}

// VerifyUser prompts with Windows Hello and verifies that the resulting
// signature belongs to this operation.
func (op *Operation) VerifyUser(username, displayHint string) error {
	signature, err := winhello.PluginPerformUserVerification(&winhello.PluginUserVerificationRequestOptions{
		WindowHandle:  op.window,
		TransactionID: op.transaction.String(),
		Username:      username,
		DisplayHint:   displayHint,
	})
	if err != nil {
		return fmt.Errorf("verify user with Windows Hello: %w", err)
	}

	key, err := winhello.PluginGetUserVerificationPublicKey(op.clsid)
	if err != nil {
		return fmt.Errorf("read user verification key: %w", err)
	}

	if err := utils.VerifyCNGSignature(key, op.encoded, signature); err != nil {
		return fmt.Errorf("verify Windows Hello signature: %w: %w", windows.Errno(windows.E_ACCESSDENIED), err)
	}

	return nil
}
