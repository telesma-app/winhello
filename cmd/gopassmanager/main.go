//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"uuid"

	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/winhello"
	"github.com/telesma-app/winhello/internal/demoauthenticator"
	"github.com/telesma-app/winhello/pkg/pluginauthenticator"
	"golang.org/x/sys/windows"
)

const (
	pluginCLSID = "{1537ff70-8f94-495b-bad1-bcff96311d5f}"
	pluginName  = "WinHello Passkey Demo"
	usage       = "usage: plugin.exe [register|unregister|status]"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return serve()
	}

	if len(args) != 1 {
		return errors.New(usage)
	}

	switch args[0] {
	case "-Embedding", "/Embedding":
		return serve()
	case "register":
		return register()
	case "unregister":
		return winhello.PluginRemoveAuthenticator(pluginCLSID)
	case "status":
		state, err := winhello.PluginGetAuthenticatorState(pluginCLSID)
		if err != nil {
			return err
		}

		if state == winhello.PluginAuthenticatorStateEnabled {
			fmt.Println("enabled")
		} else {
			fmt.Println("disabled")
		}

		return nil
	default:
		return errors.New(usage)
	}
}

func register() error {
	_, err := winhello.PluginAddAuthenticator(&winhello.PluginAddAuthenticatorOptions{
		AuthenticatorName: pluginName,
		CLSID:             pluginCLSID,
		PluginRPID:        "winhello.example",
		AuthenticatorInfo: &protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_1, protocol.FIDO_2_0},
			AAGUID:   uuid.MustParse(demoauthenticator.AAGUID),
			Options: map[protocol.Option]bool{
				protocol.OptionResidentKeys:     true,
				protocol.OptionUserPresence:     true,
				protocol.OptionUserVerification: true,
				protocol.OptionAlwaysUv:         true,
			},
			Transports: []credential.AuthenticatorTransport{credential.AuthenticatorTransportInternal},
			Algorithms: []credential.PublicKeyCredentialParameters{
				{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmES256},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("register passkey provider: %w", err)
	}

	return nil
}

func serve() error {
	clsid, err := windows.GUIDFromString(pluginCLSID)
	if err != nil {
		return fmt.Errorf("parse plugin CLSID: %w", err)
	}

	localAppData, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil {
		return fmt.Errorf("locate local app data: %w", err)
	}

	directory := filepath.Join(localAppData, "WinHelloDemo")
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}

	logFile, err := os.OpenFile(filepath.Join(directory, "provider.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer logFile.Close() //nolint:errcheck // Diagnostic log.

	provider := &demoProvider{
		backend: demoauthenticator.New(filepath.Join(directory, "credential.dat")),
		logger:  log.New(logFile, "", log.LstdFlags),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	provider.logger.Printf("Starting COM server (PID %d)", os.Getpid())

	if err := pluginauthenticator.Serve(ctx, clsid, provider); err != nil {
		provider.logger.Printf("COM server failed: %v", err)
		return err
	}

	return nil
}

type demoProvider struct {
	backend *demoauthenticator.Authenticator
	logger  *log.Logger
}

func (p *demoProvider) MakeCredential(
	ctx context.Context, op *pluginauthenticator.Operation, req *winhello.MakeCredentialRequest,
) (result pluginauthenticator.MakeCredentialResult, err error) {
	p.logger.Print("MakeCredential started")
	defer func() { p.logOperation("MakeCredential handler", err) }()

	if err := p.verifyUser(ctx, op); err != nil {
		return result, err
	}

	resp, err := p.backend.MakeCredential(req.AuthenticatorMakeCredentialRequest)
	if err != nil {
		return result, backendError(err)
	}

	id := resp.AuthData.AttestedCredentialData.CredentialID
	if err := ctx.Err(); err != nil {
		return result, errors.Join(err, p.backend.RemoveCredential(id))
	}

	metadata := []*winhello.PluginCredentialDetail{{
		CredentialID:    id,
		RPID:            req.RP.ID,
		RPName:          req.RP.Name,
		UserID:          req.User.ID,
		UserName:        req.User.Name,
		UserDisplayName: req.User.DisplayName,
	}}
	// Windows uses this metadata to offer the saved discoverable credential.
	if err := winhello.PluginAuthenticatorAddCredentials(pluginCLSID, metadata); err != nil {
		return result, errors.Join(fmt.Errorf("publish credential metadata: %w", err), p.backend.RemoveCredential(id))
	}

	return pluginauthenticator.MakeCredentialResult{
		Response: &winhello.WinHelloMakeCredentialResponse{
			AuthenticatorMakeCredentialResponse: resp,
			CredentialID:                        id,
		},
		Rollback: func() error {
			err := errors.Join(winhello.PluginAuthenticatorRemoveCredentials(pluginCLSID, metadata), p.backend.RemoveCredential(id))
			p.logOperation("MakeCredential rollback", err)

			return err
		},
	}, nil
}

func (p *demoProvider) GetAssertion(
	ctx context.Context, op *pluginauthenticator.Operation, req *winhello.CTAPCBORGetAssertionRequest,
) (_ *winhello.CTAPCBORGetAssertionResponse, err error) {
	p.logger.Print("GetAssertion started")
	defer func() { p.logOperation("GetAssertion handler", err) }()

	if err := p.verifyUser(ctx, op); err != nil {
		return nil, err
	}

	resp, err := p.backend.GetAssertion(req.AuthenticatorGetAssertionRequest)
	if err != nil {
		return nil, backendError(err)
	}

	return &winhello.CTAPCBORGetAssertionResponse{
		WinHelloGetAssertionResponse: &winhello.WinHelloGetAssertionResponse{
			AuthenticatorGetAssertionResponse: resp,
		},
		UserInformation:     resp.User,
		NumberOfCredentials: 1,
		UserSelected:        1,
	}, nil
}

func (p *demoProvider) verifyUser(ctx context.Context, op *pluginauthenticator.Operation) error {
	p.logger.Print("Requesting Windows Hello verification")

	if err := op.VerifyUser("", pluginName); err != nil {
		return err
	}

	return ctx.Err()
}

func (p *demoProvider) Locked() bool {
	return false
}

func (p *demoProvider) logOperation(operation string, err error) {
	if err != nil {
		p.logger.Printf("%s failed: %v", operation, err)
		return
	}

	p.logger.Printf("%s completed", operation)
}

func backendError(err error) error {
	var hr windows.Handle

	switch {
	case errors.Is(err, demoauthenticator.ErrInvalidRequest):
		hr = windows.E_INVALIDARG
	case errors.Is(err, demoauthenticator.ErrNoCredentials):
		hr = windows.NTE_NOT_FOUND
	case errors.Is(err, demoauthenticator.ErrCredentialExcluded):
		hr = windows.NTE_EXISTS
	case errors.Is(err, demoauthenticator.ErrUnsupportedAlgorithm), errors.Is(err, demoauthenticator.ErrUnsupportedOption):
		hr = windows.NTE_NOT_SUPPORTED
	default:
		return err
	}

	return fmt.Errorf("%w: %w", windows.Errno(hr), err)
}
