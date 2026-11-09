//go:build windows

// Package pluginauthenticator runs a Windows WebAuthn plugin COM server.
package pluginauthenticator

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/telesma-app/winhello"
	"golang.org/x/sys/windows"
)

var (
	modOle32 = windows.NewLazySystemDLL("ole32.dll")

	procCoRegisterClassObject = modOle32.NewProc("CoRegisterClassObject")
	procCoRevokeClassObject   = modOle32.NewProc("CoRevokeClassObject")
	procCoResumeClassObjects  = modOle32.NewProc("CoResumeClassObjects")
	procCoTaskMemAlloc        = modOle32.NewProc("CoTaskMemAlloc")
)

const (
	regclsMultipleUse = 1
	regclsSuspended   = 4
)

// Handler implements the provider's credential operations and reports its lock
// state. Methods can be called concurrently. A returned HRESULT as windows.Errno
// is sent back to Windows. Other errors map to a generic failure.
type Handler interface {
	MakeCredential(ctx context.Context, op *Operation, req *winhello.MakeCredentialRequest) (MakeCredentialResult, error)
	GetAssertion(ctx context.Context, op *Operation, req *winhello.CTAPCBORGetAssertionRequest) (*winhello.CTAPCBORGetAssertionResponse, error)
	Locked() bool
}

// MakeCredentialResult contains the response and optional cleanup for a
// credential created by the handler. Rollback is called synchronously if the
// server cannot encode or allocate the native response. It does not cover
// failures after the response is returned to COM.
type MakeCredentialResult struct {
	Response *winhello.WinHelloMakeCredentialResponse
	Rollback func() error
}

// Serve exposes handler as a local COM server for the supplied CLSID. The
// executable's manifest and its passkey provider registration are managed by
// the application. Serve blocks until ctx is canceled, then revokes the class
// and waits for active handler calls. Handler contexts inherit this cancellation.
// Windows-originated cancellation is currently unsupported.
func Serve(ctx context.Context, clsid windows.GUID, handler Handler) (err error) {
	if ctx.Err() != nil {
		return nil
	}

	runtime.LockOSThread()

	defer runtime.UnlockOSThread()

	if err := windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED); err != nil && !errors.Is(err, windows.Errno(windows.S_FALSE)) {
		return fmt.Errorf("initialize COM: %w", err)
	}

	defer windows.CoUninitialize()

	serverCtx, cancel := context.WithCancel(ctx)
	authenticator := &pluginAuthenticator{
		vtable:  &pluginVtbl,
		ctx:     serverCtx,
		clsid:   clsid.String(),
		handler: handler,
	}
	authenticator.refs.init(unsafe.Pointer(authenticator))

	factory := &pluginClassFactory{vtable: &factoryVtbl, authenticator: authenticator}

	factory.refs.init(unsafe.Pointer(factory))
	defer classFactoryRelease(factory)
	defer func() {
		cancel()
		authenticator.mu.Lock()
		authenticator.handler = nil
		authenticator.mu.Unlock()
		authenticator.active.Wait()
	}()

	var cookie uint32

	hr, _, _ := procCoRegisterClassObject.Call(
		uintptr(unsafe.Pointer(&clsid)),
		uintptr(unsafe.Pointer(factory)),
		windows.CLSCTX_LOCAL_SERVER,
		regclsMultipleUse|regclsSuspended,
		uintptr(unsafe.Pointer(&cookie)),
	)
	if code := windows.Errno(uint32(hr)); code != 0 {
		return fmt.Errorf("register COM class: %w", code)
	}
	defer func() {
		hr, _, _ := procCoRevokeClassObject.Call(uintptr(cookie))
		if code := windows.Errno(uint32(hr)); code != 0 {
			err = errors.Join(err, fmt.Errorf("revoke COM class: %w", code))
		}
	}()

	hr, _, _ = procCoResumeClassObjects.Call()
	if code := windows.Errno(uint32(hr)); code != 0 {
		return fmt.Errorf("resume COM class objects: %w", code)
	}

	<-ctx.Done()

	return nil
}

// COM may hold references after Serve returns. Each object stays rooted and
// pinned while either Serve or a COM client owns a reference.
var liveObjects sync.Map

type comReferences struct {
	count atomic.Uint32
	pin   runtime.Pinner
}

func (r *comReferences) init(object unsafe.Pointer) {
	r.count.Store(1)
	r.pin.Pin(object)
	liveObjects.Store(object, struct{}{})
}

func (r *comReferences) add() uintptr {
	return uintptr(r.count.Add(1))
}

func (r *comReferences) release(object unsafe.Pointer) uintptr {
	count := r.count.Add(^uint32(0))
	if count == 0 {
		r.pin.Unpin()
		liveObjects.Delete(object)
	}

	return uintptr(count)
}
