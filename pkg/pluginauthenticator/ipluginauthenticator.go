//go:build windows

package pluginauthenticator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/telesma-app/winhello"
	"github.com/telesma-app/winhello/internal/utils"
	"golang.org/x/sys/windows"
)

type pluginAuthenticator struct {
	vtable *pluginAuthenticatorVtbl
	refs   comReferences
	ctx    context.Context
	clsid  string

	// Shutdown waits for callbacks before releasing the handler.
	mu      sync.Mutex
	active  sync.WaitGroup
	handler Handler
}

type pluginAuthenticatorVtbl struct {
	ole.IUnknownVtbl
	MakeCredential  uintptr
	GetAssertion    uintptr
	CancelOperation uintptr
	GetLockStatus   uintptr
}

var pluginVtbl pluginAuthenticatorVtbl

func init() {
	pluginVtbl = pluginAuthenticatorVtbl{
		IUnknownVtbl: ole.IUnknownVtbl{
			QueryInterface: windows.NewCallback(pluginQueryInterface),
			AddRef:         windows.NewCallback(pluginAddRef),
			Release:        windows.NewCallback(pluginRelease),
		},
		MakeCredential:  windows.NewCallback(pluginMakeCredential),
		GetAssertion:    windows.NewCallback(pluginGetAssertion),
		CancelOperation: windows.NewCallback(pluginCancelOperation),
		GetLockStatus:   windows.NewCallback(pluginGetLockStatus),
	}
}

func pluginQueryInterface(this *pluginAuthenticator, iid *ole.GUID, object *unsafe.Pointer) windows.Handle {
	if object == nil {
		return windows.E_POINTER
	}

	*object = nil

	if !ole.IsEqualGUID(iid, ole.IID_IUnknown) && !ole.IsEqualGUID(iid, pluginIID) {
		return windows.E_NOINTERFACE
	}

	pluginAddRef(this)
	*object = unsafe.Pointer(this)

	return windows.S_OK
}

func pluginAddRef(this *pluginAuthenticator) uintptr {
	return this.refs.add()
}

func pluginRelease(this *pluginAuthenticator) uintptr {
	return this.refs.release(unsafe.Pointer(this))
}

func pluginMakeCredential(
	this *pluginAuthenticator,
	opReq *_WEBAUTHN_PLUGIN_OPERATION_REQUEST,
	opResp *_WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
) windows.Handle {
	if opReq == nil || opResp == nil {
		return windows.E_POINTER
	}

	*opResp = _WEBAUTHN_PLUGIN_OPERATION_RESPONSE{}

	return operationResult(this.makeCredential(opReq, opResp))
}

func (p *pluginAuthenticator) makeCredential(
	opReq *_WEBAUTHN_PLUGIN_OPERATION_REQUEST,
	opResp *_WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
) (err error) {
	handler, err := p.beginOperation()
	if err != nil {
		return err
	}
	defer p.active.Done()

	op, err := p.verifiedOperation(opReq)
	if err != nil {
		return err
	}

	req, err := winhello.PluginDecodeMakeCredentialRequest(op.encoded)
	if err != nil {
		return fmt.Errorf("decode make credential request: %w", err)
	}

	result, err := handler.MakeCredential(p.ctx, op, req)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil && result.Rollback != nil {
			err = errors.Join(err, result.Rollback())
		}
	}()

	payload, err := winhello.PluginEncodeMakeCredentialResponse(result.Response)
	if err != nil {
		return fmt.Errorf("encode attestation: %w", err)
	}

	return writeOperationResponse(opResp, payload)
}

func pluginGetAssertion(
	this *pluginAuthenticator,
	opReq *_WEBAUTHN_PLUGIN_OPERATION_REQUEST,
	opResp *_WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
) windows.Handle {
	if opReq == nil || opResp == nil {
		return windows.E_POINTER
	}

	*opResp = _WEBAUTHN_PLUGIN_OPERATION_RESPONSE{}

	return operationResult(this.getAssertion(opReq, opResp))
}

func (p *pluginAuthenticator) getAssertion(
	opReq *_WEBAUTHN_PLUGIN_OPERATION_REQUEST,
	opResp *_WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
) error {
	handler, err := p.beginOperation()
	if err != nil {
		return err
	}
	defer p.active.Done()

	op, err := p.verifiedOperation(opReq)
	if err != nil {
		return err
	}

	req, err := winhello.PluginDecodeGetAssertionRequest(op.encoded)
	if err != nil {
		return fmt.Errorf("decode get assertion request: %w", err)
	}

	resp, err := handler.GetAssertion(p.ctx, op, req)
	if err != nil {
		return err
	}

	payload, err := winhello.PluginEncodeGetAssertionResponse(resp)
	if err != nil {
		return fmt.Errorf("encode assertion: %w", err)
	}

	return writeOperationResponse(opResp, payload)
}

func (p *pluginAuthenticator) beginOperation() (Handler, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ctx.Err() != nil {
		return nil, windows.Errno(windows.CO_E_OBJNOTCONNECTED)
	}

	p.active.Add(1)

	return p.handler, nil
}

func (p *pluginAuthenticator) verifiedOperation(req *_WEBAUTHN_PLUGIN_OPERATION_REQUEST) (*Operation, error) {
	if req.RequestType != pluginRequestCTAP2CBOR || req.PbEncodedRequest == nil || req.CbEncodedRequest == 0 ||
		req.PbRequestSignature == nil || req.CbRequestSignature == 0 {
		return nil, windows.Errno(windows.E_INVALIDARG)
	}

	// COM owns the request buffers until the callback returns.
	encoded := unsafe.Slice(req.PbEncodedRequest, req.CbEncodedRequest)
	signature := unsafe.Slice(req.PbRequestSignature, req.CbRequestSignature)

	key, err := winhello.PluginGetOperationSigningPublicKey(p.clsid)
	if err != nil {
		return nil, fmt.Errorf("read operation signing key: %w", err)
	}

	if err := utils.VerifyCNGSignature(key, encoded, signature); err != nil {
		return nil, fmt.Errorf("verify operation signature: %w: %w", windows.Errno(windows.E_ACCESSDENIED), err)
	}

	return &Operation{
		clsid:       p.clsid,
		window:      req.HWnd,
		transaction: req.TransactionId,
		encoded:     encoded,
	}, nil
}

func pluginCancelOperation(_ *pluginAuthenticator, _ *_WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST) windows.Handle {
	return windows.E_NOTIMPL
}

func pluginGetLockStatus(this *pluginAuthenticator, status *uint32) windows.Handle {
	if status == nil {
		return windows.E_POINTER
	}

	handler, err := this.beginOperation()
	if err != nil {
		return operationResult(err)
	}
	defer this.active.Done()

	*status = pluginUnlocked
	if handler.Locked() {
		*status = pluginLocked
	}

	return windows.S_OK
}

func operationResult(err error) windows.Handle {
	if err == nil {
		return windows.S_OK
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, windows.ERROR_CANCELLED) {
		return windows.NTE_USER_CANCELLED
	}

	var hr windows.Errno
	if errors.As(err, &hr) && uint32(hr)&0x80000000 != 0 {
		return windows.Handle(hr)
	}

	return windows.E_FAIL
}

func writeOperationResponse(opResp *_WEBAUTHN_PLUGIN_OPERATION_RESPONSE, encoded []byte) error {
	addr, _, _ := procCoTaskMemAlloc.Call(uintptr(len(encoded)))
	if addr == 0 {
		return windows.Errno(windows.E_OUTOFMEMORY)
	}

	// CoTaskMemAlloc returns a native pointer in the syscall return register.
	buf := *(**byte)(unsafe.Pointer(&addr))
	copy(unsafe.Slice(buf, len(encoded)), encoded)
	*opResp = _WEBAUTHN_PLUGIN_OPERATION_RESPONSE{
		CbEncodedResponse: uint32(len(encoded)),
		PbEncodedResponse: buf,
	}

	return nil
}
