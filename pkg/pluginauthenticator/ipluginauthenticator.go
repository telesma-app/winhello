//go:build windows

package main

import (
	"bytes"
	"log"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/goforj/godump"
	"github.com/telesma-app/winhello"
	"golang.org/x/sys/windows"
)

var (
	IID_IClassFactory         = ole.NewGUID("{00000001-0000-0000-C000-000000000046}")
	IID_IPluginAuthenticator  = ole.NewGUID("{d26bcf6f-b54c-43ff-9f06-d5bf148625f7}")
	CLSID_PluginAuthenticator = ole.NewGUID("{1537ff70-8f94-495b-bad1-bcff96311d5f}")
)

type PluginAuthenticator struct {
	lpVtbl    *IPluginAuthenticatorVtbl
	refCount  int32
	callbacks *PluginCallbacks
}

type IPluginAuthenticatorVtbl struct {
	ole.IUnknownVtbl
	MakeCredential  uintptr
	GetAssertion    uintptr
	CancelOperation uintptr
	GetLockStatus   uintptr
}

var pluginVtbl IPluginAuthenticatorVtbl

func init() {
	pluginVtbl = IPluginAuthenticatorVtbl{
		IUnknownVtbl: ole.IUnknownVtbl{
			QueryInterface: syscall.NewCallback(pluginQueryInterface),
			AddRef:         syscall.NewCallback(pluginAddRef),
			Release:        syscall.NewCallback(pluginRelease),
		},
		MakeCredential:  syscall.NewCallback(pluginMakeCredential),
		GetAssertion:    syscall.NewCallback(pluginGetAssertion),
		CancelOperation: syscall.NewCallback(pluginCancelOperation),
		GetLockStatus:   syscall.NewCallback(pluginGetLockStatus),
	}
}

type PluginCallbacks struct {
	OnMakeCredential  func(req *PluginOperationRequest) (*winhello.WinHelloMakeCredentialResponse, error)
	OnGetAssertion    func(req *PluginOperationRequest) (*winhello.CTAPCBORGetAssertionResponse, error)
	OnCancelOperation func(req *PluginCancelOperationRequest) error
	OnGetLockStatus   func() (PluginLockStatus, error)
}

func NewPluginAuthenticator(callbacks *PluginCallbacks) *PluginAuthenticator {
	p := &PluginAuthenticator{
		lpVtbl:    &pluginVtbl,
		refCount:  1,
		callbacks: callbacks,
	}
	atomic.AddInt32(&g_objCount, 1)
	return p
}

func pluginQueryInterface(this unsafe.Pointer, iid *ole.GUID, pUnk *unsafe.Pointer) windows.Handle {
	if pUnk == nil {
		return windows.E_POINTER
	}
	*pUnk = nil

	if ole.IsEqualGUID(iid, ole.IID_IUnknown) ||
		ole.IsEqualGUID(iid, IID_IPluginAuthenticator) {
		pluginAddRef(this)
		*pUnk = this
		return windows.S_OK
	}

	return windows.E_NOINTERFACE
}

func pluginAddRef(this unsafe.Pointer) uintptr {
	pThis := (*PluginAuthenticator)(this)
	newCount := atomic.AddInt32(&pThis.refCount, 1)
	return uintptr(newCount)
}

func pluginRelease(this unsafe.Pointer) uintptr {
	pThis := (*PluginAuthenticator)(this)
	newCount := atomic.AddInt32(&pThis.refCount, -1)
	if newCount == 0 {
		atomic.AddInt32(&g_objCount, -1)
	}
	return uintptr(newCount)
}

func pluginMakeCredential(
	this unsafe.Pointer,
	opReq *_WEBAUTHN_PLUGIN_OPERATION_REQUEST,
	opResp *_WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
) windows.Handle {
	pThis := (*PluginAuthenticator)(this)

	// Hopefully, the request will be valid until the response is sent;
	// otherwise it's better to clone bytes into Go memory.
	encodedRequest := bytes.Clone(unsafe.Slice(opReq.PbEncodedRequest, opReq.CbEncodedRequest))

	req, err := winhello.PluginDecodeMakeCredentialRequest(encodedRequest)
	if err != nil {
		log.Println(err)
		return windows.E_FAIL
	}

	godump.Dump(req)

	resp, err := pThis.callbacks.OnMakeCredential(&PluginOperationRequest{
		WindowHandle:                 opReq.HWnd,
		TransactionID:                opReq.TransactionId,
		RequestSignature:             bytes.Clone(unsafe.Slice(opReq.PbRequestSignature, opReq.CbRequestSignature)),
		RequestType:                  PluginRequestType(opReq.RequestType),
		EncodedRequest:               encodedRequest,
		DecodedMakeCredentialRequest: req,
	})
	if err != nil {
		log.Println(err)
		return windows.E_FAIL
	}

	encodedResponse, err := winhello.PluginEncodeMakeCredentialResponse(resp)
	if err != nil {
		log.Println(err)
		return windows.E_FAIL
	}

	return writeOperationResponse(opResp, encodedResponse)
}

func pluginGetAssertion(
	this unsafe.Pointer,
	opReq *_WEBAUTHN_PLUGIN_OPERATION_REQUEST,
	opResp *_WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
) windows.Handle {
	pThis := (*PluginAuthenticator)(this)

	encodedRequest := bytes.Clone(unsafe.Slice(opReq.PbEncodedRequest, opReq.CbEncodedRequest))

	req, err := winhello.PluginDecodeGetAssertionRequest(unsafe.Slice(opReq.PbEncodedRequest, opReq.CbEncodedRequest))
	if err != nil {
		log.Println(err)
		return windows.E_FAIL
	}

	godump.Dump(req)

	resp, err := pThis.callbacks.OnGetAssertion(&PluginOperationRequest{
		WindowHandle:               opReq.HWnd,
		TransactionID:              opReq.TransactionId,
		RequestSignature:           bytes.Clone(unsafe.Slice(opReq.PbRequestSignature, opReq.CbRequestSignature)),
		RequestType:                PluginRequestType(opReq.RequestType),
		EncodedRequest:             encodedRequest,
		DecodedGetAssertionRequest: req,
	})
	if err != nil {
		log.Println(err)
		return windows.E_FAIL
	}

	encodedResponse, err := winhello.PluginEncodeGetAssertionResponse(resp)
	if err != nil {
		log.Println(err)
		return windows.E_FAIL
	}

	return writeOperationResponse(opResp, encodedResponse)
}

func pluginCancelOperation(this unsafe.Pointer, opReq *_WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST) windows.Handle {
	pThis := (*PluginAuthenticator)(this)

	if err := pThis.callbacks.OnCancelOperation(&PluginCancelOperationRequest{
		TransactionID:    opReq.TransactionId,
		RequestSignature: bytes.Clone(unsafe.Slice(opReq.PbRequestSignature, opReq.CbRequestSignature)),
	}); err != nil {
		return windows.E_FAIL
	}

	return windows.S_OK
}

func pluginGetLockStatus(this unsafe.Pointer, respLockStatus *PluginLockStatus) windows.Handle {
	pThis := (*PluginAuthenticator)(this)

	lockStatus, err := pThis.callbacks.OnGetLockStatus()
	if err != nil {
		return windows.E_FAIL
	}

	*respLockStatus = lockStatus
	return windows.S_OK
}

func writeOperationResponse(opResp *_WEBAUTHN_PLUGIN_OPERATION_RESPONSE, encodedResponse []byte) windows.Handle {
	addr, _, _ := procCoTaskMemAlloc.Call(uintptr(len(encodedResponse)))
	if addr == 0 {
		return windows.E_OUTOFMEMORY
	}

	// CoTaskMemAlloc returns a native pointer in the syscall return register.
	buf := *(**byte)(unsafe.Pointer(&addr))
	copy(unsafe.Slice(buf, len(encodedResponse)), encodedResponse)

	*opResp = _WEBAUTHN_PLUGIN_OPERATION_RESPONSE{
		CbEncodedResponse: uint32(len(encodedResponse)),
		PbEncodedResponse: buf,
	}
	return windows.S_OK
}
