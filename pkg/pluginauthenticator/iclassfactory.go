//go:build windows

package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"math/big"
	"sync/atomic"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/winhello"
	"golang.org/x/sys/windows"
)

type IClassFactoryVtbl struct {
	ole.IUnknownVtbl
	CreateInstance uintptr
	LockServer     uintptr
}

type ClassFactory struct {
	lpVtbl    *IClassFactoryVtbl
	refCount  int32
	callbacks *PluginCallbacks
}

var (
	classFactoryVtbl      IClassFactoryVtbl
	gClassFactoryInstance = &ClassFactory{lpVtbl: &classFactoryVtbl, callbacks: &PluginCallbacks{
		OnMakeCredential: func(req *PluginOperationRequest) (*winhello.WinHelloMakeCredentialResponse, error) {
			pubKey, err := winhello.PluginGetOperationSigningPublicKey("{1537ff70-8f94-495b-bad1-bcff96311d5f}")
			if err != nil {
				return nil, err
			}

			hasher := sha256.New()
			hasher.Write(req.EncodedRequest)
			hash := hasher.Sum(nil)

			n := (pubKey.(*ecdsa.PublicKey).Params().N.BitLen() + 7) / 8
			if len(req.RequestSignature) != n*2 {
				return nil, errors.New("invalid signature length")
			}
			r := new(big.Int).SetBytes(req.RequestSignature[:n])
			s := new(big.Int).SetBytes(req.RequestSignature[n:])

			if !ecdsa.Verify(pubKey.(*ecdsa.PublicKey), hash, r, s) {
				return nil, errors.New("invalid operation signature")
			}

			log.Println("operation signature verified")

			signature, err := winhello.PluginPerformUserVerification(&winhello.PluginUserVerificationRequestOptions{
				WindowHandle:  req.WindowHandle,
				TransactionID: req.TransactionID.String(),
				Username:      "savely",
				DisplayHint:   "Test Test Test",
			})
			if err != nil {
				return nil, err
			}

			uvPubKey, err := winhello.PluginGetUserVerificationPublicKey("{1537ff70-8f94-495b-bad1-bcff96311d5f}")
			if err != nil {
				return nil, err
			}

			n = (uvPubKey.(*ecdsa.PublicKey).Params().N.BitLen() + 7) / 8
			if len(signature) != n*2 {
				return nil, errors.New("invalid signature length")
			}
			r = new(big.Int).SetBytes(signature[:n])
			s = new(big.Int).SetBytes(signature[n:])

			if !ecdsa.Verify(uvPubKey.(*ecdsa.PublicKey), hash, r, s) {
				return nil, errors.New("invalid user verification signature")
			}

			log.Println("user verification signature verified")

			b, err := hex.DecodeString("74a6ea9213c99c2f74b22492b320cf40262a94c1a950a0397f29250b60841ef045000033b3eabb46cce24180bfae9e96fa6d2975cf006053eb5344596815a17197aa9fd824d2441f608e455c9b814b610b0dacd22b19c3eab811389c2aadf7f2c091165f6f73565a69e56961bf0dc030ec3c9d687db82f636b8c004277daf71fd90d03dfc67b217a879333b46c9c8626126e64e49539f4a50102032620012158204cf5a2a90c17988b59e6750162abd14a2c306d70bcf006b1b65b8e8962fb932622582074009d8ac98683db5e08e88e390209983c6be6fd3bcef9d02729391985f82b77")
			if err != nil {
				return nil, err
			}

			return &winhello.WinHelloMakeCredentialResponse{
				AuthenticatorMakeCredentialResponse: &protocol.AuthenticatorMakeCredentialResponse{
					AuthDataRaw: b,
				},
			}, nil
		},
		OnGetAssertion: func(req *PluginOperationRequest) (*winhello.CTAPCBORGetAssertionResponse, error) {
			return nil, errors.ErrUnsupported
		},
		OnCancelOperation: func(req *PluginCancelOperationRequest) error {
			return nil
		},
		OnGetLockStatus: func() (PluginLockStatus, error) {
			return PluginLockStatusUnlocked, nil
		},
	}}
)

func init() {
	classFactoryVtbl = IClassFactoryVtbl{
		IUnknownVtbl: ole.IUnknownVtbl{
			QueryInterface: windows.NewCallback(classFactoryQueryInterface),
			AddRef:         windows.NewCallback(classFactoryAddRef),
			Release:        windows.NewCallback(classFactoryRelease),
		},
		CreateInstance: windows.NewCallback(classFactoryCreateInstance),
		LockServer:     windows.NewCallback(classFactoryLockServer),
	}
}

func classFactoryQueryInterface(this unsafe.Pointer, iid *ole.GUID, pvObject *unsafe.Pointer) windows.Handle {
	if pvObject == nil {
		return windows.E_POINTER
	}
	*pvObject = nil

	if ole.IsEqualGUID(iid, ole.IID_IUnknown) ||
		ole.IsEqualGUID(iid, IID_IClassFactory) ||
		ole.IsEqualGUID(iid, IID_IPluginAuthenticator) {
		classFactoryAddRef(this)
		*pvObject = this
		return windows.S_OK
	}

	return windows.E_NOINTERFACE
}

func classFactoryAddRef(this unsafe.Pointer) uintptr {
	cf := (*ClassFactory)(this)
	return uintptr(atomic.AddInt32(&cf.refCount, 1))
}

func classFactoryRelease(this unsafe.Pointer) uintptr {
	cf := (*ClassFactory)(this)
	return uintptr(atomic.AddInt32(&cf.refCount, -1))
}

func classFactoryCreateInstance(this unsafe.Pointer, pUnkOuter *ole.IUnknown, riid *ole.GUID, pvObject *unsafe.Pointer) windows.Handle {
	pThis := (*ClassFactory)(this)

	if pvObject == nil {
		return windows.E_POINTER
	}
	*pvObject = nil

	if pUnkOuter != nil {
		return windows.CLASS_E_NOAGGREGATION
	}

	pObject := NewPluginAuthenticator(pThis.callbacks)
	hr := pluginQueryInterface(unsafe.Pointer(pObject), riid, pvObject)
	if hr != windows.S_OK {
		pluginRelease(unsafe.Pointer(pObject))
	}

	return hr
}

func classFactoryLockServer(this unsafe.Pointer, fLock bool) windows.Handle {
	if fLock {
		atomic.AddInt32(&g_lockCount, 1)
	} else {
		atomic.AddInt32(&g_lockCount, -1)
	}
	return windows.S_OK
}
