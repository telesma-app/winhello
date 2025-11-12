//go:build windows

package main

import (
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modOle32 = windows.NewLazySystemDLL("ole32.dll")

	procCoRegisterClassObject = modOle32.NewProc("CoRegisterClassObject")
	procCoRevokeClassObject   = modOle32.NewProc("CoRevokeClassObject")
	procCoResumeClassObjects  = modOle32.NewProc("CoResumeClassObjects")
	procCoTaskMemAlloc        = modOle32.NewProc("CoTaskMemAlloc")

	g_objCount  int32 = 0
	g_lockCount int32 = 0
)

const (
	_REGCLS_MULTIPLEUSE = 1
	_REGCLS_SUSPENDED   = 4
)

func main() {
	if err := windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED); err != nil {
		log.Fatal("CoInitialize failed:", err)
	}
	defer windows.CoUninitialize()

	cookie := uint32(0)

	hr, _, _ := procCoRegisterClassObject.Call(
		uintptr(unsafe.Pointer(CLSID_PluginAuthenticator)),
		uintptr(unsafe.Pointer(gClassFactoryInstance)),
		windows.CLSCTX_LOCAL_SERVER,
		_REGCLS_MULTIPLEUSE|_REGCLS_SUSPENDED,
		uintptr(unsafe.Pointer(&cookie)),
	)
	if hr != uintptr(windows.S_OK) {
		log.Fatal("CoRegisterClassObject failed:", syscall.Errno(hr))
	}
	defer func() {
		_, _, _ = procCoRevokeClassObject.Call(uintptr(cookie))
	}()

	// We register with REGCLS_SUSPENDED, so we need to resume manually
	hr, _, _ = procCoResumeClassObjects.Call()
	if hr != uintptr(windows.S_OK) {
		log.Fatal("CoResumeClassObjects failed:", syscall.Errno(hr))
	}

	log.Println("COM Server started")
	select {}
}
