//go:build windows

package pluginauthenticator

import (
	"unsafe"

	"github.com/go-ole/go-ole"
	"golang.org/x/sys/windows"
)

type classFactoryVtbl struct {
	ole.IUnknownVtbl
	CreateInstance uintptr
	LockServer     uintptr
}

type pluginClassFactory struct {
	vtable        *classFactoryVtbl
	refs          comReferences
	authenticator *pluginAuthenticator
}

var (
	classIID    = ole.NewGUID("{00000001-0000-0000-C000-000000000046}")
	pluginIID   = ole.NewGUID("{d26bcf6f-b54c-43ff-9f06-d5bf148625f7}")
	factoryVtbl classFactoryVtbl
)

func init() {
	factoryVtbl = classFactoryVtbl{
		IUnknownVtbl: ole.IUnknownVtbl{
			QueryInterface: windows.NewCallback(classFactoryQueryInterface),
			AddRef:         windows.NewCallback(classFactoryAddRef),
			Release:        windows.NewCallback(classFactoryRelease),
		},
		CreateInstance: windows.NewCallback(classFactoryCreateInstance),
		LockServer:     windows.NewCallback(classFactoryLockServer),
	}
}

func classFactoryQueryInterface(this *pluginClassFactory, iid *ole.GUID, object *unsafe.Pointer) windows.Handle {
	if object == nil {
		return windows.E_POINTER
	}

	*object = nil

	if !ole.IsEqualGUID(iid, ole.IID_IUnknown) && !ole.IsEqualGUID(iid, classIID) {
		return windows.E_NOINTERFACE
	}

	classFactoryAddRef(this)
	*object = unsafe.Pointer(this)

	return windows.S_OK
}

func classFactoryAddRef(this *pluginClassFactory) uintptr {
	return this.refs.add()
}

func classFactoryRelease(this *pluginClassFactory) uintptr {
	count := this.refs.release(unsafe.Pointer(this))
	if count == 0 {
		pluginRelease(this.authenticator)
	}

	return count
}

func classFactoryCreateInstance(this *pluginClassFactory, outer *ole.IUnknown, iid *ole.GUID, object *unsafe.Pointer) windows.Handle {
	if object == nil {
		return windows.E_POINTER
	}

	*object = nil

	if outer != nil {
		return windows.CLASS_E_NOAGGREGATION
	}

	if this.authenticator.ctx.Err() != nil {
		return windows.CO_E_OBJNOTCONNECTED
	}

	return pluginQueryInterface(this.authenticator, iid, object)
}

func classFactoryLockServer(_ *pluginClassFactory, _ int32) windows.Handle {
	// Serve controls the server lifetime.
	return windows.S_OK
}
