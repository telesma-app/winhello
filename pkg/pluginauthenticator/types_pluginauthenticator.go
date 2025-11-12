//go:build ignore

package main

/*
//#cgo CFLAGS: -I${SRCDIR}

#include <windows.h>
#include <pluginauthenticator.h>
*/
import "C"

type (
	_WEBAUTHN_PLUGIN_OPERATION_REQUEST        C.WEBAUTHN_PLUGIN_OPERATION_REQUEST
	_WEBAUTHN_PLUGIN_OPERATION_RESPONSE       C.WEBAUTHN_PLUGIN_OPERATION_RESPONSE
	_WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST C.WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST
)

func int32ToBool(i int32) bool {
	return i != 0
}

func boolToInt32(b bool) int32 {
	if b {
		return 1
	}
	return 0
}
