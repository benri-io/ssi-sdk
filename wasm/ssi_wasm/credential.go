package ssi_wasm

import (
	"syscall/js"
	//	"github.com/TBD54566975/ssi-sdk/credential"
)

func createVerifiedCredential() js.Func {
	f := js.FuncOf(func(o js.Value, args []js.Value) interface{} {
		//credential.VerifiableCredential
		return ValueOf(o)
	})
	return f
}

func status() js.Func {
	f := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return "OK"
	})
	return f
}

func init() {
	//  js.Global().Set("ssiStatus", status)
	//	js.Global().Set("createVerifiedCredential", createVerifiedCredential)
}
