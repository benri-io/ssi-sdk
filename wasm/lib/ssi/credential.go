package ssi_wasm

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"syscall/js"
	"time"

	gocrypto "crypto"

	"github.com/TBD54566975/ssi-sdk/credential"

	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/lestrrat-go/jwx/jwt"
)

var privKey gocrypto.PrivateKey

// Make a Verifiable Credential
// using the VC data type directly.
// Alternatively, use the builder
// A VC is set of tamper-evident claims and metadata
// that cryptographically prove who issued it
// Building a VC means using the CredentialBuilder
// as part of the credentials package in the ssk-sdk.
// VerifiableCredential is the verifiable credential model outlined in the
// vc-data-model spec https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#basic-concept
func buildRegistrationCredential(issuer string, holder string) (*credential.VerifiableCredential, error) {
	knownContext := []string{"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1"} // JSON-LD context statement
	knownID := "http://example.edu/credentials/1872"
	knownType := []string{"VerifiableCredential", "AlumniCredential"}
	knownIssuer := "https://example.edu/issuers/565049"
	knownIssuanceDate := time.Now().Format(time.RFC3339)
	knownSubject := map[string]interface{}{
		"id": issuer, //did:<method-name>:<method-specific-id>
		"registered": map[string]interface{}{ // claims are here
			"id":            holder,
			"currentStatus": "registered",
			"registeredWith": map[string]interface{}{
				"companyName": "Benri.io",
			},
			"on": "landingPage",
		},
	}

	knownCred := credential.VerifiableCredential{
		Context:           knownContext,
		ID:                knownID,
		Type:              knownType,
		Issuer:            knownIssuer,
		IssuanceDate:      knownIssuanceDate,
		CredentialSubject: knownSubject,
	}

	err := knownCred.IsValid()
	if err != nil {
		fmt.Println("not valid cred")
		return nil, err
	}
	return &knownCred, nil
}

func createDIDPeer() (string, error) {

	kt := crypto.Ed25519
	pubKey, _, err := crypto.GenerateKeyByKeyType(kt)
	if err != nil {
		return "", err
	}
	didk, err := did.PeerMethod0{}.Generate(kt, pubKey)
	if err != nil {
		return "", err
	}
	didStr := didk.ToString()
	return didStr, nil
}

func createVerifiedCredential() js.Func {

	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {

		fmt.Println("creating verified credential")
		// generate
		issuer, err := createDIDPeer()
		if err != nil {
			return err
		}
		fmt.Println("created issuer")

		holder, err := createDIDPeer()
		if err != nil {
			return err
		}
		fmt.Println("created holder")

		// generate
		vc, err := buildRegistrationCredential(issuer, holder)
		if err != nil {
			fmt.Printf("failed to build registration credential : %v", err)
			return err
		}

		jwk, err := cryptosuite.JSONWebKey2020FromEd25519(privKey.(ed25519.PrivateKey))
		if err != nil {
			return err
		}

		signer, err := cryptosuite.NewJSONWebKeySigner(jwk.ID, jwk.PrivateKeyJWK, cryptosuite.Authentication)
		if err != nil {
			return err
		}

		dat, err := signing.SignVerifiableCredentialJWT(*signer, *vc)
		if err != nil {
			return err
		}

		fmt.Printf("built vc: %v\n", string(dat))
		return string(dat)
	})
	return jsonFunc
}

func verifyVerifiedCredential() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		token := args[0].String()
		jwk, err := cryptosuite.JSONWebKey2020FromEd25519(privKey.(ed25519.PrivateKey))
		if err != nil {
			return nil
		}
		verifier, err := cryptosuite.NewJSONWebKeyVerifier(jwk.ID, jwk.PublicKeyJWK)
		if err != nil {
			return err
		}
		_, err = signing.VerifyVerifiableCredentialJWT(*verifier, token)
		if err != nil {
			return err
		}
		fmt.Println("Verified!")
		return nil
	})
	return jsonFunc
}

func decodeb64Wrapper() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		v := args[0].String()
		fmt.Println("Decoding vc...")
		parsed, err := jwt.Parse([]byte(v))
		if err != nil {
			fmt.Printf("Error: %v", err)
			return err
		}

		fmt.Printf("Decoded VC: %v\n", parsed)
		dat, err := json.Marshal(parsed)
		if err != nil {
			return err
		}
		return string(dat)
	})
	return jsonFunc
}
func init() {
	js.Global().Set("createVerifiedCredential", createVerifiedCredential())
	js.Global().Set("verifyVerifiedCredential", verifyVerifiedCredential())
	js.Global().Set("b64decode", decodeb64Wrapper())

	pk, _, err := did.GenerateDIDKey(crypto.Ed25519)
	if err != nil {
		fmt.Println("Panic!")
		panic(err)
	}
	privKey = pk

}
