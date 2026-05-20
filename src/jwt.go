package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type JWK struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWK2 struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	Kid string `json:"kid"`
	E   string `json:"e"`
}

type Header struct {
	Alg string `json:"alg"`
	Jwk JWK    `json:"jwk"`
}

type Header2 struct {
	Alg string `json:"alg"`
	Jwk JWK2   `json:"jwk"`
}

type Application struct {
	ID             string `json:"id"`
	ClientPlatform string `json:"clientPlatform"`
	Version        string `json:"version"`
}

type Device struct {
	ID       string `json:"id"`
	Platform string `json:"platform"`
	Hardware string `json:"hardware"`
}

type Attributes struct {
	SdkProtocolVersion int `json:"sdk_protocol_version"`
}

type Payload struct {
	Application Application `json:"application"`
	Device      Device      `json:"device"`
	Attributes  Attributes  `json:"attributes"`
}

type Payload2 struct {
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Iss string `json:"iss"`
	Jti string `json:"jti"`
	Aud string `json:"aud"`
	Sub string `json:"sub"`
}

func createKeyPair() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func getPublicKeyMod(publicKeyDer []byte) []byte {
	pubKey, _ := x509.ParsePKCS1PublicKey(publicKeyDer)
	return pubKey.N.Bytes()
}

func generateDeviceJWT(deviceID string) (string, string, string, string, *rsa.PrivateKey, error) {
	privateKey, err := createKeyPair()
	if err != nil {
		return "", "", "", "", nil, err
	}

	publicKeyDer := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	modulus := base64.StdEncoding.EncodeToString(getPublicKeyMod(publicKeyDer))

	headerObj := Header{
		Alg: "RS256",
		Jwk: JWK{
			Kty: "RSA",
			N:   modulus,
			E:   "AQAB",
		},
	}
	headerJSON, err := json.Marshal(headerObj)
	if err != nil {
		return "", "", "", "", nil, err
	}
	header := base64.StdEncoding.EncodeToString(headerJSON)

	payloadObj := Payload{
		Application: Application{
			ID:             "<app.package.name>",
			ClientPlatform: "ios",
			Version:        "<app.version>",
		},
		Device: Device{
			ID:       deviceID,
			Platform: "ios 16.7.8",
			Hardware: "iPhone",
		},
		Attributes: Attributes{
			SdkProtocolVersion: 1,
		},
	}
	payloadJSON, err := json.Marshal(payloadObj)
	if err != nil {
		return "", "", "", "", nil, err
	}
	payload := base64.StdEncoding.EncodeToString(payloadJSON)

	dataToSign := fmt.Sprintf("%s.%s", header, payload)
	hash := sha256.New()
	hash.Write([]byte(dataToSign))
	hashed := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", "", "", "", nil, err
	}
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	return header, payload, signatureBase64, modulus, privateKey, nil
}

func generateClientAssertion(clientID string, code string, n string, privateKey *rsa.PrivateKey) (string, error) {
	headerObj := Header2{
		Alg: "RS256",
		Jwk: JWK2{
			Kty: "RSA",
			N:   n,
			Kid: clientID,
			E:   "AQAB",
		},
	}
	headerJSON, err := json.Marshal(headerObj)
	if err != nil {
		return "", err
	}
	header := base64.StdEncoding.EncodeToString(headerJSON)

	iat := time.Now().UnixNano() / 1e6
	payloadObj := Payload2{
		Iat: iat,
		Exp: iat + 6e4,
		Iss: "<app.package.name>$ios$<app.version>",
		Jti: code,
		Aud: "(null)az/v1/token",
		Sub: clientID,
	}
	payloadJSON, err := json.Marshal(payloadObj)
	if err != nil {
		return "", err
	}
	payload := base64.StdEncoding.EncodeToString(payloadJSON)

	dataToSign := fmt.Sprintf("%s.%s", header, payload)
	hash := sha256.New()
	hash.Write([]byte(dataToSign))
	hashed := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", err
	}
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	clientAssertion := fmt.Sprintf("%s.%s.%s", header, payload, signatureBase64)
	return clientAssertion, nil
}
