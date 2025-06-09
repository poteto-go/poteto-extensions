package oidc

import (
	"github.com/poteto-go/poteto-extensions/types/perror"
)

var JWKsUrls = map[string]string{
	"google": "https://www.googleapis.com/oauth2/v3/certs",
}

type jwk struct {
	E   string `json:"e"`
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	Alg string `json:"alg"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func (keys jwks) find(kid string) (jwk, error) {
	var foundKey jwk
	for _, key := range keys.Keys {
		if key.Kid == kid {
			foundKey = key
			break
		}
	}

	if foundKey != (jwk{}) {
		return foundKey, nil
	} else {
		return jwk{}, perror.ErrJWKsKeysNotFound
	}
}
