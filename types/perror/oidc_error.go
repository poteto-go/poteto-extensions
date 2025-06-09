package perror

import "errors"

var (
	ErrInvalidToken                  = errors.New("invalid token")
	ErrFailedToDecodeToken           = errors.New("failed to decode token")
	ErrFailedToUnmarshalToken        = errors.New("failed to unmarshal token")
	ErrFailedToParseJWKsUrl          = errors.New("failed to parse jwks URL")
	ErrFailedToCreateJWKsRequest     = errors.New("failed to create jwks request")
	ErrFailedToGetJWKs               = errors.New("failed to get jwks")
	ErrFailedToUnmarshalJWKsResponse = errors.New("failed to unmarshal jwks response")
	ErrJWKsKeysNotFound              = errors.New("jwks keys not found")
	ErrFailedToValidateSignature     = errors.New("failed to validate signature")
	ErrFailedToDecodeExponentE       = errors.New("failed to decode exponent e")
	ErrFailedToDecodeModulusN        = errors.New("failed to decode modulus n")
	ErrNotIncludeBearerToken         = errors.New("not include bearer token")
)
