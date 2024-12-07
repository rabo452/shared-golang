// package jwt provides tools to generate/validate JWT
package validateJWT

import (
	"errors"

	"github.com/golang-jwt/jwt/v4"
)

func IsJWTValid(JWT_SIGN_KEY string, jwtToken string) bool {
	_, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HMAC (same as used to sign)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unknown signing method")
		}
		return []byte(JWT_SIGN_KEY), nil
	})

	// if the jwt is invalid, then err != null
	return err == nil
}
