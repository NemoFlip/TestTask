package utility

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func GenerateRefreshToken() (string, error) {
	tokenSlice := make([]byte, 32)
	_, err := rand.Read(tokenSlice)
	if err != nil {
		return "", fmt.Errorf("unable to generate bytes: %s", err)
	}
	tokenString := base64.URLEncoding.EncodeToString(tokenSlice)
	return tokenString, nil
}
