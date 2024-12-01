package pkg

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
)

type TokenManager struct {
	signingKey string
}

func NewTokenManager(signingKey string) *TokenManager {
	return &TokenManager{signingKey: signingKey}
}

func (tm *TokenManager) ValidateAccessToken(tokenString string) (*jwt.Token, error) {
	jwtToken, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return []byte(tm.signingKey), nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unable to get claims from token: %w", err)
	}
	_, ok = claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("unable to get `sub` claim from token: %w", err)
	}
	return jwtToken, nil
}

func (tm *TokenManager) SignToken(token *jwt.Token) (string, error) {
	jwtTokenString, err := token.SignedString([]byte(tm.signingKey))
	if err != nil {
		return "", fmt.Errorf("unable to sign jwt token: %s", err)
	}
	return jwtTokenString, nil
}

func (tm *TokenManager) GenerateAccessToken(payload jwt.MapClaims, signingMethod jwt.SigningMethod) (string, error) {
	accessToken := jwt.NewWithClaims(signingMethod, payload)
	signedAccessToken, err := tm.SignToken(accessToken)
	if err != nil {
		return "", err
	}
	return signedAccessToken, nil
}

func (tm *TokenManager) GenerateRefreshToken() (string, error) {
	tokenSlice := make([]byte, 32)
	_, err := rand.Read(tokenSlice)
	if err != nil {
		return "", fmt.Errorf("unable to generate bytes: %s", err)
	}
	tokenString := base64.URLEncoding.EncodeToString(tokenSlice)
	return tokenString, nil
}
