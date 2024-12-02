package pkg

import (
	"TestTask/internal/database"
	"TestTask/internal/entity"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
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
	return jwtToken, nil
}

func (tm *TokenManager) SignToken(token *jwt.Token) (string, error) {
	jwtTokenString, err := token.SignedString([]byte(tm.signingKey))
	if err != nil {
		return "", fmt.Errorf("unable to sign jwt token: %s", err)
	}
	return jwtTokenString, nil
}

func (tm *TokenManager) GenerateAccessToken(userID string, ip string, signingMethod jwt.SigningMethod) (string, error) {
	payload := jwt.MapClaims{
		"sub": userID,
		"ip":  ip,
		"exp": time.Now().Add(time.Minute * 15).Unix(),
	}
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
func (tm *TokenManager) GenerateBothTokens(ctx *gin.Context, tokenStorage database.RefreshStorage, userID string, ip string) {
	newAccessToken, err := tm.GenerateAccessToken(userID, ip, jwt.SigningMethodHS512)
	if err != nil {
		log.Println(err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	newRefreshToken, err := tm.GenerateRefreshToken()
	if err != nil {
		log.Println(err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	newHashedToken, err := bcrypt.GenerateFromPassword([]byte(newRefreshToken), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("unable to get hashed password: %s", err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	expTime := time.Now().Add(time.Minute * 43200).UTC() // 30 days refresh token is valid

	refreshToken := entity.RefreshToken{
		UserID:       userID,
		RefreshToken: string(newHashedToken),
		ExpiresAT:    expTime,
	}

	err = tokenStorage.Post(refreshToken)
	if err != nil {
		log.Println(err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	ctx.JSON(200, gin.H{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	})
}

func (tm *TokenManager) GetClaims(ctx *gin.Context) (string, string, bool) {
	userID, exists := ctx.Get("userID")
	if !exists {
		log.Println("invalid token credentials: userID is absent")
		ctx.Writer.WriteHeader(http.StatusUnauthorized)
		return "", "", false
	}

	inputIP, exists := ctx.Get("inputIP")
	if !exists {
		log.Println("invalid token credentials: ip is absent")
		ctx.Writer.WriteHeader(http.StatusUnauthorized)
		return "", "", false
	}

	userIDStr, ok := userID.(string)
	if !ok {
		log.Println("userID is not a string")
		ctx.Writer.WriteHeader(http.StatusUnauthorized)
		return "", "", false
	}

	inputIPStr, ok := inputIP.(string)
	if !ok {
		log.Println("inputIP is not a string")
		ctx.Writer.WriteHeader(http.StatusUnauthorized)
		return "", "", false
	}

	return userIDStr, inputIPStr, true
}
