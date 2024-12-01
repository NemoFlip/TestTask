package handlers

import (
	"TestTask/internal/database"
	"TestTask/internal/entity"
	"TestTask/pkg"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strings"
	"time"
)

type AuthServer struct {
	tokenStorage database.RefreshStorage
	tokenManager pkg.TokenManager
}

func NewAuthServer(tokenStorage database.RefreshStorage, tokenManager pkg.TokenManager) *AuthServer {
	return &AuthServer{tokenStorage: tokenStorage, tokenManager: tokenManager}
}

// @Summary Create tokens
// @Description get access and refresh tokens via user_id
// @Tags tokens
// @Param user_id path string true "ID of the user"
// @Produce json
// @Success 200
// @Failure 500
// @Router /get-tokens/{user_id} [get]
func (as *AuthServer) СreateTokens(ctx *gin.Context) {
	userID := ctx.Param("user_id")
	// Generating access token
	ip := ctx.ClientIP()
	payload := jwt.MapClaims{
		"sub": userID,
		"ip":  ip,
		"exp": time.Now().Add(time.Minute * 15).Unix(),
	}
	accessToken, err := as.tokenManager.GenerateAccessToken(payload, jwt.SigningMethodHS512)
	if err != nil {
		log.Println(err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Generating refresh token
	refreshTokenString, err := as.tokenManager.GenerateRefreshToken()
	if err != nil {
		log.Println(err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshTokenString), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("unable to get hashed password: %s", err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	expTime := time.Now().Add(time.Minute * 43200).UTC() // 30 days refresh token is valid

	refreshToken := entity.RefreshToken{
		UserID:       userID,
		RefreshToken: string(hashedToken),
		ExpiresAT:    expTime,
	}

	err = as.tokenStorage.Post(refreshToken)
	if err != nil {
		log.Println(err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	ctx.JSON(200, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshTokenString,
	})
}

type refreshInput struct {
	RefreshToken string `json:"refresh_token"`
}

// @Summary Refresh tokens
// @Description get access and refresh tokens via user_id
// @Tags tokens
// @Param token body refreshInput true "Данные для регистрации пользователя"
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200
// @Failure 500
// @Router /refresh [post]
func (as *AuthServer) RefreshTokens(ctx *gin.Context) {
	authHeader := ctx.GetHeader("Authorization")

	if len(authHeader) == 0 {
		log.Println("authorization token is absent")
		ctx.Writer.WriteHeader(http.StatusUnauthorized)
		return
	}

	bearerToken := strings.Split(authHeader, " ")
	if bearerToken[0] != "Bearer" || len(bearerToken) != 2 {
		log.Printf("invalid format of auth token")
		ctx.Writer.WriteHeader(http.StatusUnauthorized)
		return
	}

	tokenString := bearerToken[1]
	accessToken, err := as.tokenManager.ValidateAccessToken(tokenString)
	if err != nil {
		log.Println(err)
		ctx.Writer.WriteHeader(http.StatusBadRequest)
		return
	}

	claims, ok := accessToken.Claims.(jwt.MapClaims)
	if !ok {
		log.Println("invalid format of auth token")
		ctx.Writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	userID, ok := claims["sub"].(string)
	if !ok {
		log.Println("unable to get `sub` claim from token")
		ctx.Writer.WriteHeader(http.StatusUnauthorized)
		return
	}

	inputIP, ok := claims["ip"].(string)
	if !ok {
		log.Println("unable to get `ip` claim from token")
		ctx.Writer.WriteHeader(http.StatusUnauthorized)
		return
	}

	var inputToken refreshInput
	if err = ctx.BindJSON(&inputToken); err != nil {
		fmt.Printf("invalid input refresh token")
		ctx.Writer.WriteHeader(http.StatusBadRequest)
		return
	}

	returnedToken, err := as.tokenStorage.Get(userID)
	if err != nil {
		log.Println(err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(returnedToken.RefreshToken), []byte(inputToken.RefreshToken))
	if err != nil {
		log.Printf("invalid refresh token: %s", err)
		ctx.Writer.WriteHeader(http.StatusBadRequest)
		return
	}
	err = as.tokenStorage.Delete(userID)
	if err != nil {
		log.Println(err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	ip := ctx.ClientIP()
	if ip != inputIP {

		// TODO: email warning
	}

	payload := jwt.MapClaims{
		"ip":  ip,
		"exp": time.Now().Add(time.Minute * 15).Unix(),
	}
	newAccessToken, err := as.tokenManager.GenerateAccessToken(payload, jwt.SigningMethodHS512)
	if err != nil {
		log.Println(err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	newRefreshToken, err := as.tokenManager.GenerateRefreshToken()
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
		UserID:       returnedToken.UserID,
		RefreshToken: string(newHashedToken),
		ExpiresAT:    expTime,
	}

	err = as.tokenStorage.Post(refreshToken)
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
