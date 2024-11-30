package handlers

import (
	"TestTask/internal/database"
	"TestTask/internal/utility"
	"TestTask/pkg"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
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
		"ip":  ip,
		"exp": time.Now().Add(time.Minute * 15).Unix(),
	}
	accessToken, err := as.tokenManager.GenerateToken(payload, jwt.SigningMethodHS512)
	if err != nil {
		log.Println(err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Generating refresh token
	refreshToken, err := utility.GenerateRefreshToken()
	if err != nil {
		log.Println(err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("unable to get hashed password: %s", err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = as.tokenStorage.Post(userID, string(hashedToken))
	if err != nil {
		log.Println(err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	ctx.JSON(200, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func (as *AuthServer) RefreshTokens(ctx *gin.Context) {

}
