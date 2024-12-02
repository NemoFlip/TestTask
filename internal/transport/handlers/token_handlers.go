package handlers

import (
	"TestTask/internal/database"
	"TestTask/internal/service"
	"TestTask/pkg"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
)

type AuthServer struct {
	tokenStorage database.RefreshStorage
	tokenManager pkg.TokenManager
	emailService service.MailSender
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
	as.tokenManager.GenerateBothTokens(ctx, as.tokenStorage, userID, ip)
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
	userID, inputIP, ok := as.tokenManager.GetClaims(ctx)
	fmt.Println(inputIP)
	if !ok {
		return
	}
	var inputToken refreshInput
	if err := ctx.BindJSON(&inputToken); err != nil {
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
	fmt.Println(ip)
	if ip != inputIP {
		err = as.emailService.SendMessage()
		if err != nil {
			log.Println(err)
			ctx.Writer.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	as.tokenManager.GenerateBothTokens(ctx, as.tokenStorage, userID, ip)

}
