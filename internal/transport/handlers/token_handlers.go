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
	mailSender   *service.MailSender
}

func NewAuthServer(tokenStorage database.RefreshStorage, tokenManager pkg.TokenManager, mailSender *service.MailSender) *AuthServer {
	return &AuthServer{tokenStorage: tokenStorage, tokenManager: tokenManager, mailSender: mailSender}
}

// @Summary Create tokens
// @Description get access and refresh tokens via user_id
// @Tags tokens
// @Param user_id path string true "ID of the user"
// @Produce json
// @Success 200
// @Failure 500
// @Router /get-tokens/{user_id} [get]
func (as *AuthServer) CreateTokens(ctx *gin.Context) {
	userID := ctx.Param("user_id")
	ip := ctx.ClientIP()
	as.tokenManager.GenerateBothTokens(ctx, as.tokenStorage, userID, ip)
}

type refreshInput struct {
	RefreshToken string `json:"refresh_token"`
}

func (as *AuthServer) compareTokens(ctx *gin.Context, userID string, inputToken refreshInput) {
	// Compare it with already saved token
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

	// Delete previous token
	err = as.tokenStorage.Delete(userID)
	if err != nil {
		log.Println(err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}

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
	if !ok {
		log.Println("unable to get user_id and input_ip from context")
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Get token from request body for refreshing
	var inputToken refreshInput
	if err := ctx.BindJSON(&inputToken); err != nil {
		fmt.Printf("invalid input refresh token")
		ctx.Writer.WriteHeader(http.StatusBadRequest)
		return
	}

	// Compare it with already saved token
	as.compareTokens(ctx, userID, inputToken)

	ip := ctx.ClientIP()
	if ip != inputIP {
		if as.mailSender == nil {
			log.Printf("unable to send message to user: mailSender is not created")
			ctx.Writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		err := as.mailSender.SendMessage(ip)
		if err != nil {
			log.Println(err)
			ctx.Writer.WriteHeader(http.StatusInternalServerError)
		}
		ctx.Writer.WriteHeader(http.StatusBadRequest)
		return
	}

	as.tokenManager.GenerateBothTokens(ctx, as.tokenStorage, userID, ip)
}
