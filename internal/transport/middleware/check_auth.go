package middleware

import (
	"TestTask/pkg"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"net/http"
	"strings"
	"time"
)

func CheckAuthorization(tm *pkg.TokenManager) gin.HandlerFunc {
	return func(ctx *gin.Context) {
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
		accessToken, err := tm.ValidateAccessToken(tokenString)
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
		exp, ok := claims["exp"].(float64)
		if !ok {
			log.Println("unable to get `ip` claim from token")
			ctx.Writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		currentTime := time.Now().Unix()
		if currentTime > int64(exp) {
			log.Println("token is expired")
			ctx.Writer.WriteHeader(http.StatusUnauthorized)
			return
		}

		ctx.Set("userID", userID)
		ctx.Set("inputIP", inputIP)

		ctx.Next()
	}
}
