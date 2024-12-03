package main

import (
	_ "TestTask/docs"
	"TestTask/internal/database"
	"TestTask/internal/service"
	"TestTask/internal/transport/handlers"
	"TestTask/internal/transport/middleware"
	"TestTask/pkg"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"log"
	"os"
)

// @title TestTask
// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	router := gin.Default()
	db, err := pkg.PostgresConnect()
	if err != nil {
		log.Println(err)
		return
	}
	secretKey, ok := os.LookupEnv("JWT_SECRET_KEY")
	if !ok {
		log.Fatalf("unable to get secret key")
	}

	tokenManager := pkg.NewTokenManager(secretKey)
	tokenStorage := database.NewRefreshStorage(db)
	mailSender := service.NewMailSender()
	authServer := handlers.NewAuthServer(*tokenStorage, *tokenManager, mailSender)

	router.GET("/get-tokens/:user_id", authServer.CreateTokens)
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	checkAuth := middleware.CheckAuthorization(tokenManager)
	secureGroup := router.Group("/", checkAuth)
	{
		secureGroup.POST("/refresh", authServer.RefreshTokens)
	}

	err = router.Run(":8080")
	if err != nil {
		log.Fatalf("unable to run server on port 8080: %s", err)
	}
}
