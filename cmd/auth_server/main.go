package main

import (
	_ "TestTask/docs"
	"TestTask/internal/database"
	"TestTask/internal/transport/handlers"
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
func main() {
	router := gin.Default()
	db, err := pkg.PostgresConnect("tokenDB")
	if err != nil {
		log.Println(err)
	}
	secretKey, ok := os.LookupEnv("JWT_SECRET_KEY")
	if !ok {
		log.Fatalf("unable to get secret key")
	}

	tokenManager := pkg.NewTokenManager(secretKey)
	tokenStorage := database.NewRefreshStorage(db)
	authServer := handlers.NewAuthServer(*tokenStorage, *tokenManager)

	router.GET("/get-tokens/:user_id", authServer.СreateTokens)
	router.POST("/refresh", authServer.RefreshTokens)

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	err = router.Run(":8080")
	if err != nil {
		log.Fatalf("unable to run server on port (:8080): %s", err)
	}
}
