package routes

import (
	controller "github.com/airbornharsh/go-jwt-auth/controller"
	"github.com/gin-gonic/gin"
)

func AuthRoutes(r *gin.Engine) {
	r.POST("users/signup", controller.SignUp())
	r.POST("users/login", controller.Login())
}
