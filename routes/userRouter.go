package routes

import (
	"github.com/airbornharsh/go-jwt-auth/controller"
	"github.com/airbornharsh/go-jwt-auth/middleware"
	"github.com/gin-gonic/gin"
)

func UserRoutes(r *gin.Engine) {
	r.Use(middleware.Authenticate())
	r.GET("/users", controller.GetUsers())
	r.GET("/users/:user_id", controller.GetUser())
}
