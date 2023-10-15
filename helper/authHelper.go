package helper

import (
	"errors"

	"github.com/gin-gonic/gin"
)

// func CheckUserType(c *gin.Context, role string) (err error) {

// 	return err
// }

func MatchUserTypeToUid(c *gin.Context, userId string) (err error) {
	userType := c.GetString("user_type")
	uid := c.GetString("uid")
	err = nil

	if userType == "USER" && uid != userId {
		err = errors.New("unauthorized to access this resource")
		return err
	}

	// err = CheckUserType(c, userType)
	return err
}
