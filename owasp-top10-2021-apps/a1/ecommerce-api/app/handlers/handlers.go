package handlers

import (
	"fmt"
	"net/http"

	

	"github.com/globocom/secDevLabs/owasp-top10-2021-apps/a1/ecommerce-api/app/db"
	"github.com/labstack/echo"
	jwt "github.com/dgrijalva/jwt-go"
)

// HealthCheck is the heath check function.
func HealthCheck(c echo.Context) error {
	return c.String(http.StatusOK, "WORKING\n")
}

// GetTicket returns the userID ticket.
func GetTicket(c echo.Context) error {

    authHeader := c.Request().Header.Get("Authorization")
	id := c.Param("id")

	if authHeader == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Authorization header is missing",
		})
	}

	userDataQuery := map[string]interface{}{"userID": id}
	userDataResult, err := db.GetUserData(userDataQuery)
	if err != nil {
		// could not find this user in MongoDB (or MongoDB err connection)
		return c.JSON(http.StatusBadRequest, map[string]string{"result": "error", "details": "Error finding this UserID."})
	}


	format := c.QueryParam("format")
	if format == "json" {
		return c.JSON(http.StatusOK, map[string]string{
			"result":   "success",
			"username": userDataResult.Username,
			"userId" : userDataResult.UserID,
			"ticket":   userDataResult.Ticket,
		})
	}

	msgTicket := fmt.Sprintf("Hey, %s! This is your ticket: %s\n", userDataResult.Username, userDataResult.Ticket)
	return c.String(http.StatusOK, msgTicket)
}


func parseToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	// Exemplo de parsing do JWT
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil // sua chave secreta
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// Claims define os dados que estarão no JWT
type Claims struct {
	UserID string `json:"userId"`
	jwt.StandardClaims
}