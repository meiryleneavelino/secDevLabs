package handlers

import (
	"fmt"
	"net/http"

	"github.com/globocom/secDevLabs/owasp-top10-2021-apps/a1/ecommerce-api/app/db"
	"github.com/labstack/echo"
)

// HealthCheck is the health check function.
func HealthCheck(c echo.Context) error {
	return c.String(http.StatusOK, "WORKING\n")
}

// GetTicket returns the userID ticket.
func GetTicket(c echo.Context) error {
	// Obter o userID do contexto
	userIDFromContext, ok := c.Get("userID").(string)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"result":  "error",
			"details": "Invalid user authentication data.",
		})
	}

	// Obter o userID da URL
	id := c.Param("id")
	if id == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"result":  "error",
			"details": "User ID is required.",
		})
	}

	// Verificar se o userID autenticado corresponde ao userID fornecido
	if userIDFromContext != id {
		return c.JSON(http.StatusForbidden, map[string]string{
			"result":  "error",
			"details": "Access denied. You are not authorized to view this ticket.",
		})
	}

	// Consultar o banco de dados com base no userID
	userDataQuery := map[string]interface{}{"userID": id}
	userDataResult, err := db.GetUserData(userDataQuery)
	if err != nil {
		c.Logger().Errorf("Error querying user data: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"result":  "error",
			"details": "An internal error occurred. Please try again later.",
		})
	}

	// Verificar o formato da resposta
	format := c.QueryParam("format")
	if format == "json" {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"result":   "success",
			"username": userDataResult.Username,
			"ticket":   userDataResult.Ticket,
		})
	}

	// Resposta em texto simples
	msgTicket := fmt.Sprintf("Hey, %s! This is your ticket: %s\n", userDataResult.Username, userDataResult.Ticket)
	return c.String(http.StatusOK, msgTicket)
}