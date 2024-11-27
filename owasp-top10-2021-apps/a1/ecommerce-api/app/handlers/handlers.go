package handlers

import (
	"fmt"
	"net/http"

	"github.com/globocom/secDevLabs/owasp-top10-2021-apps/a1/ecommerce-api/app/db"
	"github.com/labstack/echo"
)

// HealthCheck is the heath check function.
func HealthCheck(c echo.Context) error {
	return c.String(http.StatusOK, "WORKING\n")
}

// GetTicket returns the userID ticket.
func GetTicket(c echo.Context) error {
    // Obter o userID do contexto (definido por um middleware de autenticação)
    userIDFromContext := c.Get("userID").(string) // Assumindo que o middleware adiciona userID no contexto

    // Obter o userID da URL
    id := c.Param("id")

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
        // Erro ao buscar dados do usuário no MongoDB
        return c.JSON(http.StatusBadRequest, map[string]string{
            "result":  "error",
            "details": "Error finding this UserID.",
        })
    }

    // Verificar o formato da resposta (JSON ou texto)
    format := c.QueryParam("format")
    if format == "json" {
        return c.JSON(http.StatusOK, map[string]string{
            "result":   "success",
            "username": userDataResult.Username,
            "ticket":   userDataResult.Ticket,
        })
    }

    // Resposta em texto simples
    msgTicket := fmt.Sprintf("Hey, %s! This is your ticket: %s\n", userDataResult.Username, userDataResult.Ticket)
    return c.String(http.StatusOK, msgTicket)
}
