package main

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"

	apiContext "github.com/globocom/secDevLabs/owasp-top10-2021-apps/a1/ecommerce-api/app/context"
	"github.com/globocom/secDevLabs/owasp-top10-2021-apps/a1/ecommerce-api/app/handlers"
	"github.com/globocom/secDevLabs/owasp-top10-2021-apps/a1/ecommerce-api/app/db"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/dgrijalva/jwt-go"
)

// TemplateRegistry defines the template registry struct
type TemplateRegistry struct {
	templates map[string]*template.Template
}

// Render implements e.Renderer interface
func (t *TemplateRegistry) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	tmpl, ok := t.templates[name]
	if !ok {
		return fmt.Errorf("template not found: %s", name)
	}
	return tmpl.ExecuteTemplate(w, "base.html", data)
}

// Middleware: Checks if a user is authorized for a specific ticket
func isAuthorized(dbInstance *db.DB) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user, ok := c.Get("user").(*jwt.Token)
			if !ok {
				return echo.ErrUnauthorized
			}

			claims, ok := user.Claims.(jwt.MapClaims)
			if !ok {
				return echo.ErrUnauthorized
			}

			userID := claims["id"]
			ticketID := c.Param("id")
			if !userHasAccessToTicket(dbInstance, fmt.Sprintf("%v", userID), ticketID) {
				return echo.ErrUnauthorized
			}

			return next(c)
		}
	}
}

// Checks if a user has access to a specific ticket
func userHasAccessToTicket(dbInstance *db.DB, userID, ticketID string) bool {
	hasPermission, err := dbInstance.CheckUserPermission(userID, ticketID)
	if err != nil {
		return false
	}
	return hasPermission
}

// Middleware: Auth checks JWT token
func AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := c.Request().Header.Get("Authorization")
		if token == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		}

		_, err := parseToken(token)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
		}

		c.Set("userID", "exampleUserID") // Exemplo simples
		return next(c)
	}
}

// Simulated token parser
func parseToken(token string) (string, error) {
	if token == "valid-token" {
		return "user123", nil
	}
	return "", errors.New("invalid token")
}

func main() {
	configAPI := apiContext.GetAPIConfig()

	if err := checkRequirements(configAPI); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Inicializa conexão com o banco de dados
	database, err := db.Connect()
	if err != nil {
		fmt.Printf("Erro ao conectar ao banco de dados: %v\n", err)
		os.Exit(1)
	}
	defer database.Session.Close()

	echoInstance := echo.New()
	echoInstance.HideBanner = true

	templates := make(map[string]*template.Template)
	templates["form.html"] = template.Must(template.ParseFiles("views/form.html", "views/base.html"))
	echoInstance.Renderer = &TemplateRegistry{templates: templates}

	echoInstance.Use(middleware.Logger())
	echoInstance.Use(middleware.Recover())
	echoInstance.Use(middleware.RequestID())

	echoInstance.GET("/", handlers.FormPage)
	echoInstance.GET("/healthcheck", handlers.HealthCheck)
	echoInstance.POST("/register", handlers.RegisterUser)
	echoInstance.POST("/login", handlers.Login)

	ticketGroup := echoInstance.Group("/ticket")
	ticketGroup.Use(isAuthorized(database))
	ticketGroup.GET("/:id", handlers.GetTicket)

	APIport := fmt.Sprintf(":%d", configAPI.APIPort)
	echoInstance.Logger.Fatal(echoInstance.Start(APIport))
}

func checkRequirements(configAPI *apiContext.APIConfig) error {
	if err := checkEnvVars(); err != nil {
		return err
	}
	if err := checkMongoDB(); err != nil {
		return err
	}
	return nil
}

func checkEnvVars() error {
	envVars := []string{
		"MONGO_HOST",
		"MONGO_DATABASE_NAME",
		"MONGO_DATABASE_USERNAME",
		"MONGO_DATABASE_PASSWORD",
	}

	var missingVars []string
	for _, v := range envVars {
		if _, exists := os.LookupEnv(v); !exists {
			missingVars = append(missingVars, v)
		}
	}

	if len(missingVars) > 0 {
		return fmt.Errorf("missing environment variables: %v", missingVars)
	}

	return nil
}

func checkMongoDB() error {
	_, err := db.Connect()
	if err != nil {
		return fmt.Errorf("check MongoDB: %v", err)
	}
	return nil
}
