package main

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/globocom/secDevLabs/owasp-top10-2021-apps/a2/snake-pro/app/api"
	"github.com/globocom/secDevLabs/owasp-top10-2021-apps/a2/snake-pro/app/config"
	db "github.com/globocom/secDevLabs/owasp-top10-2021-apps/a2/snake-pro/app/db/mongo"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/spf13/viper"
)

// TemplateRegistry defines the template registry struct
// Ref: https://medium.freecodecamp.org/how-to-setup-a-nested-html-template-in-the-go-echo-web-framework-670f16244bb4
type TemplateRegistry struct {
	templates map[string]*template.Template
}

// Render implement e.Renderer interface
// Ref: https://medium.freecodecamp.org/how-to-setup-a-nested-html-template-in-the-go-echo-web-framework-670f16244bb4
func (t *TemplateRegistry) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	tmpl, ok := t.templates[name]
	if !ok {
		err := errors.New("Template not found -> " + name)
		return err
	}
	return tmpl.ExecuteTemplate(w, "base.html", data)
}

// Função para redirecionar HTTP para HTTPS
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	// Redireciona para HTTPS
	http.Redirect(w, r, "https://localhost:10003"+r.RequestURI, http.StatusMovedPermanently)

}

func main() {
	// Carregando configurações com Viper
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		errorAPI(err)
	}
	if err := viper.Unmarshal(&config.APIconfiguration); err != nil {
		errorAPI(err)
	}

	// Verificando conexão com MongoDB
	if _, err := checkMongoDB(); err != nil {
		fmt.Println("[X] ERRO MONGODB: ", err)
		os.Exit(1)
	}

	// Configuração do Echo
	echoInstance := echo.New()
	echoInstance.HideBanner = true

	// Middleware
	echoInstance.Use(middleware.Logger())
	echoInstance.Use(middleware.Recover())
	echoInstance.Use(middleware.RequestID())

	// Configuração de templates
	templates := map[string]*template.Template{
		"form.html":    template.Must(template.ParseFiles("views/form.html", "views/base.html")),
		"game.html":    template.Must(template.ParseFiles("views/game.html", "views/base.html")),
		"ranking.html": template.Must(template.ParseFiles("views/ranking.html", "views/base.html")),
	}
	echoInstance.Renderer = &TemplateRegistry{templates: templates}

	// Rotas públicas
	echoInstance.GET("/healthcheck", api.HealthCheck)
	echoInstance.POST("/register", api.Register)
	echoInstance.POST("/login", api.Login)
	echoInstance.GET("/login", api.PageLogin)
	echoInstance.GET("/", api.Root)

	// Rotas protegidas com JWT
	r := echoInstance.Group("/game")
	jwtConfig := middleware.JWTConfig{
		TokenLookup: "cookie:sessionIDsnake",
		SigningKey:  []byte(os.Getenv("SECRET_KEY")),
	}
	r.Use(middleware.JWTWithConfig(jwtConfig))
	r.GET("/play", api.PageGame)
	r.GET("/ranking", api.PageRanking)

	// Servidor HTTP para redirecionar para HTTPS
	go func() {
		log.Println("Servidor HTTP rodando em http://localhost:8080, redirecionando para HTTPS")
		if err := http.ListenAndServe(":8080", http.HandlerFunc(redirectToHTTPS)); err != nil {
			log.Fatal("Erro ao iniciar servidor HTTP:", err)
		}
	}()

	// Pegando a porta da API (padrão: 10003)
	APIport := fmt.Sprintf(":%d", getAPIPort())

	// Iniciando o servidor HTTPS corretamente com certificados
	log.Println("Servidor HTTPS rodando em https://localhost" + APIport)
	err := echoInstance.StartTLS(APIport, "cert.pem", "key.pem")
	if err != nil {
		log.Fatal("Erro ao iniciar servidor HTTPS:", err)
	}
}

// Função para tratar erros na inicialização
func errorAPI(err error) {
	fmt.Println("[X] Erro ao iniciar Snake Pro:")
	fmt.Println("[X]", err)
	os.Exit(1)
}

// Obtém a porta da API, padrão 10003 se não definida
func getAPIPort() int {
	apiPort, err := strconv.Atoi(os.Getenv("API_PORT"))
	if err != nil {
		apiPort = 10003
	}
	return apiPort
}

// Verifica conexão com MongoDB
func checkMongoDB() (*db.DB, error) {
	return db.Connect()
}
