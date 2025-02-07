package api

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"

	jwt "github.com/dgrijalva/jwt-go"
	db "github.com/globocom/secDevLabs/owasp-top10-2021-apps/a2/snake-pro/app/db/mongo"
	"github.com/globocom/secDevLabs/owasp-top10-2021-apps/a2/snake-pro/app/types"
	"github.com/google/uuid"
	"github.com/labstack/echo"
)

// HealthCheck is the heath check function.
func HealthCheck(c echo.Context) error {
	return c.String(http.StatusOK, "WORKING!\n")
}

func Root(c echo.Context) error {
	return c.Redirect(302, "/login")
}

// Função para gerar hash da senha
func HashSenha(senha string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(senha), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// WriteCookie writes a cookie into echo Context
func WriteCookie(c echo.Context, jwt string) error {
	cookie := new(http.Cookie)
	cookie.Name = "sessionIDsnake"
	cookie.Value = jwt
	cookie.Secure = true   //inclusao meiry
	cookie.HttpOnly = true // inclusao meiry
	c.SetCookie(cookie)
	return c.String(http.StatusOK, "")
}

// ReadCookie reads a cookie from echo Context.
func ReadCookie(c echo.Context) (string, error) {
	cookie, err := c.Cookie("sessionIDsnake")
	if err != nil {
		return "", err
	}
	return cookie.Value, err
}

// Register registers a new user into MongoDB.
func Register(c echo.Context) error {

	userData := types.UserData{}
	err := c.Bind(&userData)
	if err != nil {
		// error binding JSON
		return c.JSON(http.StatusBadRequest, map[string]string{"result": "error", "details": "Invalid Input."})
	}

	if userData.Password != userData.RepeatPassword {
		return c.JSON(http.StatusBadRequest, map[string]string{"result": "error", "details": "Passwords do not match."})
	}

	//Gerar o hash antes de salvar no banco
	hashedPassword, err := HashSenha(userData.Password)
	if err != nil {
		log.Println("Erro ao gerar hash da senha:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"result": "error", "details": "Internal server error."})
	}

	// Substituir a senha original pelo hash antes de salvar
	userData.Password = hashedPassword

	newGUID1 := uuid.Must(uuid.NewRandom())
	userData.UserID = newGUID1.String()
	userData.HighestScore = 0

	err = db.RegisterUser(userData)
	if err != nil {
		// could not register this user into MongoDB (or MongoDB err connection)
		return c.JSON(http.StatusInternalServerError, map[string]string{"result": "error", "details": "Error user data2."})
	}

	msgUser := fmt.Sprintf("User %s created!", userData.Username)
	return c.String(http.StatusOK, msgUser)
}

// Login checks MongoDB if this user exists and then returns a JWT session cookie.
func Login(c echo.Context) error {

	loginAttempt := types.LoginAttempt{}
	err := c.Bind(&loginAttempt)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"result": "error", "details": "Error login."})
	}
	// input validation missing! do it later!

	userDataQuery := map[string]interface{}{"username": loginAttempt.Username}
	userDataResult, err := db.GetUserData(userDataQuery)
	if err != nil {
		// could not find this user in MongoDB (or MongoDB err connection)
		return c.JSON(http.StatusForbidden, map[string]string{"result": "error", "details": "Error login."})
	}

	//validPass := pass.CheckPass(userDataResult.Password, loginAttempt.Password)
	//if !validPass {
	// wrong password
	//	return c.JSON(http.StatusForbidden, map[string]string{"result": "error", "details": "Error login."})
	//}

	// comparando a senha fornecida com o hash armazenado
	err = bcrypt.CompareHashAndPassword([]byte(userDataResult.Password), []byte(loginAttempt.Password))
	if err != nil {
		// Se a senha estiver incorreta
		return c.JSON(http.StatusForbidden, map[string]string{"result": "error", "details": "Invalid credentials."})
	}

	// Create token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set claims
	claims := token.Claims.(jwt.MapClaims)
	claims["name"] = userDataResult.Username
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte(os.Getenv("SECRET_KEY")))
	if err != nil {
		log.Println("Error generating token:", err)
		return err
	}

	err = WriteCookie(c, t)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"result": "error", "details": "Error writing cookie."})
	}
	c.Response().Header().Set("Content-type", "text/html")
	messageLogon := fmt.Sprintf("Hello, %s! Welcome to SnakePro", userDataResult.Username)
	// err = c.Redirect(http.StatusFound, "https://www.localhost:10003/game/ranking")
	return c.String(http.StatusOK, messageLogon)
}
