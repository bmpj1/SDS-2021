package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"text/template"
	"time"

	"golang.org/x/crypto/scrypt"
)

type user struct {
	Name   string `json:"Name"`   // nombre de usuario
	Prikey string `json:"Prikey"` // sal para la contraseña
	Pubkey string `json:"Pubkey"` // sal para la contraseña
	Hash   []byte `json:"Hash"`   // hash de la contraseña
	Salt   []byte `json:"Salt"`   // sal para la contraseña
}

type entrada struct {
	Text string
	Date time.Time
}

type tema struct {
	Id        int                `json:"Id"`   // Nombre del tema
	Usuario   string             `json:"User"` // propietario del tema
	Name      string             `json:"Name"` // Nombre del tema
	Tipo      string             `json:"Tipo"` // Tipo de tema (Publico / privado)
	Entradas  map[string]entrada // Entradas de un tema tema
	Bloqueado bool               `json:"Bloqueado"` // estado del tema
}

type resp struct {
	Ok     bool   // true -> correcto, false -> error
	Msg    string // mensaje adicional
	Pubkey string
	Prikey string
}

type respTemas struct {
	Ok    bool            // true -> correcto, false -> error
	Msg   string          // mensaje adicional
	Temas map[string]tema //
}

var users = map[string]user{}
var temas = map[string]tema{}
var tokens = map[string]string{}

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// Guardamos los usuarios en la db de usuarios
func saveData(username string) {
	jsonString, err := json.Marshal(users)
	if err != nil {
		delete(users, username)
		panic(err)
	}
	ioutil.WriteFile("./db/usuarios.json", jsonString, 0644)
}

// Guardamos los temas en la db de temas
func saveTemaData() {
	jsonString, err := json.Marshal(temas)
	chk(err)
	ioutil.WriteFile("./db/temas.json", jsonString, 0644)
}

/**
* Codificamos en JSON una estructura cualquiera y
* devolvemos codificado el JSON en base64
 */
func codifyStructToJSONBase64(structure interface{}) string {
	//codificamos en JSON
	respJSON, err := json.Marshal(&structure)
	chk(err)
	//codificamos en base64 para que no dé problemas
	response := base64.StdEncoding.EncodeToString(respJSON)
	return response
}

func sendToClient(w http.ResponseWriter, structure interface{}) {
	_, _ = w.Write([]byte(codifyStructToJSONBase64(structure))) // escribimos el JSON resultante
	return
}

// Comprobar si un usuario existe en la db
func checkExist(req *http.Request) (bool, string) {
	_, ok := users[req.Form.Get("user")] // obtengo todos los usuarios y mapeo el usuario en concreto segun su login

	if ok { // ¿existe ya el usuario?
		return false, "Usuario ya registrado"
	} else {
		return true, "Usuario registrado correctamente"
	}
}

// Registrar un usuario en la db
func registerUser(w http.ResponseWriter, req *http.Request) {
	res, msg := checkExist(req)
	if res {
		//fmt.Println("password: " + decode64(req.Form.Get("pass")))
		u := user{}
		u.Name = req.Form.Get("user")              // nombre
		u.Salt = make([]byte, 16)                  // sal (16 bytes == 128 bits)
		rand.Read(u.Salt)                          // la sal es aleatoria
		password := decode64(req.Form.Get("pass")) // contraseña (keyLogin)
		// "hasheamos" la contraseña con scrypt
		u.Hash, _ = scrypt.Key(password, u.Salt, 16384, 8, 1, 32)
		u.Prikey = req.Form.Get("prikey")
		u.Pubkey = req.Form.Get("pubkey")
		users[u.Name] = u

		saveData(u.Name)
	}
	response := resp{Ok: res, Msg: msg}
	sendToClient(w, response)
}

func createTema(w http.ResponseWriter, req *http.Request) {
	//fmt.Println("estoy creando un tema...")

	t := tema{}
	t.Name = req.Form.Get("Name") // nombre
	t.Tipo = req.Form.Get("Tipo") // Tipo de visibilidad: publica o privada
	t.Entradas = make(map[string]entrada)
	t.Bloqueado = false
	t.Usuario = req.Form.Get("Usuario")
	t.Id = len(temas)
	fmt.Println("Nombre del tema: " + t.Name + " Tipo de tema: " + t.Tipo)

	temas[strconv.Itoa(t.Id)] = t

	saveTemaData()
	response := resp{Ok: true, Msg: "Tema creado correctamente."}
	sendToClient(w, response)
}

func crearEntrada(w http.ResponseWriter, req *http.Request) {
	//fmt.Println("estoy creando una entrada para un tema...")
	fmt.Println("\nCREANDO ENDTRADA!\n")
	e := entrada{}
	e.Text = req.Form.Get("Text") // nombre
	e.Date = time.Now()           // Tipo de visibilidad: publica o privada

	fmt.Println("Tema:" + req.Form.Get("Id") + "  ---- Texto de la entrada: " + e.Text + " ---- Fecha: " + e.Date.String())
	fmt.Println(temas)
	var idEntrada = strconv.Itoa(len(temas[req.Form.Get("Id")].Entradas))
	temas[req.Form.Get("Id")].Entradas[idEntrada] = e

	saveTemaData()
	response := resp{Ok: true, Msg: "Entrada creada correctamente."}
	sendToClient(w, response)
}

func generateToken() string {
	alphanum := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var token = make([]byte, 16)
	rand.Read(token)
	for i, b := range token {
		token[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(token)
}

// Validar el login
func checkUser(req *http.Request) (bool, string, string, string) {
	u, ok := users[req.Form.Get("user")] // obtengo todos los usuarios y mapeo el usuario en concreto segun su login

	if !ok { // ¿existe ya el usuario?
		return false, "Usuario inexistente", "", ""
	}

	password := decode64(req.Form.Get("pass"))

	// obtenemos la contraseña
	hash, _ := scrypt.Key(password, u.Salt, 16384, 8, 1, 32) // scrypt(contraseña)
	pubkey := u.Pubkey
	prikey := u.Prikey

	if bytes.Compare(u.Hash, hash) != 0 { // comparamos
		return false, "Credenciales inválidas", "", ""
	}
	token := generateToken()
	tokens[u.Name] = token
	return true, token, pubkey, prikey
}

func listarTemas(w http.ResponseWriter, req *http.Request) {
	rawTemas, err := ioutil.ReadFile("./db/temas.json")
	chk(err)
	_ = json.Unmarshal(rawTemas, &temas)

	response := respTemas{Ok: true, Msg: "Lista de Temas obtenida", Temas: temas}
	sendToClient(w, response)
}

func loginUser(w http.ResponseWriter, req *http.Request) {
	res, msg, pubkey, prikey := checkUser(req)
	response := resp{Ok: res, Msg: msg, Pubkey: pubkey, Prikey: prikey}
	sendToClient(w, response)
}

// Validar el token de un usuario logueado
func checkToken(token, username string, w http.ResponseWriter) bool {
	if token == tokens[username] {
		return true
	} else {
		response := resp{Ok: false, Msg: "Token no válido"}
		sendToClient(w, response)
		fmt.Println("token no valido")
		return false
	}
}
func handler(w http.ResponseWriter, req *http.Request) {
	_ = req.ParseForm()                          // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar
	switch req.Form.Get("cmd") {                 // comprobamos comando desde el cliente
	case "register":
		registerUser(w, req)
	case "login":
		loginUser(w, req)
	case "crearTema":
		if checkToken(req.Form.Get("token"), req.Form.Get("Usuario"), w) {
			createTema(w, req)
		}
	case "crearEntrada":
		if checkToken(req.Form.Get("token"), req.Form.Get("user"), w) {
			crearEntrada(w, req)
		}
	case "listarTemas":
		if checkToken(req.Form.Get("token"), req.Form.Get("user"), w) {
			listarTemas(w, req)
		}
	default:
		response(w, false, "Comando invalido")
	}

}

func server() {
	rawUsers, err := ioutil.ReadFile("./db/usuarios.json")
	chk(err)
	rawTemas, err := ioutil.ReadFile("./db/temas.json")
	chk(err)
	_ = json.Unmarshal(rawUsers, &users)
	_ = json.Unmarshal(rawTemas, &temas)

	stopChan := make(chan os.Signal)
	log.Println("Escuchando en: https://127.0.0.1:10443 ... ")
	signal.Notify(stopChan, os.Interrupt)
	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(handler))

	go func() {
		if err := http.ListenAndServeTLS(":10443", "cert.pem", "key.pem", mux); err != nil {
			log.Printf("listen: %s\n", err)
		}
	}()
	<-stopChan
	log.Println("Apagando servidor ...")
	log.Println("Servidor detenido correctamente")
}

func response(w io.Writer, ok bool, msg string) {
	r := resp{Ok: ok, Msg: msg}    // formateamos respuesta
	rJSON, err := json.Marshal(&r) // codificamos en JSON
	chk(err)                       // comprobamos error
	w.Write(rJSON)                 // escribimos el JSON resultante
}

func home(w http.ResponseWriter, req *http.Request) {
	//render(w, "../html/home.html", nil)
	//render(w, "Conexion establecida ...", nil)
	response(w, true, "Conexion establecida")
}

// Funcion que lee un archivo
func render(w http.ResponseWriter, filename string, data interface{}) {
	tmpl, err := template.ParseFiles(filename)
	if err != nil {
		log.Println(err)
		http.Error(w, "Sorry, something went wrong", http.StatusInternalServerError)
	}

	if err := tmpl.Execute(w, data); err != nil {
		log.Println(err)
		http.Error(w, "Sorry, something went wrong", http.StatusInternalServerError)
	}
}
func main() {
	server()
}
