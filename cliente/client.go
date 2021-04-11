package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/zserge/lorca"
)

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

// función para comprimir
func compress(data []byte) []byte {
	var b bytes.Buffer      // b contendrá los datos comprimidos (tamaño variable)
	w := zlib.NewWriter(&b) // escritor que comprime sobre b
	w.Write(data)           // escribimos los datos
	w.Close()               // cerramos el escritor (buffering)
	return b.Bytes()        // devolvemos los datos comprimidos
}

// función para descomprimir
func decompress(data []byte) []byte {
	var b bytes.Buffer // b contendrá los datos descomprimidos

	r, err := zlib.NewReader(bytes.NewReader(data)) // lector descomprime al leer

	chk(err)         // comprobamos el error
	io.Copy(&b, r)   // copiamos del descompresor (r) al buffer (b)
	r.Close()        // cerramos el lector (buffering)
	return b.Bytes() // devolvemos los datos descomprimidos
}

// función para cifrar (con AES en este caso), adjunta el IV al principio
func encrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)    // reservamos espacio para el IV al principio
	rand.Read(out[:16])                 // generamos el IV
	blk, err := aes.NewCipher(key)      // cifrador en bloque (AES), usa key
	chk(err)                            // comprobamos el error
	ctr := cipher.NewCTR(blk, out[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out[16:], data)    // ciframos los datos
	return
}

// función para descifrar (con AES en este caso)
func decrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)-16)     // la salida no va a tener el IV
	blk, err := aes.NewCipher(key)       // cifrador en bloque (AES), usa key
	chk(err)                             // comprobamos el error
	ctr := cipher.NewCTR(blk, data[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out, data[16:])     // desciframos (doble cifrado) los datos
	return
}

type respTemas struct {
	Ok    bool            // true -> correcto, false -> error
	Msg   string          // mensaje adicional
	Temas map[string]tema //
}
type tema struct {
	Name     string             `json:"Name"` // Nombre del tema
	Tipo     string             `json:"Tipo"` // Tipo de tema (Publico / privado)
	Entradas map[string]entrada // Entradas de un tema tema
}
type entrada struct {
	Text string
	Date time.Time
}
type uiState struct {
	ui       lorca.UI
	listType string
}

// respuesta del servidor
type resp struct {
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
}
type User struct {
	username string
	token    string
}

var loggedUser User
var cipherKey []byte

func client() {
	/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte("contraseña del cliente"))
	keyData := keyClient[:32] // la otra para los datos (256 bits)

	// generamos un par de claves (privada, pública) para el servidor
	pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	chk(err)
	pkClient.Precompute() // aceleramos su uso con un precálculo

	pkJSON, err := json.Marshal(&pkClient) // codificamos con JSON
	chk(err)

	keyPub := pkClient.Public()           // extraemos la clave pública por separado
	pubJSON, err := json.Marshal(&keyPub) // y codificamos con JSON
	chk(err)

	// ** ejemplo de registro
	data := url.Values{} // estructura para contener los valores
	// comprimimos y codificamos la clave pública
	data.Set("pubkey", encode64(compress(pubJSON)))
	// comprimimos, ciframos y codificamos la clave privada
	data.Set("prikey", encode64(encrypt(compress(pkJSON), keyData)))

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
}

// Para cargar los HTML
func (uiState *uiState) loadFile(filename string) {
	// Load HTML.
	b, err := ioutil.ReadFile(filename) // just pass the copia name
	if err != nil {
		fmt.Print(err)
	}
	html := string(b) // convert content to a 'string'
	_ = uiState.ui.Load("data:text/html," + url.PathEscape(html))
}

// Para mandar las peticiones al servidor
func sendToServer(data url.Values) []byte {
	data.Set("user", loggedUser.username) // usuario (string)
	data.Set("token", loggedUser.token)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	petition, err := client.PostForm("https://localhost:10443", data)
	chk(err)
	response, err := ioutil.ReadAll(petition.Body)
	chk(err)

	response = decode64(string(response))

	return response
}

// Para asociar las funciones al html del login
func (uiState *uiState) Login(usuario, password string) {
	keyClient := sha512.Sum512([]byte(password))
	keyLogin := keyClient[:32]   // una mitad para el login (256 bits)
	cipherKey = keyClient[32:64] // Para cifrar
	data := url.Values{}         // estructura para contener los valores

	data.Set("cmd", "login")
	data.Set("user", usuario) // usuario (string)
	data.Set("pass", encode64(keyLogin))
	loggedUser.username = usuario
	jsonResponse := sendToServer(data)
	var response resp
	err := json.Unmarshal(jsonResponse, &response)
	chk(err)

	if response.Ok {
		loggedUser.token = response.Msg
		uiState.renderMenuPage()
		//uiState.ui.Eval(`$("#errorMessage").text("Todo OK!")`)
	} else {
		uiState.ui.Eval(`$("#errorMessage").text("Usuario o contraseña incorrectos")`)
	}

}

func (uiState *uiState) getTemas() {
	data := url.Values{}
	data.Set("cmd", "listar")
	jsonResponse := sendToServer(data)
	var response respTemas
	err := json.Unmarshal(jsonResponse, &response)
	chk(err)
	temas = response.Temas
	if response.Ok {
		for key, _ := range response.Temas {
			//fmt.Println("Key:", key)
			uiState.ui.Eval(fmt.Sprintf(`$("#getTemas").append('<li class="mt-2">%v <button class="btn btn-primary" id="%v">Acceder</button></li>');`, key, key))
			//uiState.ui.Eval(fmt.Sprintf((`seevswev`), key, key))
		}
	} else {
		//TODO SHOW THE ERROR IN UI
	}
}

// Para asociar la funcion de registro al html
func (uiState *uiState) register(usuario, password string) {
	keyClient := sha512.Sum512([]byte(password))
	keyLogin := keyClient[:32]   // una mitad para el login (256 bits)
	cipherKey = keyClient[32:64] // Para cifrar
	data := url.Values{}         // estructura para contener los valores

	data.Set("cmd", "register")
	data.Set("user", usuario) // usuario (string)
	data.Set("pass", encode64(keyLogin))
	loggedUser.username = usuario
	jsonResponse := sendToServer(data)
	var response resp
	err := json.Unmarshal(jsonResponse, &response)
	chk(err)
	fmt.Println(usuario + password)
	if response.Ok {
		loggedUser.token = response.Msg
		uiState.ui.Eval(fmt.Sprintf(`alert("Usuario creado correctamente.")`))
		uiState.renderLogin()
	} else {
		uiState.ui.Eval(`$("#errorMessage").text("Error en el registro")`)
	}

}

// Para asociar la funcion de crear tema al html
func (uiState *uiState) crearTema(Name, Tipo string) {
	data := url.Values{} // estructura para contener los valores
	data.Set("cmd", "crear")
	data.Set("Name", Name)
	data.Set("Tipo", Tipo)

	jsonResponse := sendToServer(data)
	var response resp
	err := json.Unmarshal(jsonResponse, &response)
	chk(err)
	if response.Ok {
		uiState.ui.Eval(fmt.Sprintf(`alert("Tema creado correctamente.")`))
		uiState.renderMenuPage()
	} else {
		uiState.ui.Eval(`$("#errorMessage").text("Error en publicar un tema")`)
	}
}

func (uiState *uiState) renderRegister() {
	fmt.Println("entro a renderRegister")
	uiState.loadFile("./www/registro.html")
	_ = uiState.ui.Bind("submitRegister", uiState.register)
}

func (uiState *uiState) renderLogin() {
	uiState.loadFile("./www/index.html")
	_ = uiState.ui.Bind("submitLogin", uiState.Login)
	_ = uiState.ui.Bind("registerPage", uiState.renderRegister)
}

func (uiState *uiState) renderCrearTema() {
	uiState.loadFile("./www/crearTema.html")
	_ = uiState.ui.Bind("crearTema", uiState.crearTema)
}
func (uiState *uiState) renderMenuPage() {
	uiState.loadFile("./www/menu.html")
	_ = uiState.ui.Bind("crearTema", uiState.renderCrearTema)
	_ = uiState.ui.Bind("listarTemas", uiState.renderListaTemas)
	_ = uiState.ui.Bind("backMenuPage", uiState.renderMenuPage)
}
func (uiState *uiState) renderListaTemas() {
	uiState.loadFile("./www/listarTemas.html")
	_ = uiState.ui.Bind("start", uiState.getTemas)
	_ = uiState.ui.Bind("backMenuPage", uiState.renderMenuPage)
}

func main() {
	var args []string
	if runtime.GOOS == "linux" {
		args = append(args, "--class=Lorca")
	}
	ui, err := lorca.New("", "", 480, 320, args...)
	if err != nil {
		log.Fatal(err)
	}
	defer ui.Close()

	state := &uiState{ui: ui}

	state.renderLogin()

	// Wait until the interrupt signal arrives or browser window is closed
	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)
	select {
	case <-sigc:
	case <-ui.Done():
	}

	log.Println("exiting...")
	//client()
}
