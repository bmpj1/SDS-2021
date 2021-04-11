package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/jasonlvhit/gocron"
	"github.com/pierrre/archivefile/zip"

	"github.com/zserge/lorca"
)

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
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

// función para comprimir
func compress(path string) []byte {
	var b bytes.Buffer // b contendrá los datos comprimidos (tamaño variable)
	err := zip.Archive(path, &b, nil)
	chk(err)
	return b.Bytes() // devolvemos los datos comprimidos
}

// función para descomprimir
func decompress(data []byte) { //TODO change to zip library
	b := bytes.NewReader(data)

	err := zip.Unarchive(b, int64(binary.Size(data)), "./temp/", nil)
	chk(err)
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

type version struct {
	Name string
	Date time.Time
}

type copia struct {
	//Path string
	Type     string
	Versions map[int]version
}

type respCopias struct {
	Ok     bool // true -> correcto, false -> error
	Copias map[string]copia
	Msg    string // mensaje adicional

}

type respCopia struct {
	Ok    bool
	Msg   string
	Copia copia
}

type respVersion struct {
	Ok      bool
	Msg     string
	Content string
}

// respuesta del servidor
type resp struct {
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
}

type uiState struct {
	ui       lorca.UI
	listType string
}

func (uiState *uiState) loadFile(filename string) {
	// Load HTML.
	b, err := ioutil.ReadFile(filename) // just pass the copia name
	if err != nil {
		fmt.Print(err)
	}
	html := string(b) // convert content to a 'string'
	_ = uiState.ui.Load("data:text/html," + url.PathEscape(html))
}

type User struct {
	username string
	token    string
}

var loggedUser User
var cipherKey []byte

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
	} else {
		uiState.ui.Eval(`$("#errorMessage").text("Usuario o contraseña incorrectos")`)
	}

}

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

func (uiState *uiState) renderMenuPage() {
	uiState.loadFile("./www/menu.html")
	_ = uiState.ui.Bind("listarCopias", uiState.renderListaCopias)

	_ = uiState.ui.Bind("crearCopia", uiState.renderCrearCopia)
}

func (uiState *uiState) getCopias() {
	data := url.Values{}
	data.Set("cmd", "listar")
	data.Set("type", uiState.listType)
	jsonResponse := sendToServer(data)
	var response respCopias
	err := json.Unmarshal(jsonResponse, &response)
	chk(err)
	if response.Ok {
		fmt.Println(response.Copias)
		for key, _ := range response.Copias {
			//fmt.Println("Key:", key, "Value:", value.Path)
			uiState.ui.Eval(fmt.Sprintf(`$("#list").append('<li class="mt-2">%v <button class="btn btn-primary" id="%v">Mostrar Versiones</button></li>');`, key, key))
		}
	} else {
		//TODO SHOW THE ERROR IN UI
	}
}

func (uiState *uiState) recuperarVersion(version string) {
	data := url.Values{}
	data.Set("cmd", "recuperar")
	data.Set("path", uiState.listType)
	data.Set("version", version)
	jsonResponse := sendToServer(data)
	var response respVersion
	err := json.Unmarshal(jsonResponse, &response)
	chk(err)

	if response.Ok {
		decryptedContent := decrypt(decode64(response.Content), cipherKey)
		decompress(decryptedContent)
	} else {
		//TODO SHOW MESSAGE ERROR IN UI
	}
}

func (uiState *uiState) getVersiones() {
	data := url.Values{}
	data.Set("cmd", "versiones")
	data.Set("path", uiState.listType)
	jsonResponse := sendToServer(data)
	var response respCopia
	err := json.Unmarshal(jsonResponse, &response)
	chk(err)

	if response.Ok {
		for key, value := range response.Copia.Versions {
			fmt.Println("Key:", key, "Value:", value.Date)
			uiState.ui.Eval(fmt.Sprintf(`$("#list").append('<li class="mt-2">%v - %v <button class="btn btn-primary" id="%v">Recuperar</button></li>')`, key, value.Date, key))
		}
	} else {
		//TODO SHOW ERROR IN UI
	}
}

func (uiState *uiState) renderListaVersiones(copiaPath string) {
	uiState.listType = copiaPath
	uiState.loadFile("./www/listaVersiones.html")
	_ = uiState.ui.Bind("start", uiState.getVersiones)
	_ = uiState.ui.Bind("recuperarVersion", uiState.recuperarVersion)
}

func (uiState *uiState) renderListaCopias(copiaType string) {
	uiState.listType = copiaType
	uiState.loadFile("./www/listaCopias.html")
	_ = uiState.ui.Bind("start", uiState.getCopias)
	_ = uiState.ui.Bind("getVersiones", uiState.renderListaVersiones)
	_ = uiState.ui.Bind("backMenuPage", uiState.renderMenuPage)
}

func (uiState *uiState) renderCrearCopia() {
	uiState.loadFile("./www/crearCopia.html")
	_ = uiState.ui.Bind("crearCopia", uiState.crearCopia)
	_ = uiState.ui.Bind("backMenuPage", uiState.renderMenuPage)
}

// Crea una copia completa del contenido de una carpeta proporcionada por el filepath
func crearCopiaTask(filePath, copiaType string) resp {
	var compressedContent []byte
	//if copiaType == "completa" {
	compressedContent = compress(filePath)
	/*} else if copiaType == "diferencial" {

	} else if copiaType == "incremental" {

	}*/
	var encryptedContent = encrypt(compressedContent, cipherKey)
	data := url.Values{} // estructura para contener los valores
	data.Set("cmd", "crear")
	data.Set("path", filePath)
	data.Set("type", copiaType)
	data.Set("content", encode64(encryptedContent))
	jsonResponse := sendToServer(data)
	var response resp
	//Des-serializamos el json a la estructura creada
	err := json.Unmarshal(jsonResponse, &response)
	chk(err)

	return response
}

func executeCopiaTask(filePath, time, copiaType string) {
	switch time {
	case "diaria":
		err := gocron.Every(1).Day().Do(crearCopiaTask, filePath, copiaType)
		chk(err)
		<-gocron.Start()
	case "semanal":
		err := gocron.Every(1).Week().Do(crearCopiaTask, filePath, copiaType)
		chk(err)
		<-gocron.Start()
	}
}

func (uiState *uiState) crearCopia(filePath, time, copiaType string) {

	response := crearCopiaTask(filePath, copiaType)
	if response.Ok {
		go executeCopiaTask(filePath, time, copiaType)
		uiState.renderMenuPage()
	} else {
		uiState.ui.Eval(`$("#errorMessage").text(${response.Msg})`)
	}
}

func sendToServer(data url.Values) []byte {
	data.Set("user", loggedUser.username) // usuario (string)
	data.Set("token", loggedUser.token)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	petition, err := client.PostForm("https://localhost:8081", data)
	chk(err)
	response, err := ioutil.ReadAll(petition.Body)
	chk(err)
	//Paso más, pasamos a JSON simple, decodificamos JSON base 64
	response = decode64(string(response))

	return response
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

}
