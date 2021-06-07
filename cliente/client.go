package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	"strings"
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
	KeyTema   string             `json:"KeyTema"` // clave para cifrar tema
	Id        int                `json:"Id"`      // Nombre del tema
	Usuario   string             `json:"User"`    // propietario del tema
	Name      string             `json:"Name"`    // Nombre del tema
	Tipo      string             `json:"Tipo"`    // Tipo de tema (Publico / privado)
	Entradas  map[string]entrada // Entradas de un tema tema
	Bloqueado bool               `json:"Bloqueado"` // estado del tema
}
type entrada struct {
	Username string
	Text     string
	Date     time.Time
}
type uiState struct {
	ui       lorca.UI
	listType string
}

type User struct {
	username string
	token    string
	pubkey   rsa.PublicKey
	prikey   rsa.PrivateKey
}

// respuesta del servidor
type resp struct {
	Ok     bool   // true -> correcto, false -> error
	Msg    string // mensaje adicional
	Pubkey string
	Prikey string
}

var idTema string
var tipoVisibilidad string
var temas respTemas
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
	//data.Set("user", loggedUser.username) // usuario (string)
	//data.Set("token", loggedUser.token)
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

// Para asociar la funcion de registro al html
func (uiState *uiState) register(username, password string) {

	// cifrar el password
	keyClient := sha512.Sum512([]byte(password))
	keyRegister := keyClient[:32] // una mitad para el login (256 bits)
	cipherKey = keyClient[32:64]  // Para cifrar

	// generamos un par de claves (privada, pública) para el servidor
	pkClient, err := rsa.GenerateKey(rand.Reader, 2048)
	chk(err)
	pkClient.Precompute() // aceleramos su uso con un precálculo

	pkJSON, err := json.Marshal(&pkClient) // codificamos con JSON
	chk(err)

	keyPub := pkClient.Public()           // extraemos la clave pública por separado
	pubJSON, err := json.Marshal(&keyPub) // y codificamos con JSON
	chk(err)

	data := url.Values{} // estructura para contener los valores
	data.Set("cmd", "register")
	data.Set("user", (encode64([]byte(username)))) // usuario (string)
	data.Set("pass", encode64(keyRegister))
	data.Set("pubkey", encode64(compress(pubJSON)))
	data.Set("prikey", encode64(encrypt(compress(pkJSON), cipherKey)))

	loggedUser.username = username
	jsonResponse := sendToServer(data)
	var response resp
	err = json.Unmarshal(jsonResponse, &response)
	chk(err)
	//fmt.Println(usuario + password)
	if response.Ok {
		loggedUser.token = response.Msg
		uiState.ui.Eval(fmt.Sprintf(`alert("Usuario creado correctamente.")`))
		uiState.renderLogin()
	} else {
		uiState.ui.Eval(fmt.Sprintf(`alert("Error en el registro")`))
	}
}

// Para asociar las funciones al html del login
func (uiState *uiState) Login(usuario, password string) {
	// cifrar el password
	keyClient := sha512.Sum512([]byte(password))
	keyLogin := keyClient[:32]   // una mitad para el login (256 bits)
	cipherKey = keyClient[32:64] // Para cifrar

	data := url.Values{} // estructura para contener los valores

	data.Set("cmd", "login")
	data.Set("user", (encode64([]byte(usuario)))) // usuario (string)
	data.Set("pass", encode64(keyLogin))

	jsonResponse := sendToServer(data)
	var response resp
	err := json.Unmarshal(jsonResponse, &response)
	chk(err)

	if response.Ok {
		_ = json.Unmarshal(decompress(decode64(response.Pubkey)), &loggedUser.pubkey)
		_ = json.Unmarshal(decompress(decrypt(decode64(response.Prikey), cipherKey)), &loggedUser.prikey)
		//fmt.Println(loggedUser.prikey)

		loggedUser.username = encode64([]byte(usuario))
		loggedUser.token = response.Msg

		uiState.renderMenuPage()
	} else {
		uiState.ui.Eval(`alert("Usuario o contraseña incorrectos")`)
	}
}

func RSA_OAEP_Encrypt(secretMessage string, key rsa.PublicKey) string {
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &key, []byte(secretMessage), label)
	chk(err)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func RSA_OAEP_Decrypt(cipherText string, privKey rsa.PrivateKey) string {
	ct, _ := base64.StdEncoding.DecodeString(cipherText)
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &privKey, ct, label)
	if err != nil {
		return string("")
	}
	return string(plaintext)
}

func (uiState *uiState) getTemas() {
	data := url.Values{}
	data.Set("cmd", "listarTemas")
	jsonResponse := sendToServer(data)
	err := json.Unmarshal(jsonResponse, &temas)
	chk(err)

	if temas.Ok {
		if tipoVisibilidad == "privada" {
			uiState.ui.Eval(`document.getElementById("alterListType").value = "Ver Publicos"`)
		} else {
			uiState.ui.Eval(`document.getElementById("alterListType").value = "Ver Privados"`)
		}
		uiState.ui.Eval(`$("#getTemas").empty()`) // Limpiamos la lista para asegurar que siempre está vacia antes de llenarla con datos...
		for key, estructura := range temas.Temas {
			//fmt.Println("\nKey(nombre del tema):", string(decrypt(decode64(estructura.Name), decode64(estructura.KeyTema))), " Id: ", key, " ---- Entradas del tema: ", estructura.Entradas)
			//fmt.Println("id = " + key)
			var nombre string
			var tipo string
			if len(estructura.KeyTema) == 44 && tipoVisibilidad == "publica" { // publica
				nombre = string(decrypt(decode64(estructura.Name), decode64(estructura.KeyTema)))
				tipo = string(decrypt(decode64(estructura.Tipo), decode64(estructura.KeyTema)))

				if tipo == tipoVisibilidad {
					uiState.ui.Eval(fmt.Sprintf(`$("#getTemas").append('<button type="button" class="btn btn-secondary" id="%v" onClick="verTema(this)" >%v</button>');`, key, nombre))
				}
			} else if len(estructura.KeyTema) != 44 && tipoVisibilidad == "privada" { // privada
				split := strings.Split(estructura.KeyTema, " ")
				for key := range split {
					if split[key] != "" { // split[key] almacena la key del tema encriptada con la clave publica del usuario
						temaKey := RSA_OAEP_Decrypt(split[key], loggedUser.prikey)
						if temaKey != "" {
							nombre = string(decrypt(decode64(estructura.Name), []byte(temaKey)))
							tipo = string(decrypt(decode64(estructura.Tipo), []byte(temaKey)))

							if tipo == tipoVisibilidad {
								uiState.ui.Eval(fmt.Sprintf(`$("#getTemas").append('<button type="button" class="btn btn-secondary" id="%v" onClick="verTema(this)" >%v</button>');`, estructura.Id, nombre))
							}
						}

					}
				}
			}
		}
	} else {
		//TODO SHOW THE ERROR IN UI
	}
}

func (uiState *uiState) getEntradas() {
	var tipo string
	if temas.Ok {
		uiState.ui.Eval(`$("#getEntradas").empty()`) // Limpiamos la lista para asegurar que siempre está vacia antes de llenarla con datos...
		if tipoVisibilidad == "publica" {            // publica
			tipo = string(decrypt(decode64(temas.Temas[idTema].Tipo), decode64(temas.Temas[idTema].KeyTema)))
			if tipo == tipoVisibilidad {
				//fmt.Println("GET PUB TIPO: ", tipo)
				for entrada := range temas.Temas[idTema].Entradas {
					text := string(decode64(temas.Temas[idTema].Entradas[entrada].Text))
					username := string(decode64(temas.Temas[idTema].Entradas[entrada].Username))
					//fmt.Println("TU TEXTO" + estructura.Entradas[entrada].Text)
					date := temas.Temas[idTema].Entradas[entrada].Date
					//alertMessage := string(decode64(estructura.Usuario))
					//fmt.Println(alertMessage)

					uiState.ui.Eval(fmt.Sprintf(`$("#getEntradas").append('<div class="comment mt-4 text-justify col-12"><h4>Usuario: %v</h4><span>Texto: %v</span><br><p>Fecha: %v</p><hr/></div>');`, username, text, date))
				}
			}
		} else if tipoVisibilidad == "privada" { // privada
			split := strings.Split(temas.Temas[idTema].KeyTema, " ")
			for key := range split {
				if split[key] != "" {
					temaKey := RSA_OAEP_Decrypt(split[key], loggedUser.prikey)
					if temaKey != "" {
						tipo = string(decrypt(decode64(temas.Temas[idTema].Tipo), []byte(temaKey)))
						//fmt.Println("GET PRI TIPO: ", tipo)
						if tipo == tipoVisibilidad {
							for entrada := range temas.Temas[idTema].Entradas {
								text := string(decrypt(decode64(temas.Temas[idTema].Entradas[entrada].Text), []byte(temaKey)))
								username := string(decode64(temas.Temas[idTema].Entradas[entrada].Username))
								//fmt.Println("TU TEXTO" + estructura.Entradas[entrada].Text)
								date := temas.Temas[idTema].Entradas[entrada].Date
								uiState.ui.Eval(fmt.Sprintf(`$("#getEntradas").append('<div class="comment mt-4 text-justify col-12"><h4>Usuario: %v</h4><span>Texto: %v</span><br><p>Fecha: %v</p><hr/></div>');`, username, text, date))
							}
						}
					}
				}
			}
		}
	}
}

func getUsersPubKey(usuarios string) string {
	data := url.Values{}

	data.Set("cmd", "getUsersPubKey")
	data.Set("Usuario", loggedUser.username)
	data.Set("token", loggedUser.token)
	data.Set("Usuarios", string(decode64(loggedUser.username))+","+usuarios)

	jsonResponse := sendToServer(data)
	var response resp
	err := json.Unmarshal(jsonResponse, &response)
	chk(err)
	/*if response.Ok {
		split := strings.Split(response.Pubkey, " ")
		for key := range split {
			if split[key] != "" {
				fmt.Println("Recivido: ", split[key], "\n")
			}
		}
	} else {
		fmt.Println("mal")
	}*/
	return response.Pubkey
}

// Para asociar la funcion de crear tema al html
func (uiState *uiState) crearTema(Name, Tipo, usuarios string) {
	if Name == "" {
		uiState.ui.Eval(fmt.Sprintf(`alert("El tema debera tener un nombre")`))
	} else {
		aux := make([]byte, 16)
		rand.Read(aux)
		hash := sha256.New()
		hash.Reset()
		_, err := hash.Write(aux)
		chk(err)
		keyTema := hash.Sum(nil)

		pubkeys := getUsersPubKey(usuarios)

		if Tipo == "publica" {
			data := url.Values{}
			data.Set("cmd", "crearTema")
			data.Set("KeyTema", encode64([]byte(keyTema)))
			data.Set("Name", encode64(encrypt([]byte(Name), []byte(keyTema))))
			data.Set("Tipo", encode64(encrypt([]byte(Tipo), []byte(keyTema))))
			data.Set("Usuario", loggedUser.username)
			data.Set("token", loggedUser.token)

			jsonResponse := sendToServer(data)
			var response resp
			err = json.Unmarshal(jsonResponse, &response)
			if response.Ok {
				uiState.ui.Eval(fmt.Sprintf(`alert("Tema creado correctamente.")`))
				uiState.renderMenuPage()
			} else {
				uiState.ui.Eval(fmt.Sprintf(`alert("Error en publicar un tema")`))
			}
		} else { //privada
			split := strings.Split(pubkeys, " ")
			var keyTemaCifradas string
			for key := range split {
				if split[key] != "" {
					var keyPub rsa.PublicKey
					_ = json.Unmarshal(decompress(decode64(split[key])), &keyPub)

					//fmt.Println("Recivido: ", split[key], "\n")
					//fmt.Println("Recivido2: ", decompress(decode64(split[key])), "\n")
					//fmt.Println("Recivido3: ", keyPub, "\n")
					keyTemaCifradas += RSA_OAEP_Encrypt(string(keyTema), keyPub) + " "
					//fmt.Println("KEYCIFRADA: ", keyTemaCifradas)
				}
			}
			data := url.Values{}
			data.Set("cmd", "crearTema")
			data.Set("KeyTema", keyTemaCifradas)
			data.Set("Name", encode64(encrypt([]byte(Name), []byte(keyTema))))
			data.Set("Tipo", encode64(encrypt([]byte(Tipo), []byte(keyTema))))
			data.Set("Usuario", loggedUser.username)
			data.Set("token", loggedUser.token)
			jsonResponse := sendToServer(data)
			var response resp
			err = json.Unmarshal(jsonResponse, &response)
			chk(err)
			if response.Ok {
				uiState.ui.Eval(fmt.Sprintf(`alert("Tema creado correctamente.")`))
				uiState.renderMenuPage()
			} else {
				uiState.ui.Eval(fmt.Sprintf(`alert("Error en publicar un tema")`))
			}
		}
	}
}

// Para asociar la funcion de crear tema al html
func (uiState *uiState) crearEntrada(Text string) {
	var tipo string
	if temas.Ok {
		//fmt.Println("TIPO VISIBILIDAD CREAR ENTRADA: ", tipoVisibilidad)

		if tipoVisibilidad == "publica" { // publica
			tipo = string(decrypt(decode64(temas.Temas[idTema].Tipo), decode64(temas.Temas[idTema].KeyTema)))
			if tipo == tipoVisibilidad {
				fmt.Println("TIPO: ", tipo, " KEY: ", temas.Temas[idTema].KeyTema)
				data := url.Values{} // estructura para contener los valores
				data.Set("cmd", "crearEntrada")
				data.Set("Id", idTema)
				data.Set("Text", encode64([]byte(Text)))
				data.Set("user", loggedUser.username)
				data.Set("token", loggedUser.token)

				//fmt.Println(data)
				jsonResponse := sendToServer(data)
				var response resp
				err := json.Unmarshal(jsonResponse, &response)
				chk(err)
				if response.Ok {
					uiState.ui.Eval(`alert("Entrada creada correctamente.")`)
					uiState.renderMenuPage()
				} else {
					uiState.ui.Eval(`alert("Error al publicar una entrada")`)
				}
			}
		} else if tipoVisibilidad == "privada" { // privada

			split := strings.Split(temas.Temas[idTema].KeyTema, " ")
			for key := range split {
				if split[key] != "" {
					temaKey := RSA_OAEP_Decrypt(split[key], loggedUser.prikey)
					//fmt.Println("CREATE PRI KEY: ", temaKey)
					if temaKey != "" {
						//fmt.Println("ASDASDASDQWDSAD")
						tipo = string(decrypt(decode64(temas.Temas[idTema].Tipo), []byte(temaKey)))
						//fmt.Println("temakey: ", temaKey)
						if tipo == tipoVisibilidad {
							data := url.Values{} // estructura para contener los valores
							data.Set("cmd", "crearEntrada")
							data.Set("Id", idTema)
							data.Set("Text", encode64(encrypt([]byte(Text), []byte(temaKey))))
							data.Set("user", loggedUser.username)
							data.Set("token", loggedUser.token)

							//fmt.Println(data)
							jsonResponse := sendToServer(data)
							var response resp
							err := json.Unmarshal(jsonResponse, &response)
							chk(err)
							if response.Ok {
								uiState.ui.Eval(`alert("Entrada creada correctamente.")`)
								uiState.renderMenuPage()
							} else {
								uiState.ui.Eval(`alert("Error al publicar una entrada")`)
							}
						}
					}

				}
			}
		}
	}
}

func (uiState *uiState) renderRegister() {
	uiState.loadFile("./www/registro.html")
	_ = uiState.ui.Bind("submitRegister", uiState.register)
	_ = uiState.ui.Bind("loginPage", uiState.renderLogin)
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
func (uiState *uiState) renderCrearEntrada() {
	uiState.loadFile("./www/crearEntrada.html")
	_ = uiState.ui.Bind("crearEntrada", uiState.crearEntrada)
}
func (uiState *uiState) renderMenuPage() {
	uiState.loadFile("./www/menu.html")
	_ = uiState.ui.Bind("crearTema", uiState.renderCrearTema)
	_ = uiState.ui.Bind("listarTemas", uiState.renderListaTemas)
	_ = uiState.ui.Bind("backMenuPage", uiState.renderMenuPage)
	_ = uiState.ui.Bind("loginPage", uiState.renderLogin)
}
func (uiState *uiState) renderListaTemas(visibilidad string) {
	uiState.loadFile("./www/listarTemas.html")
	tipoVisibilidad = visibilidad
	_ = uiState.ui.Bind("start", uiState.getTemas)
	_ = uiState.ui.Bind("listarEntradas", uiState.renderListarEntradas)
	_ = uiState.ui.Bind("backMenuPage", uiState.renderMenuPage)
}
func (uiState *uiState) renderListarEntradas(id string) {
	uiState.loadFile("./www/listarEntradas.html")
	idTema = id
	_ = uiState.ui.Bind("start", uiState.getEntradas)
	_ = uiState.ui.Bind("crearEntrada", uiState.renderCrearEntrada)
	//	_ = uiState.ui.Bind("getVersiones", uiState.renderListarEntradas)
	_ = uiState.ui.Bind("backMenuPage", uiState.renderMenuPage)
}

func main() {
	var args []string
	if runtime.GOOS == "linux" {
		args = append(args, "--class=Lorca")
	}
	ui, err := lorca.New("", "", 780, 600, args...)
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
