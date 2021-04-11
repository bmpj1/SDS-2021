package main

import (
	"bytes"
	"context"
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
	"path/filepath"
	. "strconv"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
)

type version struct {
	Name string
	Date time.Time
	Type string //completa, incremental,diferencial...
}

type copia struct {
	Versions map[int]version
	Type     string //completa, incremental,diferencial...
}

// ejemplo de tipo para un usuario
type user struct {
	Name   string `json:"Name"` // nombre de usuario
	Hash   []byte `json:"Hash"` // hash de la contraseña
	Salt   []byte `json:"Salt"` // sal para la contraseña
	Copias map[string]copia
}

type resp struct {
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
}

type respCopias struct {
	Ok     bool   // true -> correcto, false -> error
	Msg    string // mensaje adicional
	Copias map[string]copia
}

type respCopia struct {
	Ok    bool
	Msg   string
	Copia copia
}

func Chk(e error) {
	if e != nil {
		panic(e)
	}
}

var users = map[string]user{}
var tokens = map[string]string{}

const copiasFolder = "./files/"

func createFile(service *drive.Service, name string, mimeType string, content io.Reader, parentId string) (*drive.File, error) {
	f := &drive.File{
		MimeType: mimeType,
		Name:     name,
		Parents:  []string{parentId},
	}
	file, err := service.Files.Create(f).Media(content).Do()

	if err != nil {
		log.Println("Could not create file: " + err.Error())
		return nil, err
	}

	return file, nil
}

func createDir(service *drive.Service, name string, parentId string) (*drive.File, error) {
	d := &drive.File{
		Name:     name,
		MimeType: "application/vnd.google-apps.folder",
		Parents:  []string{parentId},
	}
	file, err := service.Files.Create(d).Do()

	if err != nil {
		log.Println("Could not create dir: " + err.Error())
		return nil, err
	}

	return file, nil
}

func getRootDir(rootName string, service *drive.Service) *drive.File { //ITS ONLY A PROPOSAL, NOT SURE IF IS THE BEST WAY
	list, err := service.Files.List().Do()
	Chk(err)
	for i := 0; i < len(list.Files); i++ {
		if list.Files[i].Name == rootName {
			return list.Files[i]
		}
	}
	return &drive.File{}
}

func getService() (*drive.Service, error) {
	b, err := ioutil.ReadFile("drive/credentials.json")
	if err != nil {
		fmt.Printf("Unable to read credentials.json file. Err: %v\n", err)
		return nil, err
	}

	// If modifying these scopes, delete your previously saved token.json.
	config, err := google.ConfigFromJSON(b, drive.DriveFileScope)

	if err != nil {
		return nil, err
	}

	client := getClient(config)

	service, err := drive.New(client)

	if err != nil {
		fmt.Printf("Cannot create the Google Drive service: %v\n", err)
		return nil, err
	}

	return service, err
}

// Retrieve a token, saves the token, then returns the generated client.
func getClient(config *oauth2.Config) *http.Client {
	// The file token.json stores the user's access and refresh tokens, and is
	// created automatically when the authorization flow completes for the first
	// time.
	tokFile := "token.json"
	tok, err := tokenFromFile(tokFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokFile, tok)
	}
	return config.Client(context.Background(), tok)
}

// Request a token from the web, then returns the retrieved token.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code %v", err)
	}

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web %v", err)
	}
	return tok
}

// Retrieves a token from a local file.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// Saves a token to a file path.
func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

func main() {
	raw, err := ioutil.ReadFile("./db/db.json")
	Chk(err)
	_ = json.Unmarshal(raw, &users)

	stopChan := make(chan os.Signal)
	log.Println("Escuchando en: 127.0.0.1:8081 ... ")
	signal.Notify(stopChan, os.Interrupt)
	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(handler))

	go func() {
		if err := http.ListenAndServeTLS(":8081", "./keys/cert.pem", "./keys/key.pem", mux); err != nil {
			log.Printf("listen: %s\n", err)
		}
	}()
	<-stopChan
	log.Println("Apagando servidor ...")
	log.Println("Servidor detenido correctamente")
}

func saveData() {
	jsonString, err := json.Marshal(users)
	Chk(err)
	ioutil.WriteFile("./db/db.json", jsonString, 0644)
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	Chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

func handler(w http.ResponseWriter, req *http.Request) {
	_ = req.ParseForm()                          // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar
	switch req.Form.Get("cmd") {                 // comprobamos comando desde el cliente
	case "register":
		registerUser(w, req)
	case "login":
		loginUser(w, req)
	case "crear":
		checkToken(req.Form.Get("token"), req.Form.Get("user"), w)
		createEncryptedFile(w, req)
	case "listar":
		checkToken(req.Form.Get("token"), req.Form.Get("user"), w)
		listCopias(w, req)
	case "versiones":
		checkToken(req.Form.Get("token"), req.Form.Get("user"), w)
		listVersiones(w, req)
	case "recuperar":
		checkToken(req.Form.Get("token"), req.Form.Get("user"), w)
		recoverEncryptedFile(w, req)
	}

}

func checkToken(token, username string, w http.ResponseWriter) {
	if token != tokens[username] {
		response := resp{Ok: false, Msg: "Token no válido"}
		sendToClient(w, response)
	}
}

func checkUser(req *http.Request) (bool, string) {
	u, ok := users[req.Form.Get("user")] // obtengo todos los usuarios y mapeo el usuario en concreto segun su login

	if !ok { // ¿existe ya el usuario?
		return false, "Usuario inexistente"
	}

	password := decode64(req.Form.Get("pass"))
	// obtenemos la contraseña
	hash, _ := scrypt.Key(password, u.Salt, 16384, 8, 1, 32) // scrypt(contraseña)

	if bytes.Compare(u.Hash, hash) != 0 { // comparamos
		return false, "Credenciales inválidas"
	}
	token := generateToken()
	tokens[u.Name] = token
	return true, token
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

func loginUser(w http.ResponseWriter, req *http.Request) {
	res, msg := checkUser(req)
	response := resp{Ok: res, Msg: msg}
	sendToClient(w, response)
}

func checkExist(req *http.Request) (bool, string) {
	_, ok := users[req.Form.Get("user")] // obtengo todos los usuarios y mapeo el usuario en concreto segun su login

	if ok { // ¿existe ya el usuario?
		return false, "Usuario ya registrado"
	} else {
		return true, "Usuario registrado correctamente"
	}
}

func registerUser(w http.ResponseWriter, req *http.Request) {
	fmt.Println("estoy en servidor registro")

	res, msg := checkExist(req)

	u := user{}
	u.Name = req.Form.Get("user")              // nombre
	u.Salt = make([]byte, 16)                  // sal (16 bytes == 128 bits)
	rand.Read(u.Salt)                          // la sal es aleatoria
	password := decode64(req.Form.Get("pass")) // contraseña (keyLogin)

	fmt.Println("user and pass: " + req.Form.Get("user"))

	// "hasheamos" la contraseña con scrypt
	u.Hash, _ = scrypt.Key(password, u.Salt, 16384, 8, 1, 32)
	u.Copias = make(map[string]copia)
	//m = make(map)
	users[u.Name] = u

	saveData()
	response := resp{Ok: res, Msg: msg}
	sendToClient(w, response)
}

/**
* Codificamos en JSON una estructura cualquiera y
* devolvemos codificado el JSON en base64
 */
func codifyStructToJSONBase64(structure interface{}) string {
	//codificamos en JSON
	respJSON, err := json.Marshal(&structure)
	Chk(err)
	//codificamos en base64 para que no dé problemas al enviar al servidor
	response := base64.StdEncoding.EncodeToString(respJSON)
	return response
}

func sendToClient(w http.ResponseWriter, structure interface{}) {
	_, _ = w.Write([]byte(codifyStructToJSONBase64(structure))) // escribimos el JSON resultante
}

/* Crea un archivo encriptado con todo el contenido de un directorio */
func createEncryptedFile(w http.ResponseWriter, req *http.Request) {
	var folderPath = req.Form.Get("path")
	var folderContent = req.Form.Get("content")
	var user = req.Form.Get("user")

	splits := strings.Split(folderPath, "/")
	folderName := splits[len(splits)-1] //the folder name..
	var fullFileName string
	_, exists := users[user].Copias[folderPath]
	fullFolderPath := filepath.Join(copiasFolder, user, folderName)
	_ = os.MkdirAll(fullFolderPath, os.ModePerm)
	if exists { //the copy has been done previously, this is a new version
		versionNumber := len(users[user].Copias[folderPath].Versions)
		fullFileName = filepath.Join(fullFolderPath, Itoa(versionNumber))
		users[user].Copias[folderPath].Versions[versionNumber] = version{Name: fullFileName, Date: time.Now()}
	} else {
		fullFileName = filepath.Join(fullFolderPath, "0")
		users[user].Copias[folderPath] = copia{Versions: make(map[int]version), Type: req.Form.Get("type")}
		users[user].Copias[folderPath].Versions[0] = version{Name: fullFileName, Date: time.Now()}
	}

	encryptFile, err := os.Create(fullFileName) // abrimos el segundo fichero (salida)
	_, err = encryptFile.Write(decode64(folderContent))
	Chk(err)
	err = encryptFile.Sync()
	Chk(err)
	saveData()
	saveInDrive(folderName, fullFileName)
	response := resp{Ok: true, Msg: "guardado correctamente"}
	sendToClient(w, response)
}

func saveInDrive(fileName, filePath string) {
	f, err := os.Open(filePath)
	print(f)
	// Step 1. Get the Google Drive service
	service, err := getService()

	// Step 2. Create the directory ONLY IF IS NEEDED, maybe save it in a .json the directories created...
	/*dir, err := createDir(service, "My Folder", "root")

	if err != nil {
		panic(fmt.Sprintf("Could not create dir: %v\n", err))
	}*/
	// Step 4. Create the file and upload its content
	createdFile, err := createFile(service, fileName, "application/octet-stream", f, "root")

	if err != nil {
		panic(fmt.Sprintf("Could not create file: %v\n", err))
	}

	fmt.Printf("File '%s' successfully uploaded in '%s' directory", createdFile.Name, "root")
}

type respVersion struct {
	Ok      bool
	Msg     string
	Content string
}

func recoverEncryptedFile(w http.ResponseWriter, req *http.Request) {
	filePath := req.Form.Get("path")
	user := req.Form.Get("user")
	version, err := Atoi(req.Form.Get("version"))
	Chk(err)
	fileName := users[user].Copias[filePath].Versions[version].Name
	content, err := ioutil.ReadFile(fileName)
	Chk(err)
	response := respVersion{Ok: true, Msg: "", Content: encode64(content)}
	sendToClient(w, response)
}

func listCopias(w http.ResponseWriter, req *http.Request) {
	user := req.Form.Get("user")
	copiaType := req.Form.Get("type")
	selectedCopias := make(map[string]copia)
	for key, _ := range users[user].Copias {
		if users[user].Copias[key].Type == copiaType {
			selectedCopias[key] = users[user].Copias[key]
		}
	}

	response := respCopias{Ok: true, Msg: "", Copias: selectedCopias}
	fmt.Println(response)
	sendToClient(w, response)
}

func listVersiones(w http.ResponseWriter, req *http.Request) {
	user := req.Form.Get("user")
	copiaPath := req.Form.Get("path")

	copia, ok := users[user].Copias[copiaPath]

	response := respCopia{Ok: ok, Msg: "", Copia: copia}

	sendToClient(w, response)

}
