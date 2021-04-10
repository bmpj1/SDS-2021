package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"text/template"
)

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

type resp struct {
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
}

func server() {
	http.HandleFunc("/", home)
	chk(http.ListenAndServeTLS(":10443", "cert.pem", "key.pem", nil))
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
	fmt.Println("Escuchando en https://localhost:10443/...")
	server()
}
