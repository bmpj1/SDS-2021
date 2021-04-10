package main

import (
	"fmt"
	"net/http"
)

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// ejemplo de tipo para un usuario
type user struct {
	Name string            // nombre de usuario
	Hash []byte            // hash de la contraseña
	Salt []byte            // sal para la contraseña
	Data map[string]string // datos adicionales del usuario
}

// mapa con todos los usuarios
// (se podría codificar en JSON y escribir/leer de disco para persistencia)
var gUsers map[string]user

func server() {
	gUsers = make(map[string]user) // inicializamos mapa de usuarios
	//http.HandleFunc("/", handler) // asignamos un handler global
	chk(http.ListenAndServeTLS(":10443", "cert.pem", "key.pem", nil))
}

func main() {
	fmt.Println("Escuchando en https://localhost:10443...")
	server()
}
