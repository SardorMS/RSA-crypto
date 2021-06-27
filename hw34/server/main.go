package main

import (
	"log"
	"net/http"
)

//https://go.alif.hack:8888

func main() {
	err := http.ListenAndServeTLS(
		"go.alif.hack:8888",
		"server.crt",
		"server-private.key",
		http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Write([]byte("Hello to the Hacked Version of Site!"))
		}))
	log.Fatal(err)
}
