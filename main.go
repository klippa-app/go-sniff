package main

import (
	"log"

	"github.com/klippa-app/go-sniff/sniff"
)

func main() {
	cT := sniff.DetectContentType([]byte("<html><head>"))
	log.Println(cT)
}
