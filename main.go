package main

import (
	"encoding/asn1"
	"fmt"
	"os"
)

type ParsedASN1 struct {
	Name    string
	Salt    []byte
	Params  []string
	Program []byte
}

func main() {
	inputFilename := os.Args[1:]

	if len(inputFilename) != 1 {
		fmt.Println("Invalid quantity of arguments.")
		os.Exit(1)
	}

	rawData, err := os.ReadFile(inputFilename[0])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var Parsed ParsedASN1
	_, err = asn1.Unmarshal(rawData, &Parsed)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	password := []byte{65, 65, 65, 65}

	BruteforceHack(&Parsed, password)
}
