package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
)

// according to https://en.wikipedia.org/wiki/PrintableString
var (
	validSymbols = []byte{48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 32, 39, 40, 41, 43, 44, 45, 46, 47, 58, 61, 63, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122}
)

func keyGeneration(password []byte, parsed *ParsedASN1) []byte {
	var passWithSalt []byte
	for i := len(password); i < 16; i++ {
		password = append(password, byte(0))
	}
	for i := 0; i < len(parsed.Salt); i++ {
		passWithSalt = append(passWithSalt, password[i]^parsed.Salt[i])
	}

	key := sha256.Sum256(passWithSalt)

	return key[:]
}

func validateSmallPart(parsed []byte, key []byte) bool {
	var partiallyDecrypted []byte
	partiallyDecrypted = append(partiallyDecrypted, parsed...)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("some problems with key possibly")
	}

	if len(partiallyDecrypted) < aes.BlockSize {
		panic("ciphertext too short")
	}

	if len(partiallyDecrypted)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	mode.CryptBlocks(partiallyDecrypted, partiallyDecrypted)

	// respecting Марк Збиновски :)
	// https://ru.wikipedia.org/wiki/Збиковски,_Марк
	MZcheck := []byte{0x4D, 0x5A}
	// PE32+ signature check
	signatureCheck := []byte{0x50, 0x45}
	if bytes.Equal(MZcheck, partiallyDecrypted[:len(MZcheck)]) && bytes.Equal(signatureCheck, partiallyDecrypted[128:130]) {
		return true
	}

	return false
}

func DecryptWholeProgram(decryptionInput []byte, key []byte) []byte {
	var decoded []byte
	decoded = append(decoded, decryptionInput...)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("some problems with key possibly")
	}

	if len(decoded) < aes.BlockSize {
		panic("ciphertext too short")
	}

	if len(decoded)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	mode.CryptBlocks(decoded, decoded)

	decodedOutput := decoded

	return decodedOutput[:]
}

func ExecProgram(decrypted []byte, Parsed *ParsedASN1) {
	fileToBeCreated, err := os.Create(Parsed.Name)

	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}

	fileToBeCreated.Write(decrypted)
	fileToBeCreated.Close()

	pwd, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cmd := exec.Command(pwd+"\\"+Parsed.Name, string(Parsed.Params[0]+" "+Parsed.Params[1]))

	stdout, err := cmd.Output()

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(string(stdout))

	os.Remove(Parsed.Name)
	os.Exit(0)
}

func BruteforceHack(Parsed *ParsedASN1, password []byte) {
	// in order to have it calculated one time
	validSymbolsLen := len(validSymbols)

	for a := 0; a < validSymbolsLen; a++ {
		password[0] = validSymbols[a]

		for b := 0; b < validSymbolsLen; b++ {
			password[1] = validSymbols[b]

			for c := 0; c < validSymbolsLen; c++ {
				password[2] = validSymbols[c]

				for d := 0; d < validSymbolsLen; d++ {
					password[3] = validSymbols[d]

					key := keyGeneration(password, Parsed)
					// signature of PE32+ is located on 128-130 bytes and cypto block has to be of 16 bytes, 16*9=144
					if validateSmallPart(Parsed.Program[:16*9], key) {
						ExecProgram(DecryptWholeProgram(Parsed.Program[:], key), Parsed)
					}

				}

			}
		}
	}

}
