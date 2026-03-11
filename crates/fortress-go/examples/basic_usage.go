package main

import (
	"fmt"
	"log"

	"github.com/Genius740Code/Fortress/fortress-go"
)

func main() {
	// Create a new Fortress client
	f, err := fortress.New()
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	// Get version info
	fmt.Printf("Fortress Go SDK Version: %s\n", fortress.Version)
	fmt.Printf("API Version: %s\n", fortress.APIVersion)

	// Test basic encryption
	plaintext := []byte("Hello, Fortress!")
	ciphertext, err := f.Encrypt(plaintext, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Encrypted: %x\n", ciphertext)
	fmt.Println("Go SDK test completed successfully!")
}
