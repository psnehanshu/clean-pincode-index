package main

import (
	"os"

	_ "github.com/joho/godotenv/autoload"
	"github.com/psnehanshu/clean-pincode-index/internal/server"
)

func main() {
	// Initialize Server
	s, err := server.New(os.Getenv("DATABASE_URL"))
	if err != nil {
		panic(err)
	}
	defer s.Close()

	// Start server
	if err := s.Start(":3000"); err != nil {
		panic(err)
	}
}
