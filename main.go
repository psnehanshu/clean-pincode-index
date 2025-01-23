package main

import (
	"context"
	"os"

	"github.com/jackc/pgx/v5"
	_ "github.com/joho/godotenv/autoload"
	"github.com/psnehanshu/cleanpincode.in/internal/server"
	"go.uber.org/zap"
)

func main() {
	// Initialize logger
	z, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer z.Sync()
	logger := z.Sugar()

	// Initialize database
	conn, err := pgx.Connect(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		logger.Error("Unable to connect to database:", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())

	// Initialize Server
	s := &server.Server{
		Logger: logger,
		DB:     conn,
	}

	// Start server
	if err := s.Start(":3000"); err != nil {
		logger.Error("Server error:", err)
		os.Exit(1)
	}
}
