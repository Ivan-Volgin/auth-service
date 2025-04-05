package main

import (
	AuthService "auth-service/grpc/genproto"
	"auth-service/internal/config"
	"auth-service/internal/repo"
	"auth-service/internal/service"
	"auth-service/pkg/logger"
	"context"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if err := godotenv.Load("local.env"); err != nil {
		log.Fatal(errors.Wrap(err, "Error loading .env file"))
	}

	var cfg config.AppConfig
	if err := envconfig.Process("", &cfg); err != nil {
		log.Fatal(errors.Wrap(err, "Error processing config"))
	}

	logger, err := logger.NewLogger(cfg.LogLevel)
	if err != nil {
		log.Fatal(errors.Wrap(err, "Error initializing logger"))
	}
	defer logger.Sync()

	ctx := context.Background()
	repository, err := repo.NewRepository(ctx, cfg.PostgreSQL)
	if err != nil {
		log.Fatal(errors.Wrap(err, "Error initializing repository"))
	}

	authSrv := service.NewAuthService(cfg, repository, logger)

	grpcServer := grpc.NewServer()
	AuthService.RegisterAuthServiceServer(grpcServer, authSrv)

	listen, err := net.Listen("tcp", cfg.Grpc.Port)
	if err != nil {
		logger.Fatal(errors.Wrap(err, "Error initializing listener"))
	}

	go func() {
		logger.Infof("gRPC server started on %s", cfg.Grpc.Port)
		if err := grpcServer.Serve(listen); err != nil {
			logger.Fatal(errors.Wrap(err, "Error initializing server"))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Infof("Starting graceful shutdown...")

	logger.Infof("Closing database connection...")
	repository.Close()
	logger.Infof("Database connection closed.")

	logger.Info("Shutting down gRPC server...")
	grpcServer.GracefulStop()
	logger.Infof("Server shutdown completed.")

	logger.Infof("Graceful shutdown completed.")
}
