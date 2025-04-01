package service

import (
	AuthService "auth-service/grpc/genproto"
	"auth-service/internal/config"
	"auth-service/internal/models"
	"auth-service/internal/repo"
	"auth-service/pkg/validator"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"context"
)

type authService struct {
	cfg  config.AppConfig
	repo repo.Repository
	log  *zap.SugaredLogger
	AuthService.UnimplementedAuthServiceServer
}

func NewAuthService(cfg config.AppConfig, repo repo.Repository, log *zap.SugaredLogger) AuthService.AuthServiceServer {
	return &authService{
		cfg:  cfg,
		repo: repo,
		log:  log,
	}
}

func (a *authService) Register(ctx context.Context, request *AuthService.RegisterRequest) (*AuthService.RegisterResponse, error) {
	if err := validator.Validate(ctx, request); err != nil {
		a.log.Errorf("Validation error: %s", err)
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.GetPassword()), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	uuid, err := a.repo.RegisterOwner(ctx, models.Owner{
		Name:        request.GetName(),
		Email:       request.GetEmail(),
		Phone:       request.GetPhone(),
		Kind:        request.GetKind(),
		Description: request.GetDescription(),
		Password:    string(hashedPassword),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	return &AuthService.RegisterResponse{Message: uuid}, nil
}

func (a *authService) Login(ctx context.Context, request *AuthService.LoginRequest) (*AuthService.LoginResponse, error) {
	if err := validator.Validate(ctx, request); err != nil {
		a.log.Errorf("Validation error: %s", err)
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	token, err := a.repo.LoginOwner(ctx, request.GetEmail(), request.GetPassword())
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	return &AuthService.LoginResponse{Token: token}, nil
}
