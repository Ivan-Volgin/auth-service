package service

import (
	"auth-service/internal/models"
	"auth-service/internal/repo"
	"context"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type Service interface {
	RegisterOwner(ctx context.Context, owner models.Owner) (string, error)
	LoginOwner(ctx context.Context, email, password string) (string, error)
}

type service struct {
	repo repo.Repository
	log  *zap.SugaredLogger
}

func NewService(repo repo.Repository, logger *zap.SugaredLogger) Service {
	return &service{
		repo: repo,
		log:  logger,
	}
}

func (s *service) RegisterOwner(ctx context.Context, owner models.Owner) (string, error) {
	ownerId, err := s.repo.RegisterOwner(context.Background(), owner)
	if err != nil {
		return "", errors.Wrap(err, "Failed to register owner")
	}
	return ownerId, nil
}

func (s *service) LoginOwner(ctx context.Context, email, password string) (string, error) {
	token, err := s.repo.LoginOwner(context.Background(), email, password)
	if err != nil {
		return "", errors.Wrap(err, "failed to login")
	}
	return token, nil
}
