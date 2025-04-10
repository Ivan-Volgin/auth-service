package service

import (
	AuthService "auth-service/grpc/genproto"
	"auth-service/internal/config"
	"auth-service/internal/models"
	"auth-service/internal/repo"
	"auth-service/pkg/jwt"
	"auth-service/pkg/validator"
	"database/sql"
	"errors"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"

	"context"
)

type authService struct {
	cfg  config.AppConfig
	repo repo.Repository
	log  *zap.SugaredLogger
	jwt  jwt.JWTClient
	AuthService.UnimplementedAuthServiceServer
}

func NewAuthService(cfg config.AppConfig, repo repo.Repository, jwt jwt.JWTClient, log *zap.SugaredLogger) AuthService.AuthServiceServer {
	return &authService{
		cfg:  cfg,
		repo: repo,
		jwt:  jwt,
		log:  log,
	}
}

func (c *authService) Register(ctx context.Context, request *AuthService.RegisterRequest) (*AuthService.RegisterResponse, error) {
	if err := validator.Validate(ctx, request); err != nil {
		c.log.Errorf("Validation error: %s", err)
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.GetPassword()), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	uuid, err := c.repo.RegisterOwner(ctx, models.Owner{
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

func (c *authService) Login(ctx context.Context, request *AuthService.LoginRequest) (*AuthService.LoginResponse, error) {
	if err := validator.Validate(ctx, request); err != nil {
		c.log.Errorf("Validation error: %s", err)
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	owner, err := c.repo.LoginOwner(ctx, request.GetEmail())
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	err = bcrypt.CompareHashAndPassword([]byte(owner.PasswordHash), []byte(request.GetPassword()))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return nil, status.Errorf(codes.InvalidArgument, err.Error())
		}
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	tokens, err := c.jwt.CreateToken(&jwt.CreateTokenParams{
		UserId: owner.OwnerId,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	return &AuthService.LoginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (c *authService) Validate(
	ctx context.Context,
	req *AuthService.ValidateRequest,
) (
	*AuthService.ValidateResponse, error,
) {

	check, err := c.jwt.ValidateToken(&jwt.ValidateTokenParams{
		Token: req.AccessToken,
	})

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	if !check {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	accessData, err := c.jwt.GetDataFromToken(&jwt.GetDataFromTokenParams{
		Token: req.AccessToken,
	})

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	_, err = c.repo.GetRefreshToken(ctx, repo.GetRefreshTokenParams{
		UserID: accessData.UserId,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
		}

		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	return &AuthService.ValidateResponse{
		UserId: accessData.UserId,
	}, nil
}

func (c *authService) NewJWT(
	ctx context.Context,
	req *AuthService.NewJWTRequest,
) (
	*AuthService.NewJWTResponse, error,
) {

	if err := validator.Validate(ctx, req); err != nil {
		c.log.Errorf("validation error: %v", err)

		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	tokens, err := c.jwt.CreateToken(&jwt.CreateTokenParams{
		UserId: req.UserId,
	})

	if err != nil {
		c.log.Errorf("create tokens err: user_id = %d", req.UserId)
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	_, err = c.repo.NewRefreshToken(ctx, repo.NewRefreshTokenParams{
		UserID: req.UserId,
		Token:  tokens.RefreshToken,
	})

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgerrcode.ForeignKeyViolation {
				return nil, status.Error(codes.NotFound, ErrUserNotFound)
			}
		}
		c.log.Errorf("adding a token to the database: user_id = %d", req.UserId)
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	return &AuthService.NewJWTResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (c *authService) RevokeJwt(
	ctx context.Context,
	req *AuthService.RevokeJWTRequest,
) (
	*AuthService.RevokeJWTResponse, error,
) {

	err := c.repo.DeleteRefreshToken(ctx, repo.DeleteRefreshTokenParams{
		UserID: req.UserId,
	})
	if err != nil {
		c.log.Errorf("remove a token to the database: user_id = %d", req.UserId)
		return nil, status.Error(codes.Internal, ErrUnknown)
	}
	return &AuthService.RevokeJWTResponse{}, nil
}

func (c *authService) Refresh(
	ctx context.Context,
	req *AuthService.RefreshRequest,
) (
	*AuthService.RefreshResponse, error,
) {

	check, err := c.jwt.ValidateToken(&jwt.ValidateTokenParams{
		Token: req.RefreshToken,
	})
	if err != nil {
		c.log.Errorf("validate refresh token err")
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}
	if !check {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}
	accessData, err := c.jwt.GetDataFromToken(&jwt.GetDataFromTokenParams{
		Token: req.AccessToken,
	})
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	refreshData, err := c.jwt.GetDataFromToken(&jwt.GetDataFromTokenParams{
		Token: req.RefreshToken,
	})
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}
	if accessData.UserId != refreshData.UserId {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	rtToken, err := c.repo.GetRefreshToken(ctx, repo.GetRefreshTokenParams{
		UserID: refreshData.UserId,
	})
	if err != nil {
		c.log.Errorf("get refresh token err")
		if err == sql.ErrNoRows {
			return nil, status.Error(codes.NotFound, ErrTokenNotFound)
		}
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	if len(rtToken) == 0 {
		c.log.Errorf("len(rtToken) == 0")
		return nil, status.Error(codes.NotFound, ErrTokenNotFound)
	}

	if rtToken[0] != req.RefreshToken {
		c.log.Errorf("rtToken[0] != req.RefreshToken")
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	tokens, err := c.jwt.CreateToken(&jwt.CreateTokenParams{
		UserId: refreshData.UserId,
	})

	if err != nil {
		c.log.Errorf("create tokens error")
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	err = c.repo.UpdateRefreshToken(ctx, repo.UpdateRefreshTokenParams{
		Token:       tokens.RefreshToken,
		CreatedDate: sql.NullTime{Time: time.Now(), Valid: true},
		UserID:      refreshData.UserId,
	})

	if err != nil {
		c.log.Errorf("update refresh token err")
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	return &AuthService.RefreshResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}
