package service

import (
	AuthService "auth-service/grpc/genproto"
	"auth-service/internal/config"
	"auth-service/internal/models"
	"auth-service/internal/repo"
	RepoMock "auth-service/internal/repo/mocks"
	"auth-service/pkg/jwt"
	JWTMock "auth-service/pkg/jwt/mocks"
	"auth-service/pkg/validator"
	"bou.ke/monkey"
	"context"
	"database/sql"
	"errors"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"testing"
)

func TestRegister(t *testing.T) {
	logger := zap.NewNop().Sugar()

	t.Run("Successful registration", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}
		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.RegisterRequest{
			Name:        "John Doe",
			Email:       "john@example.com",
			Phone:       "1234567890",
			Kind:        "admin",
			Description: "Admin user",
			Password:    "password123",
		}

		const fixedHashedPassword = "$2a$10$PD0Wykus8sNoNCUVtlX6wu7F2A3zevS1h46XTXoq6Qfus/wbiiU4O"
		patch := monkey.Patch(bcrypt.GenerateFromPassword, func(password []byte, cost int) ([]byte, error) {
			return []byte(fixedHashedPassword), nil
		})
		defer patch.Unpatch()

		mockRepo.On("RegisterOwner", ctx, models.Owner{
			Name:        request.GetName(),
			Email:       request.GetEmail(),
			Phone:       request.GetPhone(),
			Kind:        request.GetKind(),
			Description: request.GetDescription(),
			Password:    fixedHashedPassword,
		}).Return("generated-uuid", nil)

		response, err := svc.Register(ctx, request)

		assert.NoError(t, err)
		assert.Equal(t, "generated-uuid", response.GetMessage())

		mockRepo.AssertCalled(t, "RegisterOwner", ctx, models.Owner{
			Name:        request.GetName(),
			Email:       request.GetEmail(),
			Phone:       request.GetPhone(),
			Kind:        request.GetKind(),
			Description: request.GetDescription(),
			Password:    fixedHashedPassword,
		})
	})

	t.Run("Validation failure", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}
		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.RegisterRequest{
			Name:        "",
			Email:       "invalid-email",
			Phone:       "1234567890",
			Kind:        "admin",
			Description: "Admin user",
			Password:    "password123",
		}

		patch := monkey.Patch(validator.Validate, func(ctx context.Context, req interface{}) error {
			return errors.New("validation error")
		})
		defer patch.Unpatch()

		response, err := svc.Register(ctx, request)

		// Проверка результатов
		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "validation error")

		mockRepo.AssertNotCalled(t, "RegisterOwner")
	})

	t.Run("Password hashing failure", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}
		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.RegisterRequest{
			Name:        "John Doe",
			Email:       "john@example.com",
			Phone:       "1234567890",
			Kind:        "admin",
			Description: "Admin user",
			Password:    "password123",
		}

		patch := monkey.Patch(bcrypt.GenerateFromPassword, func(password []byte, cost int) ([]byte, error) {
			return nil, errors.New("hashing error")
		})
		defer patch.Unpatch()

		response, err := svc.Register(ctx, request)

		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "hashing error")

		mockRepo.AssertNotCalled(t, "RegisterOwner")
	})
}

func TestLogin(t *testing.T) {
	logger := zap.NewNop().Sugar()

	t.Run("Successful login", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}
		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.LoginRequest{
			Email:    "john@example.com",
			Password: "password123",
		}

		const fixedHashedPassword = "$2a$10$PD0Wykus8sNoNCUVtlX6wu7F2A3zevS1h46XTXoq6Qfus/wbiiU4O"
		owner := &repo.LoginOwnerResponse{
			OwnerId:      "123",
			PasswordHash: fixedHashedPassword,
		}
		mockRepo.On("LoginOwner", ctx, request.GetEmail()).Return(owner, nil)

		mockJWT.On("CreateToken", &jwt.CreateTokenParams{
			UserId: owner.OwnerId,
		}).Return(&jwt.CreateTokenResponse{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
		}, nil)

		response, err := svc.Login(ctx, request)

		assert.NoError(t, err)
		assert.Equal(t, "access-token", response.GetAccessToken())
		assert.Equal(t, "refresh-token", response.GetRefreshToken())

		mockRepo.AssertCalled(t, "LoginOwner", ctx, request.GetEmail())
		mockJWT.AssertCalled(t, "CreateToken", &jwt.CreateTokenParams{
			UserId: owner.OwnerId,
		})
	})

	t.Run("Validation failure", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}
		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.LoginRequest{
			Email:    "invalid-email",
			Password: "password123",
		}

		patch := monkey.Patch(validator.Validate, func(ctx context.Context, req interface{}) error {
			return errors.New("validation error")
		})
		defer patch.Unpatch()

		response, err := svc.Login(ctx, request)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation error")
		assert.Nil(t, response)

		mockRepo.AssertNotCalled(t, "LoginOwner")
		mockJWT.AssertNotCalled(t, "CreateToken")
	})

	t.Run("User not found", func(t *testing.T) {
		// Определяем входные данные
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}
		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.LoginRequest{
			Email:    "nonexistent@example.com", // Email пользователя, которого нет в базе
			Password: "password123",
		}

		// Настройка поведения мока репозитория
		mockRepo.On("LoginOwner", ctx, request.GetEmail()).Return(nil, errors.New("user not found"))

		// Вызов тестируемого метода
		response, err := svc.Login(ctx, request)

		// Проверка результатов
		assert.Error(t, err) // Ожидаем ошибку
		assert.Contains(t, err.Error(), "user not found")
		assert.Nil(t, response) // Ответ должен быть nil

		// Убедимся, что методы моков были вызваны
		mockRepo.AssertCalled(t, "LoginOwner", ctx, request.GetEmail())
		mockJWT.AssertNotCalled(t, "CreateToken")
	})

	t.Run("Invalid password", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}
		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.LoginRequest{}
		request.Email = "john@example.com"
		request.Password = "password123"

		const fixedHashedPassword = "$2a$10$PD0Wykus8sNoNCUVtlX6wu7F2A3zevS1h46XTXoq6Qfus/wbiiU4O"
		owner := &repo.LoginOwnerResponse{
			OwnerId:      "123",
			PasswordHash: fixedHashedPassword,
		}

		mockRepo.On("LoginOwner", ctx, request.GetEmail()).Return(owner, nil)

		// Мокируем bcrypt.CompareHashAndPassword
		patch := monkey.Patch(bcrypt.CompareHashAndPassword, func(hashedPassword, password []byte) error {
			return bcrypt.ErrMismatchedHashAndPassword // Пароль не совпадает
		})
		defer patch.Unpatch()

		response, err := svc.Login(ctx, request)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "crypto/bcrypt: hashedPassword is not the hash of the given password")
		assert.Nil(t, response)

		mockRepo.AssertCalled(t, "LoginOwner", ctx, request.GetEmail())
		mockJWT.AssertNotCalled(t, "CreateToken")
	})

	t.Run("Token creation failure", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}
		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.LoginRequest{}
		request.Email = "john@example.com"
		request.Password = "password123"

		const fixedHashedPassword = "$2a$10$PD0Wykus8sNoNCUVtlX6wu7F2A3zevS1h46XTXoq6Qfus/wbiiU4O"
		owner := &repo.LoginOwnerResponse{
			OwnerId:      "123",
			PasswordHash: fixedHashedPassword,
		}

		mockRepo.On("LoginOwner", ctx, request.GetEmail()).Return(owner, nil)

		patch := monkey.Patch(bcrypt.CompareHashAndPassword, func(hashedPassword, password []byte) error {
			return nil
		})
		defer patch.Unpatch()

		mockJWT.On("CreateToken", &jwt.CreateTokenParams{
			UserId: owner.OwnerId,
		}).Return(nil, errors.New("token creation error"))

		response, err := svc.Login(ctx, request)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token creation error")
		assert.Nil(t, response)

		mockRepo.AssertCalled(t, "LoginOwner", ctx, request.GetEmail())
		mockJWT.AssertCalled(t, "CreateToken", &jwt.CreateTokenParams{
			UserId: owner.OwnerId,
		})
	})
}

func TestValidate(t *testing.T) {
	logger := zap.NewNop().Sugar()

	t.Run("Successful validation", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}
		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.ValidateRequest{
			AccessToken: "valid-access-token",
		}

		mockJWT.On("ValidateToken", &jwt.ValidateTokenParams{
			Token: request.AccessToken,
		}).Return(true, nil)

		mockJWT.On("GetDataFromToken", &jwt.GetDataFromTokenParams{
			Token: request.AccessToken,
		}).Return(&jwt.GetDataFromTokenResponse{
			UserId: "123",
		}, nil)

		mockRepo.On("GetRefreshToken", ctx, repo.GetRefreshTokenParams{
			UserID: "123",
		}).Return([]string{}, nil)

		response, err := svc.Validate(ctx, request)

		assert.NoError(t, err)
		assert.Equal(t, "123", response.GetUserId())

		mockJWT.AssertCalled(t, "ValidateToken", &jwt.ValidateTokenParams{
			Token: request.AccessToken,
		})
		mockJWT.AssertCalled(t, "GetDataFromToken", &jwt.GetDataFromTokenParams{
			Token: request.AccessToken,
		})
		mockRepo.AssertCalled(t, "GetRefreshToken", ctx, repo.GetRefreshTokenParams{
			UserID: "123",
		})
	})

	t.Run("Invalid JWT token", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}
		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.ValidateRequest{
			AccessToken: "invalid-access-token",
		}

		mockJWT.On("ValidateToken", &jwt.ValidateTokenParams{
			Token: request.AccessToken,
		}).Return(false, errors.New("invalid token"))

		response, err := svc.Validate(ctx, request)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), ErrValidateJwt)
		assert.Nil(t, response)

		mockJWT.AssertCalled(t, "ValidateToken", &jwt.ValidateTokenParams{
			Token: request.AccessToken,
		})
		mockJWT.AssertNotCalled(t, "GetDataFromToken")
		mockRepo.AssertNotCalled(t, "GetRefreshToken")
	})

	t.Run("Error extracting data from token", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}
		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.ValidateRequest{
			AccessToken: "valid-access-token",
		}

		mockJWT.On("ValidateToken", &jwt.ValidateTokenParams{
			Token: request.AccessToken,
		}).Return(true, nil)

		mockJWT.On("GetDataFromToken", &jwt.GetDataFromTokenParams{
			Token: request.AccessToken,
		}).Return(nil, errors.New("failed to extract data"))

		response, err := svc.Validate(ctx, request)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), ErrValidateJwt)
		assert.Nil(t, response)

		mockJWT.AssertCalled(t, "ValidateToken", &jwt.ValidateTokenParams{
			Token: request.AccessToken,
		})
		mockJWT.AssertCalled(t, "GetDataFromToken", &jwt.GetDataFromTokenParams{
			Token: request.AccessToken,
		})
		mockRepo.AssertNotCalled(t, "GetRefreshToken")
	})

	t.Run("No refresh token in repository", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}
		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.ValidateRequest{
			AccessToken: "valid-access-token",
		}

		mockJWT.On("ValidateToken", &jwt.ValidateTokenParams{
			Token: request.AccessToken,
		}).Return(true, nil)

		mockJWT.On("GetDataFromToken", &jwt.GetDataFromTokenParams{
			Token: request.AccessToken,
		}).Return(&jwt.GetDataFromTokenResponse{
			UserId: "123",
		}, nil)

		mockRepo.On("GetRefreshToken", ctx, repo.GetRefreshTokenParams{
			UserID: "123",
		}).Return(nil, sql.ErrNoRows)

		response, err := svc.Validate(ctx, request)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), ErrValidateJwt)
		assert.Nil(t, response)

		mockJWT.AssertCalled(t, "ValidateToken", &jwt.ValidateTokenParams{
			Token: request.AccessToken,
		})
		mockJWT.AssertCalled(t, "GetDataFromToken", &jwt.GetDataFromTokenParams{
			Token: request.AccessToken,
		})
		mockRepo.AssertCalled(t, "GetRefreshToken", ctx, repo.GetRefreshTokenParams{
			UserID: "123",
		})
	})

	t.Run("Internal error in repository", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}
		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.ValidateRequest{
			AccessToken: "valid-access-token",
		}

		// Настройка поведения мока JWT
		mockJWT.On("ValidateToken", &jwt.ValidateTokenParams{
			Token: request.AccessToken,
		}).Return(true, nil)

		mockJWT.On("GetDataFromToken", &jwt.GetDataFromTokenParams{
			Token: request.AccessToken,
		}).Return(&jwt.GetDataFromTokenResponse{
			UserId: "123",
		}, nil)

		mockRepo.On("GetRefreshToken", ctx, repo.GetRefreshTokenParams{
			UserID: "123",
		}).Return(nil, errors.New("internal error"))

		// Вызов тестируемого метода
		response, err := svc.Validate(ctx, request)

		// Проверка результатов
		assert.Error(t, err)
		assert.Contains(t, err.Error(), ErrUnknown)
		assert.Nil(t, response)

		// Проверка вызовов моков
		mockJWT.AssertCalled(t, "ValidateToken", &jwt.ValidateTokenParams{
			Token: request.AccessToken,
		})
		mockJWT.AssertCalled(t, "GetDataFromToken", &jwt.GetDataFromTokenParams{
			Token: request.AccessToken,
		})
		mockRepo.AssertCalled(t, "GetRefreshToken", ctx, repo.GetRefreshTokenParams{
			UserID: "123",
		})
	})
}

func TestNewJWT(t *testing.T) {
	logger := zap.NewNop().Sugar()

	t.Run("Successful token creation", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}
		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.NewJWTRequest{
			UserId: "123",
		}

		mockJWT.On("CreateToken", &jwt.CreateTokenParams{
			UserId: request.UserId,
		}).Return(&jwt.CreateTokenResponse{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
		}, nil)

		mockRepo.On("NewRefreshToken", ctx, repo.NewRefreshTokenParams{
			UserID: request.UserId,
			Token:  "new-refresh-token",
		}).Return(int64(0), nil)

		response, err := svc.NewJWT(ctx, request)

		assert.NoError(t, err)
		assert.Equal(t, "new-access-token", response.GetAccessToken())
		assert.Equal(t, "new-refresh-token", response.GetRefreshToken())

		mockJWT.AssertCalled(t, "CreateToken", &jwt.CreateTokenParams{
			UserId: request.UserId,
		})
		mockRepo.AssertCalled(t, "NewRefreshToken", ctx, repo.NewRefreshTokenParams{
			UserID: request.UserId,
			Token:  "new-refresh-token",
		})
	})

	t.Run("Validation failure", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}
		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.NewJWTRequest{
			UserId: "", // Некорректный UserId
		}

		patch := monkey.Patch(validator.Validate, func(ctx context.Context, req interface{}) error {
			return errors.New("validation error")
		})
		defer patch.Unpatch()

		response, err := svc.NewJWT(ctx, request)

		// Проверка результатов
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation error")
		assert.Nil(t, response)

		mockJWT.AssertNotCalled(t, "CreateToken")
		mockRepo.AssertNotCalled(t, "NewRefreshToken")
	})

	t.Run("Token creation failure", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}
		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.NewJWTRequest{
			UserId: "123",
		}

		// Настройка поведения мока JWT
		mockJWT.On("CreateToken", &jwt.CreateTokenParams{
			UserId: request.UserId,
		}).Return(nil, errors.New("token creation error"))

		// Вызов тестируемого метода
		response, err := svc.NewJWT(ctx, request)

		// Проверка результатов
		assert.Error(t, err)
		assert.Contains(t, err.Error(), ErrUnknown)
		assert.Nil(t, response)

		// Проверка вызовов моков
		mockJWT.AssertCalled(t, "CreateToken", &jwt.CreateTokenParams{
			UserId: request.UserId,
		})
		mockRepo.AssertNotCalled(t, "NewRefreshToken")
	})

	t.Run("Internal error in repository", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}
		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.NewJWTRequest{
			UserId: "123",
		}

		mockJWT.On("CreateToken", &jwt.CreateTokenParams{
			UserId: request.UserId,
		}).Return(&jwt.CreateTokenResponse{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
		}, nil)

		mockRepo.On("NewRefreshToken", ctx, repo.NewRefreshTokenParams{
			UserID: request.UserId,
			Token:  "new-refresh-token",
		}).Return(int64(0), errors.New("internal error"))

		response, err := svc.NewJWT(ctx, request)

		// Проверка результатов
		assert.Error(t, err)
		assert.Contains(t, err.Error(), ErrUnknown)
		assert.Nil(t, response)

		mockJWT.AssertCalled(t, "CreateToken", &jwt.CreateTokenParams{
			UserId: request.UserId,
		})
		mockRepo.AssertCalled(t, "NewRefreshToken", ctx, repo.NewRefreshTokenParams{
			UserID: request.UserId,
			Token:  "new-refresh-token",
		})
	})
}

func TestRevokeJwt(t *testing.T) {
	logger := zap.NewNop().Sugar()

	t.Run("Successful token revocation", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}

		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.RevokeJWTRequest{
			UserId: "123",
		}

		mockRepo.On("DeleteRefreshToken", ctx, repo.DeleteRefreshTokenParams{
			UserID: request.UserId,
		}).Return(nil)

		response, err := svc.RevokeJwt(ctx, request)

		assert.NoError(t, err)
		assert.NotNil(t, response)

		mockRepo.AssertCalled(t, "DeleteRefreshToken", ctx, repo.DeleteRefreshTokenParams{
			UserID: request.UserId,
		})
	})

	t.Run("Error during token revocation", func(t *testing.T) {
		mockRepo := new(RepoMock.Repository)
		mockJWT := new(JWTMock.JWTClient)
		appConfig := config.AppConfig{}

		svc := NewAuthService(appConfig, mockRepo, mockJWT, logger)

		ctx := context.Background()
		request := &AuthService.RevokeJWTRequest{
			UserId: "123",
		}

		mockRepo.On("DeleteRefreshToken", ctx, repo.DeleteRefreshTokenParams{
			UserID: request.UserId,
		}).Return(errors.New("internal error"))

		response, err := svc.RevokeJwt(ctx, request)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), ErrUnknown)
		assert.Nil(t, response)

		mockRepo.AssertCalled(t, "DeleteRefreshToken", ctx, repo.DeleteRefreshTokenParams{
			UserID: request.UserId,
		})
	})
}
