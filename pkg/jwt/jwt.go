package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type JWTClient interface {
	CreateToken(params *CreateTokenParams) (*CreateTokenResponse, error)
	ValidateToken(params *ValidateTokenParams) (bool, error)
	GetDataFromToken(params *GetDataFromTokenParams) (*GetDataFromTokenResponse, error)
}

type jwtClient struct {
	privateKey       *rsa.PrivateKey
	publicKey        *rsa.PublicKey
	accessTokenTime  time.Duration
	refreshTokenTime time.Duration
}

func NewJWTClient(
	privateKey *rsa.PrivateKey,
	publicKey *rsa.PublicKey,
	accessTokenTime time.Duration,
	refreshTokenTime time.Duration,
) *jwtClient {
	return &jwtClient{
		privateKey:       privateKey,
		publicKey:        publicKey,
		accessTokenTime:  accessTokenTime,
		refreshTokenTime: refreshTokenTime,
	}
}

func (c *jwtClient) CreateToken(params *CreateTokenParams) (*CreateTokenResponse, error) {
	accessToken, err := c.newToken(params, c.accessTokenTime)
	if err != nil {
		return nil, fmt.Errorf("failed to create access token: %v", err)
	}

	refreshToken, err := c.newToken(params, c.refreshTokenTime)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %v", err)
	}

	return &CreateTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (c *jwtClient) ValidateToken(params *ValidateTokenParams) (bool, error) {
	token, err := jwt.Parse(params.Token, func(token *jwt.Token) (interface{}, error) {
		return c.publicKey, nil
	})

	if err != nil {
		return false, err
	}

	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		expirationTime := token.Claims.(jwt.MapClaims)["exp"].(float64)
		if int64(expirationTime) > time.Now().Unix() {
			return true, nil
		}
	}
	return false, err
}

func (c *jwtClient) GetDataFromToken(params *GetDataFromTokenParams) (*GetDataFromTokenResponse, error) {
	token, err := jwt.Parse(params.Token, func(token *jwt.Token) (interface{}, error) {
		return c.publicKey, nil
	})
	if err != nil {
		if err.Error() != "Token is expired" {
			return nil, err
		}
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		userIdClaims, ok1 := claims["userId"].(string)

		if !ok1 {
			log.Error().Fields(map[string]bool{
				"userIdIsCasted": ok1,
			}).Msgf("failed to validate token")

			return nil, fmt.Errorf("invalid token claims")
		}

		return &GetDataFromTokenResponse{
			UserId: userIdClaims,
		}, nil
	}
	return nil, errors.New("invalid signing method")
}

func (c *jwtClient) CreateTokenId(params *CreateTokenParams) (string, error) {

	privateKey, err := readPrivateKey()
	if err != nil {
		return "", err
	}
	accessToken := jwt.New(jwt.SigningMethodRS256)

	claims := accessToken.Claims.(jwt.MapClaims)
	claims["userId"] = params.UserId
	accessTokenString, err := accessToken.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return accessTokenString, nil
}

func (c *jwtClient) newToken(params *CreateTokenParams, lt time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims = jwt.MapClaims{
		"exp":    time.Now().Add(lt).Unix(),
		"userId": params.UserId,
	}

	tokenString, err := token.SignedString(c.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create signed string from token: %v", err)
	}

	return tokenString, nil
}

func readPrivateKey() (*rsa.PrivateKey, error) {
	privateKeyBytes, err := os.ReadFile("private.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to read private.pem: %v", err)
	}

	block, _ := pem.Decode(privateKeyBytes)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private.pem: %v", err)
	}

	return privateKey, nil
}
