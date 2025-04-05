package repo

import (
	"auth-service/internal/config"
	"auth-service/internal/models"
	"context"
	"fmt"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"
)

const (
	createOwnerQuery = `
        INSERT INTO owners (name, email, phone, kind, description, password_hash, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW()) RETURNING id`

	checkExistenceQuery  = `SELECT EXISTS(SELECT 1 FROM owners WHERE email = $1 OR phone = $2)`
	getOwnerByEmailQuery = `SELECT id, password_hash FROM owners WHERE email = $1`

	insertRefreshTokenQuery = `
		INSERT INTO auth_tokens (owner_id, refresh_token, created_at, updated_at)
		VALUES ($1, $2, NOW(), NOW())
		RETURNING id;
	`

	deleteRefreshTokenQuery = `
		DELETE FROM auth_tokens
		WHERE owner_id = $1;
	`

	getRefreshTokenQuery = `
		SELECT refresh_token
		FROM auth_tokens
		WHERE owner_id = $1;
	`

	updateRefreshTokenQuery = `
		UPDATE auth_tokens
		SET refresh_token = $1, updated_at = NOW(), created_at = $2
		WHERE owner_id = $3;
	`
)

type repository struct {
	pool *pgxpool.Pool
}

type Repository interface {
	RegisterOwner(ctx context.Context, owner models.Owner) (string, error)
	LoginOwner(ctx context.Context, email string) (*LoginOwnerResponse, error)

	NewRefreshToken(ctx context.Context, params NewRefreshTokenParams) (int64, error)
	DeleteRefreshToken(ctx context.Context, params DeleteRefreshTokenParams) error
	GetRefreshToken(ctx context.Context, params GetRefreshTokenParams) ([]string, error)
	UpdateRefreshToken(ctx context.Context, params UpdateRefreshTokenParams) error

	Close()
}

func NewRepository(ctx context.Context, cfg config.PostgreSQL) (Repository, error) {
	// Формируем строку подключения
	connString := fmt.Sprintf(
		`user=%s password=%s host=%s port=%d dbname=%s sslmode=%s 
        pool_max_conns=%d pool_max_conn_lifetime=%s pool_max_conn_idle_time=%s`,
		cfg.User,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Name,
		cfg.SSLMode,
		cfg.PoolMaxConns,
		cfg.PoolMaxConnLifetime.String(),
		cfg.PoolMaxConnIdleTime.String(),
	)

	// Парсим конфигурацию подключения
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse PostgreSQL config")
	}

	// Оптимизация выполнения запросов (кеширование запросов)
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe

	// Создаём пул соединений с базой данных
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create PostgreSQL connection pool")
	}

	return &repository{pool}, nil
}

func (r *repository) Close() {
	if r.pool != nil {
		r.pool.Close()
	}
}

func (r *repository) RegisterOwner(ctx context.Context, owner models.Owner) (string, error) {
	exists, err := r.checkExistence(ctx, owner.Email, owner.Password)
	if err != nil {
		return "", errors.Wrap(err, "failed to check owner existence")
	}

	if exists {
		return "", errors.New("owner with this email or phone already exists")
	}

	var ownerID string
	err = r.pool.QueryRow(
		ctx,
		createOwnerQuery,
		owner.Name, owner.Email, owner.Phone, owner.Kind, owner.Description, owner.Password,
	).Scan(&ownerID)
	if err != nil {
		return "", errors.New("failed to create owner")
	}

	return ownerID, nil
}

func (r *repository) LoginOwner(ctx context.Context, email string) (*LoginOwnerResponse, error) {
	var owner LoginOwnerResponse
	err := r.pool.QueryRow(ctx, getOwnerByEmailQuery, email).Scan(&owner.OwnerId, &owner.PasswordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("owner not found")
		}
		return nil, errors.Wrap(err, "failed to fetch owner data")
	}

	return &owner, nil
}

func (r *repository) checkExistence(ctx context.Context, email, phone string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, checkExistenceQuery, email, phone).Scan(&exists)
	if err != nil {
		return false, errors.New("failed to check owner existence")
	}
	return exists, nil
}

func (r *repository) NewRefreshToken(ctx context.Context, params NewRefreshTokenParams) (int64, error) {
	var id int64
	err := r.pool.QueryRow(ctx, insertRefreshTokenQuery, params.UserID, params.Token).Scan(&id)
	if err != nil {
		return 0, errors.Wrap(err, "failed to insert refresh token")
	}
	return id, nil
}

func (r *repository) DeleteRefreshToken(ctx context.Context, params DeleteRefreshTokenParams) error {
	_, err := r.pool.Exec(ctx, deleteRefreshTokenQuery, params.UserID)
	if err != nil {
		return errors.Wrap(err, "failed to delete refresh token")
	}
	return nil
}

func (r *repository) GetRefreshToken(ctx context.Context, params GetRefreshTokenParams) ([]string, error) {
	rows, err := r.pool.Query(ctx, getRefreshTokenQuery, params.UserID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch refresh token")
	}
	defer rows.Close()

	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return nil, errors.Wrap(err, "failed to fetch refresh token")
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

func (r *repository) UpdateRefreshToken(ctx context.Context, params UpdateRefreshTokenParams) error {
	_, err := r.pool.Exec(ctx, updateRefreshTokenQuery, params.Token, params.CreatedDate, params.UserID)
	if err != nil {
		return errors.Wrap(err, "failed to update refresh token")
	}
	return nil
}
