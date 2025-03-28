package repo

import (
	"auth-service/internal/config"
	"auth-service/internal/models"
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

const (
	createOwnerQuery = `
        INSERT INTO owners (name, email, phone, kind, description, password_hash, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW()) RETURNING id`
	checkExistenceQuery  = `SELECT EXISTS(SELECT 1 FROM owners WHERE email = $1 OR phone = $2)`
	getOwnerByEmailQuery = `SELECT id, password_hash FROM owners WHERE email = $1`
)

type repository struct {
	pool *pgxpool.Pool
}

type Repository interface {
	RegisterOwner(ctx context.Context, owner models.Owner) (string, error)
	LoginOwner(ctx context.Context, email, password string) (string, error)
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

func (r *repository) RegisterOwner(ctx context.Context, owner models.Owner) (string, error) {
	tx, err := r.pool.Begin(context.Background())
	if err != nil {
		return "", errors.New("failed to begin transaction")
	}

	defer func() {
		if err != nil {
			tx.Rollback(context.Background())
		}
	}()

	var exists bool
	err = tx.QueryRow(
		context.Background(),
		checkExistenceQuery,
		owner.Email, owner.Phone,
	).Scan(&exists)
	if err != nil {
		return "", errors.New("failed to check owner existence")
	}

	if exists {
		tx.Rollback(context.Background())
		return "", errors.New("owner with this email or phone already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(owner.Password), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.Wrap(err, "failed to hash password")
	}

	var ownerID string
	err = tx.QueryRow(
		context.Background(),
		createOwnerQuery,
		owner.Name, owner.Email, owner.Phone, owner.Kind, owner.Description, string(hashedPassword),
	).Scan(&ownerID)
	if err != nil {
		return "", errors.New("failed to create owner")
	}

	err = tx.Commit(context.Background())
	if err != nil {
		return "", errors.New("failed to commit transaction")
	}

	return ownerID, nil
}

func (r *repository) LoginOwner(ctx context.Context, email, password string) (string, error) {
	tx, err := r.pool.Begin(context.Background())
	if err != nil {
		return "", errors.New("failed to begin transaction")
	}

	defer func() {
		if err != nil {
			tx.Rollback(context.Background())
		}
	}()

	var ownerID, storedHash string
	err = tx.QueryRow(context.Background(), getOwnerByEmailQuery, email).Scan(&ownerID, &storedHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			tx.Rollback(context.Background())
			return "", errors.New("owner not found")
		}
		return "", errors.Wrap(err, "failed to fetch owner data")
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			tx.Rollback(context.Background())
			return "", errors.New("invalid password")
		}
		return "", errors.Wrap(err, "failed to compare passwords")
	}

	err = tx.Commit(context.Background())
	if err != nil {
		return "", errors.New("failed to commit transaction")
	}

	return "token123", nil
}
