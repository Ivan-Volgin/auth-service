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

// Оставляю функцию на всякий случай, в будующем будет удалена, миграции будут применяться другим способом
/*func applyMigrations(pool *pgxpool.Pool) error {
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()

	driver, err := pgxMigrate.WithInstance(sqlDB, &pgxMigrate.Config{})
	if err != nil {
		return errors.Wrap(err, "failed to initialize pgx migrate driver")
	}

	migrationsPath := "./migrations"
	m, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", migrationsPath),
		"postgres",
		driver,
	)
	if err != nil {
		return errors.Wrap(err, "failed to create migrate instance")
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return errors.Wrap(err, "failed to apply migrations")
	}

	return nil
}*/

func (r *repository) Close() {
	stats := r.pool.Stat()
	fmt.Println(float64(stats.TotalConns()))

	if r.pool != nil {
		r.pool.Close()
	}

	stats = r.pool.Stat()
	fmt.Println(float64(stats.TotalConns()))
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
		context.Background(),
		createOwnerQuery,
		owner.Name, owner.Email, owner.Phone, owner.Kind, owner.Description, owner.Password,
	).Scan(&ownerID)
	if err != nil {
		return "", errors.New("failed to create owner")
	}

	return ownerID, nil
}

func (r *repository) LoginOwner(ctx context.Context, email, password string) (string, error) {
	var ownerID, storedHash string
	err := r.pool.QueryRow(context.Background(), getOwnerByEmailQuery, email).Scan(&ownerID, &storedHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", errors.New("owner not found")
		}
		return "", errors.Wrap(err, "failed to fetch owner data")
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return "", errors.New("invalid password")
		}
		return "", errors.Wrap(err, "failed to compare passwords")
	}

	return "token123", nil
}

func (r *repository) checkExistence(ctx context.Context, email, phone string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(context.Background(), checkExistenceQuery, email, phone).Scan(&exists)
	if err != nil {
		return false, errors.New("failed to check owner existence")
	}
	return exists, nil
}
