package repo

import "database/sql"

type LoginOwnerResponse struct {
	OwnerId      string
	PasswordHash string
}
type NewRefreshTokenParams struct {
	UserID string
	Token  string
}

type DeleteRefreshTokenParams struct {
	UserID string
}

type GetRefreshTokenParams struct {
	UserID string
}

type UpdateRefreshTokenParams struct {
	UserID      string
	Token       string
	CreatedDate sql.NullTime
}

type UpdatePasswordParams struct {
	UserID   string
	Password string
}
