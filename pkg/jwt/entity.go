package jwt

type GetDataFromTokenParams struct {
	Token string
}

type GetDataFromTokenResponse struct {
	UserId string
}

type CreateTokenParams struct {
	UserId string
}

type CreateTokenResponse struct {
	AccessToken  string
	RefreshToken string
}

type ValidateTokenParams struct {
	Token string
}
