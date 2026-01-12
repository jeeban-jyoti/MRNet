package models

type SignupRequest struct {
	Email        string `json:"email"`
	Id           string `json:"id"`
	PasswordHash string `json:"passwordHash"`
}

type LoggedInResponse struct {
	Success      bool   `json:"success"`
	RefreshToken string `json:"refresh_token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	Error        string `json:"error,omitempty"`
}

type TokenLoginRequest struct {
	AccessJWTToken string `json:"access_token"`
}

type RenewTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RenewTokenResponse struct {
	AccessToken string `json:"access_token"`
}

type CredentialsLoginRequest struct {
	Id           string `json:"id"`
	PasswordHash string `json:"passwordHash"`
}

type RequestPasswordChangeRequest struct {
	Email string `json:"email"`
}

type PasswordChangeRequest struct {
	Email           string `json:"email"`
	SecretHash      string `json:"secretHash"`
	NewPasswordHash string `json:"newPasswordHash"`
}

type UserIDChangeRequest struct {
	OldId        string `json:"oldId"`
	NewId        string `json:"newId"`
	PasswordHash string `json:"passwordHash"`
}

type ModificationResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type LogoutRequest struct {
	Id          string `json:"id"`
	AccessToken string `json:"access_token"`
}

type LogoutResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}
