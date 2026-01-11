package models

type SignupRequest struct {
	Email        string `json:"email"`
	Id           string `json:"id"`
	PasswordHash string `json:"password"`
}

type LoggedInResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"`
	Error   string `json:"error,omitempty"`
}

type TokenLoginRequest struct {
	JWTToken string `json:"token"`
}

type CredentialsLoginRequest struct {
	Id           string `json:"id"`
	PasswordHash string `json:"password"`
}

type PasswdChangeRequest struct {
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
