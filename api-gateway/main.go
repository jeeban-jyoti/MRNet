package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	authenticationpb "mrnet/gen/go/proto/authentication"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Gateway struct {
	signupClient       authenticationpb.SignupServiceClient
	loginClient        authenticationpb.LoginServiceClient
	modificationClient authenticationpb.ModificationServiceClient
}

type SignupRequest struct {
	Email    string `json:"email"`
	Id       string `json:"id"`
	Password string `json:"password"`
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
	Id       string `json:"id"`
	Password string `json:"password"`
}

type PasswdChangeRequest struct {
	Email      string `json:"email"`
	SecretHash string `json:"secretHash"`
}

type UserIDChangeRequest struct {
	Email      string `json:"email"`
	PasswdHash string `json:"passwdHash"`
}

type ModificationResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

func main() {
	conn, err := grpc.NewClient(
		"localhost:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	gateway := &Gateway{
		signupClient:       authenticationpb.NewSignupServiceClient(conn),
		loginClient:        authenticationpb.NewLoginServiceClient(conn),
		modificationClient: authenticationpb.NewModificationServiceClient(conn),
	}

	http.HandleFunc("/signup", gateway.signupHandler)
	http.HandleFunc("/cred-login", gateway.credLoginHandler)
	http.HandleFunc("/token-login", gateway.tokenLoginHandler)
	http.HandleFunc("/userid-change", gateway.changeUseridHandler)
	http.HandleFunc("/passwd-change", gateway.changePasswdHandler)

	log.Println("API Gateway running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func (g *Gateway) signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resp, err := g.signupClient.Signup(ctx, &authenticationpb.UserSignupDetails{
		Email:      req.Email,
		Id:         req.Id,
		PasswdHash: req.Password,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	out := LoggedInResponse{
		Success: resp.LoginSuccess,
		Token:   resp.JwtToken,
		Error:   resp.Error,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (g *Gateway) credLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CredentialsLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resp, err := g.loginClient.LoginWithCredentials(ctx, &authenticationpb.UserLoginDetails{
		EmailOrId:  req.Id,
		PasswdHash: req.Password,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	out := LoggedInResponse{
		Success: resp.LoginSuccess,
		Token:   resp.JwtToken,
		Error:   resp.Error,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (g *Gateway) tokenLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TokenLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resp, err := g.loginClient.LoginWithToken(ctx, &authenticationpb.JWTToken{
		JwtToken: req.JWTToken,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	out := LoggedInResponse{
		Success: resp.LoginSuccess,
		Token:   resp.JwtToken,
		Error:   resp.Error,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (g *Gateway) changeUseridHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req UserIDChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resp, err := g.modificationClient.ChangeUserId(ctx,
		&authenticationpb.UserIdPasswd{
			Email:      req.Email,
			PasswdHash: req.PasswdHash,
		})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	out := ModificationResponse{
		Success: resp.Success,
		Error:   resp.Error,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (g *Gateway) changePasswdHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req PasswdChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resp, err := g.modificationClient.ChangePasswd(ctx,
		&authenticationpb.PasswdResetRequest{
			Email:      req.Email,
			SecretHash: req.SecretHash,
		})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	out := LoggedInResponse{
		Success: resp.Success,
		Error:   resp.Error,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
