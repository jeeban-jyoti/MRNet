package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	authenticationpb "mrnet/gen/go/proto/authentication"
	"mrnet/models"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Gateway struct {
	signupClient       authenticationpb.SignupServiceClient
	loginClient        authenticationpb.LoginServiceClient
	modificationClient authenticationpb.ModificationServiceClient
	logoutClient       authenticationpb.LogoutServiceClient
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
		logoutClient:       authenticationpb.NewLogoutServiceClient(conn),
	}

	http.HandleFunc("/signup", gateway.signupHandler)
	http.HandleFunc("/cred-login", gateway.credLoginHandler)
	http.HandleFunc("/token-login", gateway.tokenLoginHandler)
	http.HandleFunc("/userid-change", gateway.changeUseridHandler)
	http.HandleFunc("/request-passwd-change", gateway.requestChangePasswdHandler)
	http.HandleFunc("/passwd-change", gateway.changePasswdHandler)
	http.HandleFunc("/renew-access-token", gateway.renewAccessTokenHandler)
	http.HandleFunc("/logout", gateway.logoutHandler)

	http.HandleFunc("/metadaata", gateway.metaDataHandler)

	log.Println("API Gateway running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func (g *Gateway) signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resp, err := g.signupClient.Signup(ctx, &authenticationpb.UserSignupDetails{
		Email:        req.Email,
		Id:           req.Id,
		PasswordHash: req.PasswordHash,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	out := models.LoggedInResponse{
		Success:      resp.LoginSuccess,
		RefreshToken: resp.RefreshJwtToken,
		AccessToken:  resp.AccessJwtToken,
		Error:        resp.Error,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (g *Gateway) credLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.CredentialsLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resp, err := g.loginClient.LoginWithCredentials(ctx, &authenticationpb.UserLoginDetails{
		Id:           req.Id,
		PasswordHash: req.PasswordHash,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	out := models.LoggedInResponse{
		Success:      resp.LoginSuccess,
		RefreshToken: resp.RefreshJwtToken,
		AccessToken:  resp.AccessJwtToken,
		Error:        resp.Error,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (g *Gateway) tokenLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.TokenLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resp, err := g.loginClient.LoginWithToken(ctx, &authenticationpb.JWTToken{
		AccessJwtToken: req.AccessJWTToken,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	out := models.LoggedInResponse{
		Success:      resp.LoginSuccess,
		RefreshToken: resp.RefreshJwtToken,
		AccessToken:  resp.AccessJwtToken,
		Error:        resp.Error,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (g *Gateway) changeUseridHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.UserIDChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resp, err := g.modificationClient.ChangeUserId(ctx,
		&authenticationpb.UserIdResetRequest{
			OldId:        req.OldId,
			NewId:        req.NewId,
			PasswordHash: req.PasswordHash,
		})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	out := models.ModificationResponse{
		Success: resp.Success,
		Error:   resp.Error,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (g *Gateway) requestChangePasswdHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.RequestPasswordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resp, err := g.modificationClient.RequestChangePassword(ctx, &authenticationpb.RequestChangePasswordRequest{
		Email: req.Email,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	out := models.ModificationResponse{
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

	var req models.PasswordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resp, err := g.modificationClient.ChangePassword(ctx,
		&authenticationpb.PasswordResetRequest{
			Email:           req.Email,
			SecretHash:      req.SecretHash,
			NewPasswordHash: req.NewPasswordHash,
		})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	out := models.ModificationResponse{
		Success: resp.Success,
		Error:   resp.Error,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (g *Gateway) renewAccessTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.RenewTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resp, err := g.loginClient.RenewAccessToken(ctx, &authenticationpb.RenewJWTToken{
		RefreshToken: req.RefreshToken,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	out := models.RenewTokenResponse{
		AccessToken: resp.AccessJwtToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (g *Gateway) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resp, err := g.logoutClient.LogoutWithAccessToken(ctx, &authenticationpb.LogoutRequest{
		Id:          req.Id,
		AccessToken: req.AccessToken,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	out := models.LogoutResponse{
		Success: resp.Success,
		Error:   resp.Error,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (g *Gateway) metaDataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resp, err := g.logoutClient.LogoutWithAccessToken(ctx, &authenticationpb.LogoutRequest{
		Id:          req.Id,
		AccessToken: req.AccessToken,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	out := models.LogoutResponse{
		Success: resp.Success,
		Error:   resp.Error,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
