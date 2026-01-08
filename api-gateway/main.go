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
	signupClient authenticationpb.SignupServiceClient
}

type SignupRequest struct {
	Email    string `json:"email"`
	Id       string `json:"id"`
	Password string `json:"password"`
}

type SignupResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"`
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
		signupClient: authenticationpb.NewSignupServiceClient(conn),
	}

	http.HandleFunc("/signup", gateway.signupHandler)

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

	out := SignupResponse{
		Success: resp.LoginSuccess,
		Token:   resp.JwtToken,
		Error:   resp.Error,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
