package main

import (
	"context"
	"errors"
	"log"
	"net"
	"time"

	"mrnet/cache"
	"mrnet/db"
	authenticationpb "mrnet/gen/go/proto/authentication"
	"mrnet/models"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
)

var jwtSecret = []byte("JeebanTestingNotSoSecretSecret")

func GenerateJWT(userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(720 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ValidateJWT(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", errors.New("invalid token")
	}

	userID, ok := claims["sub"].(string)
	if !ok || userID == "" {
		return "", errors.New("invalid subject")
	}

	return userID, nil
}

type SignupServer struct {
	authenticationpb.UnimplementedSignupServiceServer
}

func (s *SignupServer) Signup(
	ctx context.Context,
	req *authenticationpb.UserSignupDetails,
) (*authenticationpb.LoginResponse, error) {

	log.Println("Signup:", req.Email, req.Id)

	if req.Email == "" || req.PasswordHash == "" || req.Id == "" {
		return &authenticationpb.LoginResponse{
			LoginSuccess: false,
			Error:        "missing fields",
		}, nil
	}

	var user models.SignupRequest

	query := "insert into users (id, email, password_hash) values ($1, $2, $3) returning id, email, password_hash"
	err := db.Pool.QueryRow(
		cache.Ctx,
		query,
		req.Id,
		req.Email,
		req.PasswordHash,
	).Scan(&user.Id, &user.Email, &user.PasswordHash)

	if err != nil {
		return nil, err
	}

	jwt, jwtErr := GenerateJWT(user.Id)
	if jwtErr != nil {
		log.Fatal("failed to generate jwt!")
	}

	return &authenticationpb.LoginResponse{
		LoginSuccess: true,
		JwtToken:     jwt,
	}, nil
}

type LoginServer struct {
	authenticationpb.UnimplementedLoginServiceServer
}

func (l *LoginServer) LoginWithCredentials(
	ctx context.Context,
	req *authenticationpb.UserLoginDetails,
) (*authenticationpb.LoginResponse, error) {

	log.Println("Login with credentials:", req.Id)

	if req.Id == "" || req.PasswordHash == "" {
		return &authenticationpb.LoginResponse{
			LoginSuccess: false,
			Error:        "missing credentials",
		}, nil
	}

	var user models.CredentialsLoginRequest

	query := "select id, password_hash from users where id=$1"
	err := db.Pool.QueryRow(
		cache.Ctx,
		query,
		req.Id,
	).Scan(&user.Id, &user.PasswordHash)

	if err != nil {
		return nil, err
	}
	if user.PasswordHash != req.PasswordHash {
		return nil, errors.New("Password did not match!")
	}

	jwt, jwtErr := GenerateJWT(user.Id)
	if jwtErr != nil {
		return nil, err
	}

	return &authenticationpb.LoginResponse{
		LoginSuccess: true,
		JwtToken:     jwt,
	}, nil
}

func (l *LoginServer) LoginWithToken(
	ctx context.Context,
	req *authenticationpb.JWTToken,
) (*authenticationpb.LoginResponse, error) {

	log.Println("Login with token")

	if req.JwtToken == "" {
		return &authenticationpb.LoginResponse{
			LoginSuccess: false,
			Error:        "missing token",
		}, nil
	}

	userid, err := ValidateJWT(req.JwtToken)

	if err != nil {
		return nil, err
	}

	var user models.CredentialsLoginRequest

	query := "select id from users where id=$1"
	dbErr := db.Pool.QueryRow(
		cache.Ctx,
		query,
		userid,
	).Scan(&user.Id, &user.PasswordHash)

	if dbErr != nil {
		return nil, dbErr
	}

	jwt, jwtErr := GenerateJWT(user.Id)
	if jwtErr != nil {
		return nil, err
	}

	return &authenticationpb.LoginResponse{
		LoginSuccess: true,
		JwtToken:     jwt,
	}, nil
}

type ModificationServer struct {
	authenticationpb.UnimplementedModificationServiceServer
}

func (m *ModificationServer) ChangePasswd(
	ctx context.Context,
	req *authenticationpb.PasswdResetRequest,
) (*authenticationpb.ModificationResponse, error) {

	log.Println("Password change:", req.Email)

	if req.Email == "" || req.SecretHash == "" || req.NewPasswordHash == "" {
		return &authenticationpb.ModificationResponse{
			Success: false,
			Error:   "missing fields",
		}, nil
	}

	//TODO

	return &authenticationpb.ModificationResponse{
		Success: true,
	}, nil
}

func (m *ModificationServer) ChangeUserId(
	ctx context.Context,
	req *authenticationpb.UserIdResetRequest,
) (*authenticationpb.ModificationResponse, error) {

	log.Println("UserID change:", req.OldId)

	if req.OldId == "" || req.NewId == "" || req.PasswordHash == "" {
		return &authenticationpb.ModificationResponse{
			Success: false,
			Error:   "missing fields",
		}, nil
	}

	var user models.UserIDChangeRequest

	query := "select password_hash from users where id=$1"
	err := db.Pool.QueryRow(
		cache.Ctx,
		query,
		req.OldId,
	).Scan(&user.PasswordHash)

	if err != nil {
		return nil, err
	}
	if user.PasswordHash != req.PasswordHash {
		return nil, errors.New("Password did not match!")
	}

	updateQuery := "update users set id = $1 where id=$2"
	cmdTag, updateErr := db.Pool.Exec(
		cache.Ctx,
		updateQuery,
		req.NewId,
		req.OldId,
	)

	if updateErr != nil {
		return nil, updateErr
	}

	if cmdTag.RowsAffected() == 0 {
		return &authenticationpb.ModificationResponse{
			Success: false,
			Error:   "update failed",
		}, nil
	}

	return &authenticationpb.ModificationResponse{
		Success: true,
	}, nil
}

func main() {
	cache.InitRedis()
	db.InitDB()

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatal(err)
	}

	grpcServer := grpc.NewServer()

	authenticationpb.RegisterSignupServiceServer(
		grpcServer, &SignupServer{},
	)
	authenticationpb.RegisterLoginServiceServer(
		grpcServer, &LoginServer{},
	)
	authenticationpb.RegisterModificationServiceServer(
		grpcServer, &ModificationServer{},
	)

	log.Println("Auth gRPC Server running on :50051")
	log.Fatal(grpcServer.Serve(lis))
}
