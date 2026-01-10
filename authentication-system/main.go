package main

import (
	"context"
	"log"
	"net"

	authenticationpb "mrnet/gen/go/proto/authentication"

	"google.golang.org/grpc"
)

type SignupServer struct {
	authenticationpb.UnimplementedSignupServiceServer
}

func (s *SignupServer) Signup(
	ctx context.Context,
	req *authenticationpb.UserSignupDetails,
) (*authenticationpb.LoginResponse, error) {

	log.Println("Signup:", req.Email, req.Id)

	if req.Email == "" || req.PasswdHash == "" || req.Id == "" {
		return &authenticationpb.LoginResponse{
			LoginSuccess: false,
			Error:        "missing fields",
		}, nil
	}

	// TODO: store user in DB

	return &authenticationpb.LoginResponse{
		LoginSuccess: true,
		JwtToken:     "signup-jwt-token",
	}, nil
}

type LoginServer struct {
	authenticationpb.UnimplementedLoginServiceServer
}

func (l *LoginServer) LoginWithCredentials(
	ctx context.Context,
	req *authenticationpb.UserLoginDetails,
) (*authenticationpb.LoginResponse, error) {

	log.Println("Login with credentials:", req.EmailOrId)

	if req.EmailOrId == "" || req.PasswdHash == "" {
		return &authenticationpb.LoginResponse{
			LoginSuccess: false,
			Error:        "missing credentials",
		}, nil
	}

	// TODO: verify password

	return &authenticationpb.LoginResponse{
		LoginSuccess: true,
		JwtToken:     "credentials-jwt-token",
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

	// TODO: validate JWT

	return &authenticationpb.LoginResponse{
		LoginSuccess: true,
		JwtToken:     req.JwtToken,
	}, nil
}

type ModificationServer struct {
	authenticationpb.UnimplementedModificationServiceServer
}

func (m *ModificationServer) PasswdChange(
	ctx context.Context,
	req *authenticationpb.PasswdResetRequest,
) (*authenticationpb.ModificationSuccess, error) {

	log.Println("Password change:", req.Email)

	if req.Email == "" || req.SecretHash == "" {
		return &authenticationpb.ModificationSuccess{
			Success: false,
			Error:   "missing fields",
		}, nil
	}

	// TODO: update password in DB

	return &authenticationpb.ModificationSuccess{
		Success: true,
	}, nil
}

func (m *ModificationServer) UserIdChange(
	ctx context.Context,
	req *authenticationpb.UserIdPasswd,
) (*authenticationpb.ModificationSuccess, error) {

	log.Println("UserID change:", req.Email)

	if req.Email == "" || req.PasswdHash == "" {
		return &authenticationpb.ModificationSuccess{
			Success: false,
			Error:   "missing fields",
		}, nil
	}

	// TODO: update userId in DB

	return &authenticationpb.ModificationSuccess{
		Success: true,
	}, nil
}

func main() {
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
