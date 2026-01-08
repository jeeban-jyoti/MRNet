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

	log.Println("Signup request:", req.Email, req.Id)

	// Fake signup logic
	if req.Email == "" || req.PasswdHash == "" {
		return &authenticationpb.LoginResponse{
			LoginSuccess: false,
			Error:        "missing fields",
		}, nil
	}

	return &authenticationpb.LoginResponse{
		LoginSuccess: true,
		JwtToken:     "signup-jwt-token",
	}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatal(err)
	}

	grpcServer := grpc.NewServer()

	authenticationpb.RegisterSignupServiceServer(
		grpcServer,
		&SignupServer{},
	)

	log.Println("Authentication Service (Signup) running on :50051")
	grpcServer.Serve(lis)
}
