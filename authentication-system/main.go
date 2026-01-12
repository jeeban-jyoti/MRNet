package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"

	"mrnet/cache"
	"mrnet/db"
	authenticationpb "mrnet/gen/go/proto/authentication"
	"mrnet/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc"
)

var jwtSecret = []byte("JeebanTestingNotSoSecretSecret")

// ----- Helper Functions -----

func GenerateRefreshJWT(userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(720 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func GenerateAccessJWT(userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(15 * time.Minute).Unix(),
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

func Generate6DigitOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// TODO
func sendOTPMail(email string, otp string) bool {
	return true
}

func HashOTP(otp string) string {
	hash := sha256.Sum256([]byte(otp))
	return hex.EncodeToString(hash[:])
}

func SaveOTP(identifier string) error {
	otp, err := Generate6DigitOTP()
	log.Println(otp)
	if err != nil {
		return err
	}

	key := "otp:" + identifier
	hashedOTP := HashOTP(otp)

	// Store OTP with 5-minute TTL
	cacheErr := cache.RDB.Set(
		cache.Ctx,
		key,
		hashedOTP,
		5*time.Minute,
	).Err()

	if cacheErr != nil {
		return cacheErr
	}

	if !sendOTPMail(identifier, otp) {
		return errors.New("Failed to send mail")
	}

	return nil
}

func VerifyOTP(identifier string, inputOTP string) (bool, error) {
	key := "otp:" + identifier
	log.Println(key)
	storedHash, err := cache.RDB.Get(cache.Ctx, key).Result()
	log.Println("hello" + storedHash)
	if err != nil {
		// key missing or expired
		return false, nil
	}

	if inputOTP != storedHash {
		return false, nil
	}

	// OTP is valid → delete it (one-time use)
	cache.RDB.Del(cache.Ctx, key)

	return true, nil
}

// ----- END -----

// ----- Signup Services -----

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

	refreshJwt, refreshJwtErr := GenerateRefreshJWT(user.Id)
	if refreshJwtErr != nil {
		log.Fatal("failed to generate jwt!")
	}

	accessJwt, accessJwtErr := GenerateAccessJWT(user.Id)
	if accessJwtErr != nil {
		log.Fatal("failed to generate jwt!")
	}

	query := "insert into user_authentication (id, email, password_hash, refresh_token) values ($1, $2, $3, $4) returning id, email, password_hash"
	err := db.Pool.QueryRow(
		cache.Ctx,
		query,
		req.Id,
		req.Email,
		req.PasswordHash,
		refreshJwt,
	).Scan(&user.Id, &user.Email, &user.PasswordHash)

	if err != nil {
		return nil, err
	}

	cachingErr := cache.SetIdToDetailsForAuthInCache(req.Id, req.PasswordHash, refreshJwt)
	if cachingErr != nil {
		log.Println(err)
	}

	return &authenticationpb.LoginResponse{
		LoginSuccess:    true,
		RefreshJwtToken: refreshJwt,
		AccessJwtToken:  accessJwt,
	}, nil
}

// ----- END -----

// ----- Login Services -----

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
	var refreshJwt string

	storedDataFromId, cacheError := cache.GetIdToDetailsForAuthInCache(req.Id)
	if cacheError != nil {
		query := "select id, password_hash, refresh_token from users where id=$1"
		err := db.Pool.QueryRow(
			cache.Ctx,
			query,
			req.Id,
		).Scan(&user.Id, &user.PasswordHash, &refreshJwt)

		if err != nil {
			return nil, err
		}
	} else {
		user.PasswordHash = storedDataFromId["passwordHash"]
		refreshJwt = storedDataFromId["refreshToken"]
	}

	if user.PasswordHash != req.PasswordHash {
		return nil, errors.New("Password did not match!")
	}

	accessJwt, accessJwtErr := GenerateAccessJWT(user.Id)
	if accessJwtErr != nil {
		log.Fatal("failed to generate jwt!")
	}

	return &authenticationpb.LoginResponse{
		LoginSuccess:    true,
		RefreshJwtToken: refreshJwt,
		AccessJwtToken:  accessJwt,
	}, nil
}

func (l *LoginServer) LoginWithToken(
	ctx context.Context,
	req *authenticationpb.JWTToken,
) (*authenticationpb.LoginResponse, error) {

	log.Println("Login with token")

	if req.AccessJwtToken == "" {
		return &authenticationpb.LoginResponse{
			LoginSuccess: false,
			Error:        "missing token",
		}, nil
	}

	userid, err := ValidateJWT(req.AccessJwtToken)

	if err != nil {
		return nil, err
	}

	var user models.CredentialsLoginRequest

	query := "select id from users where id=$1"
	dbErr := db.Pool.QueryRow(
		cache.Ctx,
		query,
		userid,
	).Scan(&user.Id)

	if dbErr != nil {
		return nil, dbErr
	}

	return &authenticationpb.LoginResponse{
		LoginSuccess: true,
	}, nil
}

func (l *LoginServer) RenewAccessToken(
	ctx context.Context,
	req *authenticationpb.RenewJWTToken,
) (*authenticationpb.JWTToken, error) {

	log.Println("Login with token")

	if req.RefreshToken == "" {
		return nil, errors.New("Empty token field")
	}

	userid, err := ValidateJWT(req.RefreshToken)

	if err != nil {
		return nil, err
	}

	var refreshToken pgtype.Text

	query := "select refresh_token from users where id=$1"
	dbErr := db.Pool.QueryRow(
		cache.Ctx,
		query,
		userid,
	).Scan(&refreshToken)

	if dbErr != nil {
		return nil, dbErr
	}

	if !refreshToken.Valid {
		return nil, errors.New("Logged out!")
	}

	if refreshToken.String != req.RefreshToken {
		return nil, errors.New("Token mismatch!")
	}

	accessJwtToken, accessJwtErr := GenerateAccessJWT(userid)
	if accessJwtErr != nil {
		return nil, accessJwtErr
	}

	return &authenticationpb.JWTToken{
		AccessJwtToken: accessJwtToken,
	}, nil
}

// ----- END -----

// ----- Modification Services -----

type ModificationServer struct {
	authenticationpb.UnimplementedModificationServiceServer
}

func (m *ModificationServer) RequestChangePassword(
	ctx context.Context,
	req *authenticationpb.RequestChangePasswordRequest,
) (*authenticationpb.ModificationResponse, error) {

	log.Println("Password change:", req.Email)

	if req.Email == "" {
		return &authenticationpb.ModificationResponse{
			Success: false,
			Error:   "Empty email field",
		}, nil
	}

	cmdTag, err := db.Pool.Exec(
		cache.Ctx,
		"select email from users where email=$1",
		req.Email,
	)

	if err != nil {
		return nil, err
	}

	if cmdTag.RowsAffected() == 0 {
		return &authenticationpb.ModificationResponse{
			Success: false,
			Error:   "update failed",
		}, nil
	}

	if SaveOTP(req.Email) != nil {
		return &authenticationpb.ModificationResponse{
			Success: false,
			Error:   "OTP system failed",
		}, nil
	}

	return &authenticationpb.ModificationResponse{
		Success: true,
	}, nil
}

func (m *ModificationServer) ChangePassword(
	ctx context.Context,
	req *authenticationpb.PasswordResetRequest,
) (*authenticationpb.ModificationResponse, error) {

	log.Println("Password change:", req.Email)

	if req.Email == "" || req.SecretHash == "" || req.NewPasswordHash == "" {
		return &authenticationpb.ModificationResponse{
			Success: false,
			Error:   "missing fields",
		}, nil
	}

	verified, verifyErr := VerifyOTP(req.Email, req.SecretHash)
	if verifyErr != nil {
		return &authenticationpb.ModificationResponse{
			Success: false,
			Error:   "error verifying",
		}, nil
	}
	if !verified {
		return &authenticationpb.ModificationResponse{
			Success: false,
			Error:   "Invalid OTP",
		}, nil
	}

	updateQuery := `
		UPDATE users
		SET password_hash = $1
		WHERE email = $2
		RETURNING id
	`

	var userid string
	err := db.Pool.QueryRow(
		ctx,
		updateQuery,
		req.NewPasswordHash,
		req.Email,
	).Scan(&userid)

	if err != nil {
		return &authenticationpb.ModificationResponse{
			Success: false,
			Error:   "error occured while setting password in database",
		}, nil
	}

	cacheUpdateErr := cache.UpdateIdToDetailsForAuthInCache(userid, req.NewPasswordHash)
	if cacheUpdateErr != nil {
		_, err := cache.DelDataFromCache(userid)
		if err != nil {
			log.Fatal("inconsistent cache!")
			return &authenticationpb.ModificationResponse{
				Success: true,
				Error:   "inconsistent cache",
			}, nil
		}
	}

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

	storedDataInCache, cacheErr1 := cache.GetIdToDetailsForAuthInCache(req.OldId)
	if cacheErr1 != nil {
		log.Fatal("Inconsistent Cache!")
		return &authenticationpb.ModificationResponse{
			Success: true,
			Error:   "inconsistent cache",
		}, nil
	}

	_, cacheErr2 := cache.DelDataFromCache(req.OldId)
	if cacheErr2 != nil {
		log.Fatal("Inconsistent Cache!")
		return &authenticationpb.ModificationResponse{
			Success: true,
			Error:   "inconsistent cache",
		}, nil
	}

	cacheErr3 := cache.SetIdToDetailsForAuthInCache(req.NewId, storedDataInCache["passwordHash"], storedDataInCache["refreshToken"])
	if cacheErr3 != nil {
		log.Fatal("Inconsistent Cache!")
		return &authenticationpb.ModificationResponse{
			Success: true,
			Error:   "inconsistent cache",
		}, nil
	}

	return &authenticationpb.ModificationResponse{
		Success: true,
	}, nil
}

// ----- END -----

// ----- Logout Services -----

type LogoutServer struct {
	authenticationpb.UnimplementedModificationServiceServer
}

func (m *LogoutServer) Logout(
	ctx context.Context,
	req *authenticationpb.LogoutRequest,
) (*authenticationpb.LogoutResponse, error) {

	log.Println("Password change:", req.Id)

	if req.AccessToken == "" || req.Id == "" {
		return &authenticationpb.LogoutResponse{
			Success: false,
			Error:   "Empty fields",
		}, nil
	}

	cmdTag, err := db.Pool.Exec(
		cache.Ctx,
		"update user_authentication set refresh_token = NULL where id=$1",
		req.Id,
	)

	if err != nil {
		return nil, err
	}

	if cmdTag.RowsAffected() == 0 {
		return &authenticationpb.LogoutResponse{
			Success: false,
			Error:   "update failed",
		}, nil
	}

	_, cacheErr := cache.DelDataFromCache(req.Id)
	if cacheErr != nil {
		return &authenticationpb.LogoutResponse{
			Success: true,
			Error:   "cache inconsistent",
		}, nil
	}

	return &authenticationpb.LogoutResponse{
		Success: true,
	}, nil
}

// ----- END -----

func main() {
	cache.InitRedis()
	db.InitDB()

	defer cache.CloseRedis()
	defer db.CloseDB()

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
