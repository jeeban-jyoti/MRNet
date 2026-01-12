package cache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

var RDB *redis.Client
var Ctx = context.Background()

func InitRedis() {
	RDB = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
}

func CloseRedis() {
	RDB.Close()
}

func SetIdToDetailsForAuthInCache(id, passwordHash, refreshToken string) error {
	err := RDB.HSet(
		Ctx,
		id,
		"passwordHash", passwordHash,
		"refreshToken", refreshToken,
	).Err()
	if err != nil {
		return err
	}

	return RDB.Expire(Ctx, id, time.Hour).Err()
}

func GetIdToDetailsForAuthInCache(id string) (map[string]string, error) {
	return RDB.HGetAll(Ctx, id).Result()
}

func UpdateIdToDetailsForAuthInCache(id, passwordHash string) error {
	err := RDB.HSet(
		Ctx,
		id,
		"passwordHash", passwordHash,
	).Err()
	if err != nil {
		return err
	}

	return RDB.Expire(Ctx, id, time.Hour).Err()
}

func DelDataFromCache(id string) (any, error) {
	return RDB.Del(Ctx, id).Result()
}
