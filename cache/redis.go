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

func SetIdToDetailsForAuthInCache(id string, passwordHash string, refreshToken string) error {
	return RDB.HSet(
		Ctx,
		id,
		"passwordHash", passwordHash,
		"refreshToken", refreshToken,
		time.Hour,
	).Err()
}

func GetIdToDetailsForAuthInCache(id string) (map[string]string, error) {
	return RDB.HGetAll(Ctx, id).Result()
}

func UpdateIdToDetailsForAuthInCache(id string, passwordHash string) error {
	return RDB.HSet(
		Ctx,
		id,
		"passwordHash", passwordHash,
		time.Hour,
	).Err()
}

func DelDataFromCache(id string) (any, error) {
	return RDB.Del(Ctx, id).Result()
}
