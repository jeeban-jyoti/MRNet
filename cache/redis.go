package cache

import (
	"context"

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
