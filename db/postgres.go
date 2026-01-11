package db

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

var Pool *pgxpool.Pool

func InitDB() {
	dsn := "postgres://appuser:apppass@localhost:5432/appdb"

	var err error
	Pool, err = pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatal(err)
	}
}
