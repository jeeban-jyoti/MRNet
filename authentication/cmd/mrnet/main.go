// Command mrnet runs one MRNet auth component, chosen by the first argument.
// One binary keeps the container image single and the build fast.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"mrnet/authentication/internal/config"
	"mrnet/authentication/internal/infra"
	"mrnet/authentication/internal/registry"
	"mrnet/authentication/internal/svc/account"
	"mrnet/authentication/internal/svc/gateway"
	"mrnet/authentication/internal/svc/hasher"
	"mrnet/authentication/internal/svc/replicator"
	"mrnet/authentication/internal/svc/token"
	"mrnet/authentication/internal/svc/validator"
	"mrnet/authentication/internal/users"
)

var commands = map[string]func(context.Context) error{
	"gateway":          gateway.Run,
	"validator":        validator.Run,
	"token":            token.Run,
	"account":          account.Run,
	"hasher":           hasher.Run,
	"replicator":       replicator.Run,
	"migrate":          migrate,
	"migrate-registry": migrateRegistry,
}

func main() {
	level := slog.LevelInfo
	if os.Getenv("LOG_LEVEL") == "debug" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})).
		With("region", os.Getenv("REGION")))

	if len(os.Args) < 2 {
		usage()
	}
	if os.Args[1] == "healthcheck" {
		healthcheck()
	}
	run, ok := commands[os.Args[1]]
	if !ok {
		usage()
	}
	slog.Info("starting", "component", os.Args[1])
	if err := run(context.Background()); err != nil {
		slog.Error("exited", "component", os.Args[1], "err", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: mrnet <gateway|validator|token|account|hasher|replicator|migrate|migrate-registry|healthcheck URL>")
	os.Exit(2)
}

// healthcheck is for container health probes (the image has no curl).
func healthcheck() {
	url := "http://127.0.0.1:8080/readyz"
	if len(os.Args) > 2 {
		url = os.Args[2]
	}
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
	os.Exit(0)
}

func migrate(ctx context.Context) error {
	db, err := infra.Postgres(ctx, config.MustStr("POSTGRES_PRIMARY_URL"), 2)
	if err != nil {
		return err
	}
	_, err = db.Exec(ctx, users.Schema)
	if err == nil {
		slog.Info("postgres schema ready")
	}
	return err
}

func migrateRegistry(ctx context.Context) error {
	db, err := infra.Postgres(ctx, config.MustStr("REGISTRY_URL"), 2)
	if err != nil {
		return err
	}
	_, err = db.Exec(ctx, registry.Schema)
	if err == nil {
		slog.Info("registry schema ready")
	}
	return err
}
