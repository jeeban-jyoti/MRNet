#!/bin/sh
# Runs once when the primary's data directory is first created.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -c "CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD '$REPLICATION_PASSWORD';"
echo "host replication replicator all scram-sha-256" >> "$PGDATA/pg_hba.conf"
