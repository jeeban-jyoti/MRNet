#!/bin/sh
# Streaming read replica: clone the primary once, then follow it.
set -e
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  until pg_isready -h "$PRIMARY_HOST" -U replicator -d postgres -q; do sleep 1; done
  rm -rf "$PGDATA"/*
  PGPASSWORD="$REPLICATION_PASSWORD" pg_basebackup -h "$PRIMARY_HOST" -U replicator \
    -D "$PGDATA" -R -X stream --checkpoint=fast
  chmod 700 "$PGDATA"
fi
exec postgres -c hot_standby=on -c max_connections=300
