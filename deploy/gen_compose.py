#!/usr/bin/env python3
"""Generates deploy/compose.yaml: every MRNet auth cluster, for two regions
plus the global email registry, on one machine.

Each region gets its own Docker network (its "datacenter"); a shared "wan"
network carries only cross-region traffic: Kafka mirroring, session moves,
forwarded password changes, JWKS fetches and the global registry.

Edit REGIONS and re-run `python3 deploy/gen_compose.py` to add a region.
"""
import json
import os

REGIONS = {
    # region: host port of its gateway
    "ap1": 8443,
    "eu1": 9443,
}
REDIS_NODES = 6  # 3 primaries + 3 replicas per region
CRDB_NODES = 3

IMAGE = "mrnet-auth:dev"
REGISTRY_URL = "postgresql://root@" + ",".join(f"crdb-{i}:26257" for i in range(1, CRDB_NODES + 1)) + "/defaultdb?sslmode=disable"


def env_list(d):
    return {k: str(v) for k, v in d.items()}


def go_service(cmd, region, env, networks, depends, healthy=True):
    svc = {
        "image": IMAGE,
        "pull_policy": "never",
        "command": [cmd],
        "restart": "unless-stopped",
        "environment": env_list(env),
        "networks": networks,
        "depends_on": depends,
    }
    if healthy:
        svc["healthcheck"] = {
            "test": ["CMD", "/mrnet", "healthcheck"],
            "interval": "3s", "timeout": "2s", "retries": 40, "start_period": "5s",
        }
    return svc


def region_services(r, port):
    others = [o for o in REGIONS if o != r]
    redis_nodes = [f"{r}-redis-{i}" for i in range(1, REDIS_NODES + 1)]
    pg_primary = f"postgres://mrnet:mrnet@{r}-pg-primary:5432/mrnet?sslmode=disable"
    pg_replica = f"postgres://mrnet:mrnet@{r}-pg-replica:5432/mrnet?sslmode=disable"
    jwks = ",".join(f"http://{x}-token:8080/.well-known/jwks.json" for x in REGIONS)
    common = {
        "REGION": r,
        "REGIONS": ",".join(REGIONS),
        "ACCESS_TTL": "${ACCESS_TTL:-10m}",
        "LOG_LEVEL": "${LOG_LEVEL:-info}",
    }
    stores = {
        "POSTGRES_PRIMARY_URL": pg_primary,
        "POSTGRES_REPLICA_URL": pg_replica,
        "REDIS_CLUSTER_ADDRS": ",".join(f"{n}:6379" for n in redis_nodes),
        "REDIS_RL_ADDR": f"{r}-redis-rl:6379",
        "KAFKA_BROKERS": f"{r}-kafka:9092",
        "REGISTRY_URL": REGISTRY_URL,
    }
    auth = {
        **common, **stores,
        "HASHER_URL": f"http://{r}-hasher:8080",
        "JWKS_URLS": jwks,
        "KMS_MASTER_KEY": f"${{{r.upper()}_KMS_MASTER_KEY}}",
        "ROTATION_KEY": f"${{{r.upper()}_ROTATION_KEY}}",
        "INTERNAL_SECRET": "${INTERNAL_SECRET}",
        "PEER_TOKEN_URLS": ",".join(f"{o}=http://{o}-token:8080" for o in others),
        "PEER_ACCOUNT_URLS": ",".join(f"{o}=http://{o}-account:8080" for o in others),
        "BREACH_RANGE_URL": f"http://{r}-hasher:8080/range/",
    }
    ready = {"condition": "service_healthy"}
    done = {"condition": "service_completed_successfully"}
    started = {"condition": "service_started"}
    store_deps = {
        f"{r}-migrate": done,
        f"{r}-redis-cluster-init": done,
        f"{r}-redis-rl": started,
        f"{r}-kafka": ready,
        f"{r}-pg-replica": ready,
        "registry-migrate": done,
    }
    net = [r]
    net_wan = [r, "wan"]

    s = {}
    s[f"{r}-pg-primary"] = {
        "image": "postgres:17-alpine",
        "restart": "unless-stopped",
        "environment": {"POSTGRES_USER": "mrnet", "POSTGRES_PASSWORD": "mrnet", "POSTGRES_DB": "mrnet",
                        "REPLICATION_PASSWORD": "replica"},
        "command": ["postgres", "-c", "wal_level=replica", "-c", "max_wal_senders=10", "-c", "max_connections=300"],
        "volumes": [f"{r}-pg-primary:/var/lib/postgresql/data", "./postgres/primary-init.sh:/docker-entrypoint-initdb.d/10-replication.sh:ro"],
        "healthcheck": {"test": ["CMD-SHELL", "pg_isready -U mrnet -d mrnet"], "interval": "2s", "retries": 60},
        "networks": net,
    }
    s[f"{r}-pg-replica"] = {
        "image": "postgres:17-alpine",
        "restart": "unless-stopped",
        "user": "postgres",
        "environment": {"PRIMARY_HOST": f"{r}-pg-primary", "REPLICATION_PASSWORD": "replica",
                        "PGDATA": "/var/lib/postgresql/data"},
        "entrypoint": ["/bin/sh", "/replica-entrypoint.sh"],
        "volumes": [f"{r}-pg-replica:/var/lib/postgresql/data", "./postgres/replica-entrypoint.sh:/replica-entrypoint.sh:ro"],
        "depends_on": {f"{r}-pg-primary": ready},
        "healthcheck": {"test": ["CMD-SHELL", "pg_isready -U mrnet -d mrnet"], "interval": "2s", "retries": 90},
        "networks": net,
    }
    for n in redis_nodes:
        s[n] = {
            "image": "redis:7.4",
            "restart": "unless-stopped",
            "command": ["redis-server", "--cluster-enabled", "yes", "--cluster-config-file", "nodes.conf",
                        "--cluster-node-timeout", "5000", "--appendonly", "yes", "--appendfsync", "everysec",
                        "--cluster-announce-hostname", n, "--cluster-preferred-endpoint-type", "hostname"],
            "volumes": [f"{n}:/data"],
            "networks": net,
        }
    s[f"{r}-redis-cluster-init"] = {
        "image": "redis:7.4",
        "environment": {"NODES": " ".join(redis_nodes)},
        "entrypoint": ["/bin/sh", "/cluster-init.sh"],
        "volumes": ["./redis/cluster-init.sh:/cluster-init.sh:ro"],
        "depends_on": {n: started for n in redis_nodes},
        "networks": net,
    }
    s[f"{r}-redis-rl"] = {
        "image": "redis:7.4",
        "restart": "unless-stopped",
        "command": ["redis-server", "--save", "", "--appendonly", "no"],
        "networks": net,
    }
    s[f"{r}-kafka"] = {
        "image": "apache/kafka:3.9.1",
        "restart": "unless-stopped",
        "hostname": f"{r}-kafka",
        "environment": {
            "KAFKA_NODE_ID": "1",
            "KAFKA_PROCESS_ROLES": "broker,controller",
            "KAFKA_LISTENERS": "PLAINTEXT://:9092,CONTROLLER://:9093",
            "KAFKA_ADVERTISED_LISTENERS": f"PLAINTEXT://{r}-kafka:9092",
            "KAFKA_CONTROLLER_LISTENER_NAMES": "CONTROLLER",
            "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP": "CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT",
            "KAFKA_CONTROLLER_QUORUM_VOTERS": "1@localhost:9093",
            "KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR": "1",
            "KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR": "1",
            "KAFKA_TRANSACTION_STATE_LOG_MIN_ISR": "1",
            "KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS": "0",
            "KAFKA_NUM_PARTITIONS": "3",
            "KAFKA_LOG_RETENTION_HOURS": "168",
            "KAFKA_HEAP_OPTS": "-Xmx384m -Xms384m",
        },
        "volumes": [f"{r}-kafka:/var/lib/kafka/data"],
        "healthcheck": {
            "test": ["CMD-SHELL", "/opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server localhost:9092 >/dev/null 2>&1"],
            "interval": "5s", "timeout": "10s", "retries": 40, "start_period": "10s",
        },
        "networks": net_wan,
    }
    s[f"{r}-migrate"] = {
        "image": IMAGE,
        "pull_policy": "never",
        "command": ["migrate"],
        "environment": env_list({**common, "POSTGRES_PRIMARY_URL": pg_primary}),
        "depends_on": {f"{r}-pg-primary": ready},
        "networks": net,
    }
    s[f"{r}-hasher"] = go_service("hasher", r, {
        **common, "HASH_PEPPER": "${HASH_PEPPER}", "HASHER_WORKERS": "${HASHER_WORKERS:-4}",
    }, net, {})
    s[f"{r}-token"] = go_service("token", r, auth, net_wan, {**store_deps, f"{r}-hasher": ready})
    s[f"{r}-account"] = go_service("account", r, auth, net_wan, {**store_deps, f"{r}-hasher": ready})
    s[f"{r}-validator"] = go_service("validator", r, {
        **common,
        "JWKS_URLS": jwks,
        "REDIS_CLUSTER_ADDRS": stores["REDIS_CLUSTER_ADDRS"],
        "KAFKA_BROKERS": stores["KAFKA_BROKERS"],
    }, net_wan, {f"{r}-token": ready, f"{r}-redis-cluster-init": done, f"{r}-kafka": ready})
    s[f"{r}-replicator"] = go_service("replicator", r, {
        **common,
        "POSTGRES_PRIMARY_URL": pg_primary,
        "REDIS_CLUSTER_ADDRS": stores["REDIS_CLUSTER_ADDRS"],
        "KAFKA_BROKERS": stores["KAFKA_BROKERS"],
        "REMOTE_KAFKA": ",".join(f"{o}={o}-kafka:9092" for o in others),
    }, net_wan, {f"{r}-migrate": done, f"{r}-redis-cluster-init": done, f"{r}-kafka": ready,
                 **{f"{o}-kafka": ready for o in others}})
    s[f"{r}-gateway"] = go_service("gateway", r, {
        **common,
        "VALIDATOR_URL": f"http://{r}-validator:8080",
        "TOKEN_URL": f"http://{r}-token:8080",
        "ACCOUNT_URL": f"http://{r}-account:8080",
        "REDIS_RL_ADDR": f"{r}-redis-rl:6379",
        "IP_LIMIT_PER_MIN": "${IP_LIMIT_PER_MIN:-6000}",
    }, net, {f"{r}-validator": ready, f"{r}-token": ready, f"{r}-account": ready}, healthy=False)
    s[f"{r}-gateway"]["ports"] = [f"{port}:8443"]
    volumes = [f"{r}-pg-primary", f"{r}-pg-replica", f"{r}-kafka", *redis_nodes]
    return s, volumes


def main():
    services, volumes = {}, []
    crdb = [f"crdb-{i}" for i in range(1, CRDB_NODES + 1)]
    for n in crdb:
        services[n] = {
            "image": "cockroachdb/cockroach:latest-v24.3",
            "restart": "unless-stopped",
            "hostname": n,
            "command": ["start", "--insecure", f"--join={','.join(crdb)}", f"--advertise-addr={n}:26257",
                        "--cache=128MiB", "--max-sql-memory=128MiB"],
            "volumes": [f"{n}:/cockroach/cockroach-data"],
            "networks": ["wan"],
        }
        volumes.append(n)
    services["crdb-1"]["ports"] = ["8090:8080"]  # CockroachDB console
    services["registry-init"] = {
        "image": "cockroachdb/cockroach:latest-v24.3",
        "entrypoint": ["/bin/bash", "-c",
                       "until /cockroach/cockroach init --insecure --host=crdb-1:26257 2>&1 | tee /dev/stderr | grep -qE 'initialized|already been initialized'; do sleep 2; done"],
        "depends_on": {n: {"condition": "service_started"} for n in crdb},
        "networks": ["wan"],
    }
    services["registry-migrate"] = {
        "image": IMAGE,
        "pull_policy": "never",
        "command": ["migrate-registry"],
        "environment": {"REGISTRY_URL": REGISTRY_URL},
        "depends_on": {"registry-init": {"condition": "service_completed_successfully"}},
        "networks": ["wan"],
    }
    for r, port in REGIONS.items():
        s, v = region_services(r, port)
        services.update(s)
        volumes += v

    doc = {
        "name": "mrnet-auth",
        "services": services,
        "networks": {**{r: {} for r in REGIONS}, "wan": {}},
        "volumes": {v: {} for v in volumes},
    }
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "compose.yaml")
    with open(out, "w") as f:
        f.write("# Generated by deploy/gen_compose.py. Edit that script, not this file.\n")
        # JSON is valid YAML, and keeps this script free of dependencies.
        json.dump(doc, f, indent=2)
        f.write("\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
