#!/bin/sh
# Forms the region's session cluster (3 primaries, 1 replica each) once.
set -e
first=$(echo $NODES | cut -d' ' -f1)
for h in $NODES; do until redis-cli -h "$h" ping >/dev/null 2>&1; do sleep 1; done; done
if redis-cli -h "$first" cluster info | grep -q cluster_state:ok; then
  echo "cluster already formed"; exit 0
fi
addrs=""
for h in $NODES; do addrs="$addrs $(getent hosts "$h" | awk '{print $1}'):6379"; done
redis-cli --cluster create $addrs --cluster-replicas 1 --cluster-yes
until redis-cli -h "$first" cluster info | grep -q cluster_state:ok; do sleep 1; done
echo "cluster formed"
