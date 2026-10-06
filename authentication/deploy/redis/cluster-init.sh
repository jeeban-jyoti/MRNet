#!/bin/sh
# Forms the region's session cluster (3 primaries, 1 replica each) once.
# On later starts the nodes already know each other from nodes.conf and
# re-form by themselves, so this only re-introduces them and waits.
set -e
first=$(echo $NODES | cut -d' ' -f1)
for h in $NODES; do until redis-cli -h "$h" ping >/dev/null 2>&1; do sleep 1; done; done
known=$(redis-cli -h "$first" cluster info | tr -d '\r' | awk -F: '/^cluster_known_nodes/ {print $2}')
if [ "${known:-1}" -gt 1 ]; then
  echo "cluster exists ($known nodes), waiting for it to re-form"
  # nodes.conf may hold old IPs (e.g. volumes from before IPs were pinned);
  # a MEET at the current address makes each node update its peers'.
  for h in $NODES; do
    ip=$(getent hosts "$h" | awk '{print $1}')
    for o in $NODES; do [ "$o" = "$h" ] || redis-cli -h "$o" cluster meet "$ip" 6379 >/dev/null; done
  done
else
  addrs=""
  for h in $NODES; do addrs="$addrs $(getent hosts "$h" | awk '{print $1}'):6379"; done
  redis-cli --cluster create $addrs --cluster-replicas 1 --cluster-yes
fi
until redis-cli -h "$first" cluster info | grep -q cluster_state:ok; do sleep 1; done
echo "cluster ready"
