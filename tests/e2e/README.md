# M3.15 two-node Kubernetes E2E

The test is disabled unless `ONCACHE_M3_E2E=1` is set. It expects a healthy
two-node K3s/Flannel VXLAN cluster and an agent image already available to both
nodes.

Required environment:

```text
ONCACHE_M3_E2E=1
ONCACHE_M3_E2E_IMAGE=oncache-agent:m3-e2e
ONCACHE_M3_E2E_NODE_A=<node name>
ONCACHE_M3_E2E_NODE_B=<node name>
```

Optional variables:

```text
ONCACHE_M3_E2E_CHART=charts/oncache
ONCACHE_M3_E2E_EVIDENCE=/tmp/oncache-m3-e2e
ONCACHE_M3_E2E_CLEANUP=1
```

Build the image with `make -C tests build-m3-e2e-image`, import it into both
node containerd instances, and then run `make -C tests test-m3-e2e` from the
repository root. The test preserves evidence by default. It does not promise
that the current VM environment is healthy; the runner must verify both nodes
are running and Ready before executing the workload.
