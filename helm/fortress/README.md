# Fortress Helm Chart

Fortress is a highly customizable, secure database system with multi-layer encryption.

## Introduction

This chart bootstraps a Fortress deployment on a Kubernetes cluster using the Helm package manager.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- PV provisioner support in the underlying infrastructure

## Installing the Chart

To install the chart with the release name `fortress`:

```bash
# Clone the repository
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress

# Install using local chart
helm install my-fortress ./helm/fortress
```

## Troubleshooting

If you encounter issues with the installation:

1. **Ensure Kubernetes cluster is accessible**:
   ```bash
   kubectl cluster-info
   ```

2. **Check Helm version**:
   ```bash
   helm version
   ```

3. **Verify chart dependencies**:
   ```bash
   helm dependency build ./helm/fortress
   ```

4. **Install with debug output**:
   ```bash
   helm install my-fortress ./helm/fortress --debug
   ```

5. **Check pod status**:
   ```bash
   kubectl get pods -l app.kubernetes.io/name=fortress
   ```

## Uninstalling the Chart

To uninstall/delete the `my-fortress` deployment:

```bash
helm uninstall my-fortress
```

## Configuration

The following table lists the configurable parameters of the Fortress chart and their default values.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Fortress server image repository | `fortress-server` |
| `image.tag` | Fortress server image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `replicaCount` | Number of Fortress server replicas | `3` |
| `service.type` | Kubernetes service type | `ClusterIP` |
| `service.port` | Service port | `8080` |
| `resources.requests.memory` | Memory request | `256Mi` |
| `resources.requests.cpu` | CPU request | `250m` |
| `resources.limits.memory` | Memory limit | `512Mi` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `persistence.enabled` | Enable persistent storage | `true` |
| `persistence.size` | Persistent volume size | `10Gi` |
| `persistence.storageClass` | Storage class for PVC | `fast-ssd` |

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install`. For example:

```bash
helm install my-fortress ./helm/fortress --set replicaCount=5
```

Alternatively, a YAML file that specifies the values for the parameters can be provided while installing the chart. For example:

```bash
helm install my-fortress ./helm/fortress -f values.yaml
```

## Persistence

The chart supports persistent storage for Fortress data. By default, a PersistentVolumeClaim is created and mounted at `/data`.

## Security

The chart includes several security best practices:
- Non-root container execution
- Read-only root filesystem
- Dropping all Linux capabilities
- Resource limits and requests
- Health checks and readiness probes

## Monitoring

The chart includes Prometheus metrics scraping annotations. To enable monitoring, ensure you have Prometheus deployed with service discovery configured.

## Scaling

The chart supports horizontal scaling by adjusting the `replicaCount` value. Fortress is designed to be stateless except for the persistent data volume.
