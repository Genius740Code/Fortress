# Fortress Helm Repository

> **Note**: This is a local Helm repository. For production deployment, see the [Helm chart installation guide](../README.md#kubernetes-installation).

This repository hosts the official Helm charts for Fortress secure database system.

## Quick Start

For local development and testing:

```bash
# Install from local chart
helm install my-fortress ./helm/fortress \
  --namespace fortress \
  --create-namespace
```

For production deployment, see the main README for Kubernetes installation instructions.

## 📦 Available Charts

| Chart | Version | Description |
|-------|----------|-------------|
| [fortress](./charts/fortress-0.1.0.tgz) | 0.1.0 | Fortress secure database system |

## 🔧 Configuration

See the [Fortress Helm Chart documentation](../helm/fortress/README.md) for detailed configuration options.

## 📚 Documentation

- [Fortress Documentation](https://docs.fortress-db.com)
- [Installation Guide](../README.md#kubernetes-installation)
- [Configuration Guide](../docs/K8S_DEPLOYMENT.md)
- [Troubleshooting](../docs/K8S_DEPLOYMENT.md#troubleshooting)

## 🛠️ Development

### Building Charts

```bash
cd helm/fortress
helm lint .
helm package .
```

### Testing Charts

```bash
helm install test-fortress ./fortress-0.1.0.tgz \
  --namespace test \
  --create-namespace \
  --dry-run
```

## 📄 License

All charts in this repository are licensed under the [Apache License 2.0](../LICENSE).

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/Genius740Code/Fortress/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Genius740Code/Fortress/discussions)
- **Documentation**: [Fortress Docs](https://docs.fortress-db.com)

---

**Note**: This repository is automatically updated when new versions are released.
