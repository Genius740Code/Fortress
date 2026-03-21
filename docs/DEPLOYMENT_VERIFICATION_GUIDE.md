# Fortress Deployment Verification Guide

## 🎯 Post-Implementation Verification

This guide provides comprehensive verification steps to ensure all Deployment & Operations features are working correctly in production.

---

## 📋 Verification Checklist

### **1. Kubernetes Infrastructure Verification**

#### Basic Cluster Health
```bash
# Check cluster nodes
kubectl get nodes -o wide

# Check cluster info
kubectl cluster-info

# Check all namespaces
kubectl get namespaces

# Verify storage classes
kubectl get storageclass
```

#### Fortress Namespace Setup
```bash
# Verify fortress namespace exists
kubectl get namespace fortress-production

# Check all resources in fortress namespace
kubectl get all -n fortress-production

# Verify resource quotas
kubectl get resourcequota -n fortress-production
```

### **2. Application Deployment Verification**

#### Deployment Status
```bash
# Check deployment status
kubectl get deployment fortress-production -n fortress-production -o wide

# Check replica set status
kubectl get rs -n fortress-production

# Check pod status with details
kubectl get pods -n fortress-production -o wide

# Verify pod readiness
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=fortress -n fortress-production --timeout=300s
```

#### Service Connectivity
```bash
# Check services
kubectl get services -n fortress-production

# Verify service endpoints
kubectl get endpoints -n fortress-production

# Test service connectivity
kubectl run test-pod --image=curlimages/curl -i --rm --restart=Never -- curl -s http://fortress-production.fortress-production.svc.cluster.local:8080/health
```

#### Ingress Configuration
```bash
# Check ingress status
kubectl get ingress -n fortress-production

# Verify ingress rules
kubectl describe ingress fortress-production -n fortress-production

# Test external connectivity (replace with your domain)
curl -k https://fortress.example.com/health
```

### **3. Autoscaling Verification**

#### Horizontal Pod Autoscaler
```bash
# Check HPA status
kubectl get hpa -n fortress-production

# Describe HPA details
kubectl describe hpa fortress-production -n fortress-production

# Generate load to test HPA
kubectl run load-generator --image=busybox --rm -i --restart=Never -- /bin/sh -c "while true; do wget -q -O- http://fortress-production.fortress-production.svc.cluster.local:8080/health; done"

# Watch HPA scale up
watch kubectl get hpa -n fortress-production
```

#### Vertical Pod Autoscaler
```bash
# Check VPA status
kubectl get vpa -n fortress-production

# Describe VPA recommendations
kubectl describe vpa fortress-production-vpa -n fortress-production

# Check VPA events
kubectl get events -n fortress-production --field-selector involvedObject.kind=VerticalPodAutoscaler
```

### **4. Security Verification**

#### Network Policies
```bash
# Check network policies
kubectl get networkpolicy -n fortress-production

# Test network policy enforcement
kubectl run test-pod --image=busybox --rm -i --restart=Never -- nslookup fortress-production.fortress-production.svc.cluster.local

# Verify denied traffic
kubectl run test-pod --image=busybox --rm -i --restart=Never -- wget -qO- --timeout=5 http://external-service.com
```

#### Pod Security
```bash
# Check pod security context
kubectl get pod fortress-production-xxx -n fortress-production -o jsonpath='{.spec.securityContext}'

# Verify non-root user
kubectl exec -n fortress-production deployment/fortress-production -- whoami

# Check capabilities
kubectl exec -n fortress-production deployment/fortress-production -- capsh --print
```

#### RBAC Verification
```bash
# Check service account
kubectl get serviceaccount fortress-server -n fortress-production

# Check roles and bindings
kubectl get role,rolebinding -n fortress-production

# Test RBAC permissions
kubectl auth can-i get pods -n fortress-production --as=system:serviceaccount:fortress-production:fortress-server
```

### **5. Monitoring Stack Verification**

#### Prometheus Health
```bash
# Check Prometheus deployment
kubectl get pods -n monitoring -l app=prometheus

# Verify Prometheus targets
kubectl port-forward -n monitoring svc/prometheus-server 9090:80 &
curl http://localhost:9090/api/v1/targets

# Check Fortress metrics
curl -s http://localhost:9090/api/v1/query?query=up{job="fortress-server"}
```

#### Grafana Dashboard
```bash
# Check Grafana deployment
kubectl get pods -n monitoring -l app=grafana

# Access Grafana
kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80 &
# Open http://localhost:3000 (admin/admin123)

# Verify data sources
curl -u admin:admin123 http://localhost:3000/api/datasources
```

#### Loki Log Aggregation
```bash
# Check Loki deployment
kubectl get pods -n monitoring -l app=loki

# Test log ingestion
kubectl port-forward -n monitoring svc/loki 3100:80 &
curl -X POST -H "Content-Type: application/json" -d '{"streams": [{"stream": {"app": "test"}, "values": [["$(date +%s%N)", "test log"]}]}' http://localhost:3100/loki/api/v1/push

# Query logs
curl -G "http://localhost:3100/loki/api/v1/query_range" --data-urlencode 'query={app="test"}'
```

### **6. Performance Verification**

#### Load Testing
```bash
# Install k6 if not available
curl https://github.com/grafana/k6/releases/download/v0.45.0/k6-v0.45.0-linux-amd64.tar.gz -L | tar xz
sudo mv k6-v0.45.0-linux-amd64/k6 /usr/local/bin/

# Create load test script
cat > load-test.js << 'EOF'
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '2m', target: 100 },
    { duration: '5m', target: 100 },
    { duration: '2m', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],
    http_req_failed: ['rate<0.1'],
  },
};

export default function () {
  let response = http.get('http://fortress-production.fortress-production.svc.cluster.local:8080/health');
  check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 500ms': (r) => r.timings.duration < 500,
  });
  sleep(1);
}
EOF

# Run load test
k6 run load-test.js --out json=load-test-results.json
```

#### Performance Metrics
```bash
# Check response times
kubectl port-forward -n monitoring svc/prometheus-server 9090:80 &
curl -G "http://localhost:9090/api/v1/query_range" --data-urlencode 'query=histogram_quantile(0.95, rate(fortress_request_duration_seconds_bucket[5m]))' --data-urlencode 'start=1h ago' --data-urlencode 'end=now'

# Check error rates
curl -G "http://localhost:9090/api/v1/query_range" --data-urlencode 'query=rate(fortress_http_requests_total{status=~"5.."}[5m]) / rate(fortress_http_requests_total[5m])' --data-urlencode 'start=1h ago' --data-urlencode 'end=now'
```

### **7. Cloud Integration Verification**

#### AWS Integration (if enabled)
```bash
# Check AWS IAM role
kubectl exec -n fortress-production deployment/fortress-production -- aws sts get-caller-identity

# Verify CloudWatch metrics
kubectl exec -n fortress-production deployment/fortress-production -- aws cloudwatch list-metrics --namespace Fortress

# Test S3 access (if configured)
kubectl exec -n fortress-production deployment/fortress-production -- aws s3 ls
```

#### Azure Integration (if enabled)
```bash
# Check Azure identity
kubectl exec -n fortress-production deployment/fortress-production -- az account show

# Verify Azure Monitor
kubectl exec -n fortress-production deployment/fortress-production -- az monitor metrics list --resource /subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.ContainerService/managedClusters/CLUSTER_NAME
```

#### GCP Integration (if enabled)
```bash
# Check GCP service account
kubectl exec -n fortress-production deployment/fortress-production -- gcloud auth list

# Verify Cloud Monitoring
kubectl exec -n fortress-production deployment/fortress-production -- gcloud monitoring metrics list
```

### **8. Disaster Recovery Verification**

#### Backup Verification
```bash
# Check PVC backups
kubectl get pvc -n fortress-production

# Test backup restoration (if using Velero)
velero backup create fortress-backup --from-cluster fortress-production
velero restore create --from-backup fortress-backup
```

#### Failover Testing
```bash
# Simulate node failure
kubectl cordon <node-name>
kubectl drain <node-name> --ignore-daemonsets --delete-local-data

# Verify pod rescheduling
kubectl get pods -n fortress-production -o wide

# Uncordon node
kubectl uncordon <node-name>
```

---

## 🚨 Troubleshooting Guide

### **Common Issues and Solutions**

#### **Pod Issues**
```bash
# Check pod events
kubectl describe pod <pod-name> -n fortress-production

# Check pod logs
kubectl logs <pod-name> -n fortress-production -f

# Debug pod
kubectl exec -it <pod-name> -n fortress-production -- /bin/bash
```

#### **Service Issues**
```bash
# Check service endpoints
kubectl get endpoints <service-name> -n fortress-production

# Test service connectivity
kubectl run test-pod --image=busybox --rm -i --restart=Never -- nslookup <service-name>.fortress-production.svc.cluster.local
```

#### **Ingress Issues**
```bash
# Check ingress controller logs
kubectl logs -n ingress-nginx deployment/ingress-nginx-controller

# Test ingress connectivity
kubectl run test-pod --image=curlimages/curl -i --rm --restart=Never -- curl -v -H "Host: fortress.example.com" http://ingress-nginx-controller.ingress-nginx.svc.cluster.local/health
```

#### **Autoscaling Issues**
```bash
# Check HPA metrics
kubectl describe hpa fortress-production -n fortress-production

# Check metrics server
kubectl get pods -n kube-system -l k8s-app=metrics-server
kubectl logs -n kube-system deployment/metrics-server
```

#### **Monitoring Issues**
```bash
# Check Prometheus logs
kubectl logs -n monitoring deployment/prometheus-server

# Check Prometheus configuration
kubectl get configmap prometheus-config -n monitoring -o yaml

# Reload Prometheus configuration
kubectl delete pod -l app=prometheus -n monitoring
```

---

## 📊 Performance Benchmarks

### **Expected Performance Metrics**

#### **Application Performance**
- **Response Time**: P95 < 500ms
- **Throughput**: 1000+ requests/second
- **Error Rate**: < 0.1%
- **CPU Usage**: < 70% average
- **Memory Usage**: < 80% average

#### **Infrastructure Performance**
- **Pod Startup Time**: < 30 seconds
- **Scale-up Time**: < 60 seconds
- **Scale-down Time**: < 300 seconds
- **Network Latency**: < 10ms intra-cluster

#### **Monitoring Performance**
- **Metrics Collection**: < 1 second latency
- **Log Ingestion**: 10,000+ logs/second
- **Alert Delivery**: < 30 seconds
- **Dashboard Refresh**: < 1 second

---

## ✅ Success Criteria

### **Deployment Success**
- [ ] All pods are running and ready
- [ ] Services are accessible and responding
- [ ] Ingress is configured and working
- [ ] Health checks are passing
- [ ] Autoscaling is functional

### **Security Success**
- [ ] Network policies are enforced
- [ ] Pods are running as non-root
- [ ] RBAC is working correctly
- [ ] Secrets are properly managed
- [ ] Vulnerability scanning is clean

### **Monitoring Success**
- [ ] Prometheus is collecting metrics
- [ ] Grafana dashboards are populated
- [ ] Loki is aggregating logs
- [ ] Alerts are configured and working
- [ ] Performance benchmarks are met

### **Cloud Integration Success**
- [ ] Cloud provider authentication works
- [ ] Cloud services are accessible
- [ ] Auto-scaling is functioning
- [ ] Cloud monitoring is integrated
- [ ] Cost optimization is active

---

## 🎯 Next Steps

### **Immediate Actions**
1. **Run Full Verification**: Execute all verification steps
2. **Performance Tuning**: Optimize based on benchmark results
3. **Security Hardening**: Implement additional security measures
4. **Documentation**: Update operational runbooks

### **Long-term Improvements**
1. **Multi-Region Deployment**: Expand to multiple regions
2. **Advanced Monitoring**: Implement distributed tracing
3. **AI Operations**: Add predictive scaling and anomaly detection
4. **Cost Optimization**: Implement advanced cost management

---

## 📞 Support Contacts

### **Technical Support**
- **Infrastructure**: infrastructure@fortress-db.com
- **Application**: application@fortress-db.com
- **Security**: security@fortress-db.com
- **Monitoring**: monitoring@fortress-db.com

### **Emergency Contacts**
- **Critical Issues**: emergency@fortress-db.com
- **On-Call Engineer**: +1-555-FORTRESS
- **Slack**: #fortress-operations

---

**This verification guide ensures that your Fortress Deployment & Operations implementation is working correctly and meeting all production requirements.**
