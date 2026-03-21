# Fortress Operational Runbook

## 🎯 Mission-Critical Operations Guide

This runbook provides step-by-step procedures for managing Fortress in production environments.

---

## 🚨 Emergency Procedures

### **1. Service Outage Response**

#### **Immediate Response (First 5 Minutes)**
```bash
# 1. Assess the situation
kubectl get pods -n fortress-production
kubectl get events -n fortress-production --sort-by='.lastTimestamp'

# 2. Check service health
kubectl get services -n fortress-production
kubectl describe service fortress-production -n fortress-production

# 3. Check recent deployments
kubectl rollout history deployment/fortress-production -n fortress-production

# 4. Check logs for errors
kubectl logs -n fortress-production -l app.kubernetes.io/name=fortress --tail=100
```

#### **Quick Fixes**
```bash
# Restart deployment
kubectl rollout restart deployment/fortress-production -n fortress-production

# Scale up if needed
kubectl scale deployment fortress-production --replicas=10 -n fortress-production

# Rollback to previous version
kubectl rollout undo deployment/fortress-production -n fortress-production

# Force rollback to specific revision
kubectl rollout undo deployment/fortress-production --to-revision=2 -n fortress-production
```

#### **Communication Protocol**
1. **Alert Team**: Send emergency notification
2. **Status Page**: Update incident status
3. **Stakeholders**: Communicate impact and ETA
4. **Documentation**: Log all actions taken

### **2. Performance Degradation**

#### **Diagnosis**
```bash
# Check resource usage
kubectl top pods -n fortress-production
kubectl top nodes

# Check HPA status
kubectl get hpa -n fortress-production
kubectl describe hpa fortress-production -n fortress-production

# Check metrics
kubectl port-forward -n monitoring svc/prometheus-server 9090:80 &
# Open http://localhost:9090 to check performance metrics
```

#### **Performance Fixes**
```bash
# Manual scaling
kubectl scale deployment fortress-production --replicas=20 -n fortress-production

# Adjust HPA thresholds
kubectl patch hpa fortress-production -n fortress-production -p '{"spec":{"targetCPUUtilizationPercentage":60}}'

# Enable VPA if not already
kubectl apply -f k8s/vertical-pod-autoscaler.yaml
```

### **3. Security Incident Response**

#### **Immediate Isolation**
```bash
# Enable network lockdown
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: emergency-lockdown
  namespace: fortress-production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF

# Scale down to prevent further damage
kubectl scale deployment fortress-production --replicas=0 -n fortress-production
```

#### **Security Investigation**
```bash
# Check audit logs
kubectl get events -n fortress-production --field-selector type=Warning

# Check pod security context
kubectl get pod -n fortress-production -o jsonpath='{.items[*].spec.securityContext}'

# Check network policies
kubectl get networkpolicy -n fortress-production

# Review recent changes
kubectl rollout history deployment/fortress-production -n fortress-production
```

---

## 🔧 Maintenance Procedures

### **1. Rolling Updates**

#### **Safe Update Process**
```bash
# 1. Backup current configuration
helm get values fortress-production -n fortress-production > backup-values-$(date +%Y%m%d-%H%M%S).yaml

# 2. Test in staging first
./scripts/deploy-staging.sh new-version-tag

# 3. Update production with canary
helm upgrade fortress-production helm/fortress \
  --namespace fortress-production \
  --set image.tag=new-version-tag \
  --set strategy.type=RollingUpdate \
  --set strategy.rollingUpdate.maxSurge=1 \
  --set strategy.rollingUpdate.maxUnavailable=0 \
  --wait --timeout=15m

# 4. Monitor deployment
kubectl rollout status deployment/fortress-production -n fortress-production --timeout=600s
```

#### **Update Verification**
```bash
# Check new pods are running
kubectl get pods -n fortress-production -l app.kubernetes.io/name=fortress

# Verify new version
kubectl exec -n fortress-production deployment/fortress-production -- fortress --version

# Run smoke tests
kubectl port-forward -n fortress-production svc/fortress-production 8080:80 &
curl -f http://localhost:8080/health
```

### **2. Backup and Recovery**

#### **Automated Backups**
```bash
# Create namespace backup
kubectl get namespace fortress-production -o yaml > namespace-backup.yaml

# Backup all resources
kubectl get all -n fortress-production -o yaml > resources-backup.yaml

# Backup PVCs
kubectl get pvc -n fortress-production -o yaml > pvc-backup.yaml

# Backup configurations
helm get values fortress-production -n fortress-production > helm-values-backup.yaml
```

#### **Disaster Recovery**
```bash
# 1. Restore namespace
kubectl apply -f namespace-backup.yaml

# 2. Restore PVCs
kubectl apply -f pvc-backup.yaml

# 3. Restore application
helm install fortress-production helm/fortress \
  --namespace fortress-production \
  --values helm-values-backup.yaml \
  --wait --timeout=15m

# 4. Verify restoration
kubectl get pods -n fortress-production
kubectl rollout status deployment/fortress-production -n fortress-production
```

### **3. Scaling Operations**

#### **Manual Scaling**
```bash
# Scale up for high load
kubectl scale deployment fortress-production --replicas=50 -n fortress-production

# Scale down for cost optimization
kubectl scale deployment fortress-production --replicas=3 -n fortress-production

# Enable autoscaling
kubectl apply -f k8s/horizontal-pod-autoscaler.yaml

# Configure VPA for optimization
kubectl apply -f k8s/vertical-pod-autoscaler.yaml
```

#### **Performance Tuning**
```bash
# Adjust resource limits
kubectl patch deployment fortress-production -n fortress-production -p '{"spec":{"template":{"spec":{"containers":[{"name":"fortress","resources":{"limits":{"cpu":"4000m","memory":"8Gi"}}}]}}}}'

# Update HPA configuration
kubectl patch hpa fortress-production -n fortress-production -p '{"spec":{"minReplicas":5,"maxReplicas":100,"targetCPUUtilizationPercentage":60}}'

# Configure VPA
kubectl patch vpa fortress-production-vpa -n fortress-production -p '{"spec":{"updatePolicy":{"updateMode":"Auto"}}}'
```

---

## 🔍 Monitoring and Alerting

### **1. Health Monitoring**

#### **Key Metrics to Monitor**
```bash
# Application health
curl -s "http://prometheus-server:9090/api/v1/query?query=up{job='fortress-server'}"

# Response times
curl -s "http://prometheus-server:9090/api/v1/query?query=histogram_quantile(0.95, rate(fortress_request_duration_seconds_bucket[5m]))"

# Error rates
curl -s "http://prometheus-server:9090/api/v1/query?query=rate(fortress_http_requests_total{status=~'5..'}[5m]) / rate(fortress_http_requests_total[5m])"

# Resource usage
curl -s "http://prometheus-server:9090/api/v1/query?query=rate(container_cpu_usage_seconds_total{pod=~'fortress-production-.*'}[5m])"
curl -s "http://prometheus-server:9090/api/v1/query?query=container_memory_usage_bytes{pod=~'fortress-production-.*'}"
```

#### **Log Monitoring**
```bash
# Check recent error logs
kubectl logs -n fortress-production -l app.kubernetes.io/name=fortress --since=1h | grep ERROR

# Monitor real-time logs
kubectl logs -n fortress-production -l app.kubernetes.io/name=fortress -f

# Check specific pod logs
kubectl logs -n fortress-production deployment/fortress-production -c fortress --tail=100
```

### **2. Alert Management**

#### **Critical Alerts**
- **FortressDown**: Service completely unavailable
- **HighErrorRate**: Error rate > 5%
- **HighMemoryUsage**: Memory usage > 90%
- **HighCPUUsage**: CPU usage > 80%
- **SlowQueries**: P95 response time > 1s

#### **Alert Response Procedures**
```bash
# 1. Acknowledge alert in AlertManager
# 2. Check affected pods
kubectl get pods -n fortress-production --field-selector=status.phase!=Running

# 3. Check resource constraints
kubectl describe pod <pod-name> -n fortress-production

# 4. Check node health
kubectl get nodes --field-selector=Ready=False

# 5. Escalate if needed
```

---

## 🛡️ Security Operations

### **1. Security Monitoring**

#### **Daily Security Checks**
```bash
# Check for unusual activity
kubectl auth can-i --list --as=system:anonymous -n fortress-production

# Review pod security
kubectl get pods -n fortress-production -o jsonpath='{.items[*].spec.securityContext}'

# Check network policies
kubectl get networkpolicy -n fortress-production -o yaml

# Review RBAC
kubectl get role,rolebinding -n fortress-production -o yaml
```

#### **Vulnerability Management**
```bash
# Scan running images
kubectl get pods -n fortress-production -o jsonpath='{.items[*].spec.containers[*].image}' | tr ' ' '\n' | sort -u

# Check image vulnerabilities (using trivy)
trivy image fortressdb/fortress:latest

# Review security updates
kubectl get pods -n fortress-production -o jsonpath='{.items[*].spec.containers[*].name}' | tr ' ' '\n' | sort -u
```

### **2. Incident Response**

#### **Security Incident Checklist**
- [ ] Isolate affected systems
- [ ] Preserve forensic evidence
- [ ] Notify security team
- [ ] Document timeline
- [ ] Implement containment
- [ ] Eradicate threat
- [ ] Recover systems
- [ ] Post-incident review

---

## 📊 Performance Optimization

### **1. Resource Optimization**

#### **Memory Optimization**
```bash
# Check memory usage patterns
kubectl top pods -n fortress-production --sort-by=memory

# Analyze memory leaks
kubectl exec -n fortress-production deployment/fortress-production -- pmap $(pidof fortress)

# Optimize JVM settings (if applicable)
kubectl patch deployment fortress-production -n fortress-production -p '{"spec":{"template":{"spec":{"containers":[{"name":"fortress","env":[{"name":"JAVA_OPTS","value":"-Xms2g -Xmx4g -XX:+UseG1GC"}]}]}}}}'
```

#### **CPU Optimization**
```bash
# Check CPU usage patterns
kubectl top pods -n fortress-production --sort-by=cpu

# Adjust CPU limits
kubectl patch deployment fortress-production -n fortress-production -p '{"spec":{"template":{"spec":{"containers":[{"name":"fortress","resources":{"limits":{"cpu":"2000m"}}}]}}}}'

# Enable CPU profiling
kubectl patch deployment fortress-production -n fortress-production -p '{"spec":{"template":{"spec":{"containers":[{"name":"fortress","env":[{"name":"RUST_PROFILE","value":"1"}]}]}}}}'
```

### **2. Database Optimization**

#### **Performance Tuning**
```bash
# Check database connections
kubectl exec -n fortress-production deployment/fortress-production -- fortress db status

# Monitor query performance
kubectl exec -n fortress-production deployment/fortress-production -- fortress db slow-queries

# Optimize database
kubectl exec -n fortress-production deployment/fortress-production -- fortress db optimize
```

---

## 🔄 Regular Maintenance

### **1. Weekly Tasks**

#### **System Health Check**
```bash
#!/bin/bash
# Weekly health check script
echo "=== Weekly Fortress Health Check ==="

# Check cluster health
kubectl cluster-info
kubectl get nodes

# Check application status
kubectl get pods -n fortress-production
kubectl get services -n fortress-production

# Check autoscaling
kubectl get hpa -n fortress-production

# Check monitoring
kubectl get pods -n monitoring

# Check backups
kubectl get pvc -n fortress-production

echo "=== Health check completed ==="
```

#### **Performance Review**
```bash
# Generate weekly performance report
kubectl top pods -n fortress-production > weekly-performance-$(date +%Y%m%d).log

# Check alerts
kubectl get events -n fortress-production --sort-by='.lastTimestamp' > weekly-events-$(date +%Y%m%d).log

# Review metrics
curl -s "http://prometheus-server:9090/api/v1/query_range?query=rate(fortress_http_requests_total[1w])&start=1w ago&end=now" > weekly-metrics-$(date +%Y%m%d).json
```

### **2. Monthly Tasks**

#### **Security Updates**
```bash
# Check for security updates
kubectl get pods -n fortress-production -o jsonpath='{.items[*].spec.containers[*].image}' | tr ' ' '\n' | sort -u > current-images.txt

# Update base images
helm upgrade fortress-production helm/fortress \
  --namespace fortress-production \
  --set image.tag=latest-security \
  --wait --timeout=15m
```

#### **Capacity Planning**
```bash
# Analyze resource usage trends
kubectl top pods -n fortress-production --no-headers | awk '{sum+=$3} END {print "Total Memory:", sum/1024, "Gi"}'

# Review scaling events
kubectl describe hpa fortress-production -n fortress-production | grep -A 10 "Events"

# Plan capacity upgrades
kubectl get nodes -o wide
```

---

## 📞 Escalation Procedures

### **1. Escalation Levels**

#### **Level 1: Standard Operations**
- **Response Time**: 1 hour
- **Contact**: ops-team@fortress-db.com
- **Procedures**: Standard troubleshooting

#### **Level 2: Critical Issues**
- **Response Time**: 15 minutes
- **Contact**: critical-ops@fortress-db.com
- **Procedures**: Emergency response procedures

#### **Level 3: Major Incidents**
- **Response Time**: 5 minutes
- **Contact**: emergency@fortress-db.com
- **Procedures**: Incident response team activation

### **2. Communication Protocols**

#### **Internal Communication**
- **Slack**: #fortress-operations
- **Email**: ops-team@fortress-db.com
- **Pager**: +1-555-FORTRESS

#### **External Communication**
- **Status Page**: status.fortress-db.com
- **Twitter**: @FortressStatus
- **Customer Support**: support@fortress-db.com

---

## 📚 Documentation Updates

### **1. Runbook Maintenance**

#### **Regular Updates**
- Update procedures based on incident learnings
- Add new troubleshooting steps
- Update contact information
- Revise escalation procedures

#### **Version Control**
- Track all changes in Git
- Tag releases with runbook version
- Maintain change log
- Review quarterly

### **2. Knowledge Base**

#### **Documentation Requirements**
- Architecture diagrams
- Network topology
- Security policies
- Performance benchmarks
- Recovery procedures

---

**This operational runbook provides comprehensive procedures for managing Fortress in production, ensuring high availability, security, and performance.**
