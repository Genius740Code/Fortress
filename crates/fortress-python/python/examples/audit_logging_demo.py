#!/usr/bin/env python3
"""
Audit logging demo using Fortress Python SDK
"""

import asyncio
import fortress
from datetime import datetime, timedelta
import json


async def main():
    print("📋 Fortress Audit Logging Demo")
    print("=" * 40)
    
    # Create audit logger with custom configuration
    audit_config = fortress.AuditConfigWrapper(
        enabled=True,
        level="detailed",
        storage_backend="local",
        storage_path="./audit_logs",
        retention_days=30,
        include_sensitive_data=False,
        log_format="json"
    )
    
    audit_logger = fortress.AuditLogger(audit_config)
    print("Audit logger created with detailed configuration")
    print()
    
    # Simulate various operations and log them
    print("Simulating operations and logging audit events...")
    
    # User authentication event
    await audit_logger.log_event(
        event_type="authentication",
        user_id="user123",
        action="login",
        resource="system",
        result="success",
        details={
            "ip_address": "192.168.1.100",
            "user_agent": "Fortress-CLI/1.0",
            "timestamp": datetime.now().isoformat()
        }
    )
    
    # Key generation event
    await audit_logger.log_event(
        event_type="key_management",
        user_id="user123",
        action="generate_key",
        resource="encryption_keys",
        result="success",
        details={
            "algorithm": "aegis256",
            "key_id": "key_456",
            "key_size": 32,
            "purpose": "data_encryption"
        }
    )
    
    # Data encryption event
    await audit_logger.log_event(
        event_type="encryption",
        user_id="user123",
        action="encrypt",
        resource="user_data",
        result="success",
        details={
            "algorithm": "aegis256",
            "data_size": 1024,
            "encryption_time_ms": 15,
            "key_id": "key_456"
        }
    )
    
    # Failed decryption attempt
    await audit_logger.log_event(
        event_type="encryption",
        user_id="user789",
        action="decrypt",
        resource="user_data",
        result="failure",
        details={
            "error": "Invalid key",
            "attempt_count": 3,
            "ip_address": "192.168.1.200"
        }
    )
    
    # Policy evaluation event
    await audit_logger.log_event(
        event_type="authorization",
        user_id="user123",
        action="evaluate_policy",
        resource="policy_engine",
        result="success",
        details={
            "policy_id": "policy_001",
            "role": "developer",
            "decision": "allow",
            "processing_time_ms": 5
        }
    )
    
    # Tenant management event
    await audit_logger.log_event(
        event_type="tenant_management",
        user_id="admin001",
        action="create_tenant",
        resource="tenant_registry",
        result="success",
        details={
            "tenant_id": "tenant_abc123",
            "tenant_name": "New Corp",
            "plan": "enterprise",
            "resource_limits": {
                "max_keys": 1000,
                "max_storage_gb": 100
            }
        }
    )
    
    # Configuration change event
    await audit_logger.log_event(
        event_type="configuration",
        user_id="admin001",
        action="update_config",
        resource="system_config",
        result="success",
        details={
            "config_section": "encryption",
            "changed_fields": ["key_rotation_days", "default_algorithm"],
            "old_values": {
                "key_rotation_days": 90,
                "default_algorithm": "aes256gcm"
            },
            "new_values": {
                "key_rotation_days": 60,
                "default_algorithm": "aegis256"
            }
        }
    )
    
    print("Logged 8 audit events")
    print()
    
    # Query audit logs
    print("Querying audit logs...")
    
    # Get recent events
    recent_events = await audit_logger.get_recent_events(limit=5)
    print(f"Recent {len(recent_events)} events:")
    for event in recent_events:
        print(f"  [{event.timestamp}] {event.event_type}: {event.action} by {event.user_id} - {event.result}")
    
    print()
    
    # Query by user
    print("Events for user123:")
    user_events = await audit_logger.get_events_by_user("user123", limit=10)
    for event in user_events:
        print(f"  [{event.timestamp}] {event.event_type}: {event.action} - {event.result}")
    
    print()
    
    # Query by event type
    print("Encryption events:")
    encryption_events = await audit_logger.get_events_by_type("encryption", limit=10)
    for event in encryption_events:
        print(f"  [{event.timestamp}] {event.action} by {event.user_id} - {event.result}")
    
    print()
    
    # Query failed events
    print("Failed events:")
    failed_events = await audit_logger.get_failed_events(limit=10)
    for event in failed_events:
        print(f"  [{event.timestamp}] {event.event_type}: {event.action} by {event.user_id} - {event.result}")
        if event.details and "error" in event.details:
            print(f"    Error: {event.details['error']}")
    
    print()
    
    # Time-based queries
    print("Events from last hour:")
    one_hour_ago = datetime.now() - timedelta(hours=1)
    recent_hour_events = await audit_logger.get_events_by_time_range(
        start_time=one_hour_ago,
        end_time=datetime.now()
    )
    print(f"Found {len(recent_hour_events)} events in the last hour")
    
    print()
    
    # Generate audit report
    print("Generating audit report...")
    report_start = datetime.now() - timedelta(days=1)
    report_end = datetime.now()
    
    report = await audit_logger.generate_report(
        start_time=report_start,
        end_time=report_end,
        include_summary=True,
        include_details=True
    )
    
    print(f"Audit Report ({report_start.date()} to {report_end.date()})")
    print("=" * 50)
    
    if report.summary:
        print("Summary:")
        print(f"  Total events: {report.summary.get('total_events', 0)}")
        print(f"  Successful events: {report.summary.get('successful_events', 0)}")
        print(f"  Failed events: {report.summary.get('failed_events', 0)}")
        print(f"  Unique users: {report.summary.get('unique_users', 0)}")
        print(f"  Event types: {list(report.summary.get('event_types', {}).keys())}")
    
    print()
    
    if report.top_events:
        print("Top Events:")
        for event_type, count in report.top_events.items():
            print(f"  {event_type}: {count}")
    
    print()
    
    if report.security_alerts:
        print("Security Alerts:")
        for alert in report.security_alerts:
            print(f"  ⚠️  {alert['type']}: {alert['description']}")
            print(f"     Count: {alert['count']}")
            print(f"     Last occurrence: {alert['last_occurrence']}")
    
    print()
    
    # Export audit logs
    print("Exporting audit logs...")
    
    # Export to JSON
    json_export = await audit_logger.export_logs(
        format="json",
        start_time=report_start,
        end_time=report_end
    )
    
    with open("audit_export.json", "w") as f:
        json.dump(json_export, f, indent=2, default=str)
    print("Exported logs to audit_export.json")
    
    # Export to CSV
    csv_export = await audit_logger.export_logs(
        format="csv",
        start_time=report_start,
        end_time=report_end
    )
    
    with open("audit_export.csv", "w") as f:
        f.write(csv_export)
    print("Exported logs to audit_export.csv")
    
    print()
    
    # Test audit log retention
    print("Testing audit log retention...")
    
    # Get retention settings
    retention_info = await audit_logger.get_retention_info()
    print(f"Retention period: {retention_info.retention_days} days")
    print(f"Total log size: {retention_info.total_size_mb} MB")
    print(f"Oldest log entry: {retention_info.oldest_entry}")
    
    # Simulate log cleanup
    cleanup_result = await audit_logger.cleanup_old_logs()
    print(f"Cleanup completed: {cleanup_result.deleted_count} logs deleted")
    print(f"Freed space: {cleanup_result.freed_space_mb} MB")
    
    print()
    
    # Test audit log integrity
    print("Testing audit log integrity...")
    
    integrity_check = await audit_logger.verify_integrity()
    if integrity_check.valid:
        print("✅ Audit log integrity verified")
        print(f"  Checked {integrity_check.checked_entries} entries")
        print(f"  Checksum: {integrity_check.checksum}")
    else:
        print("❌ Audit log integrity issues detected")
        for issue in integrity_check.issues:
            print(f"  - {issue}")
    
    print()
    
    # Clean up
    print("Cleaning up demo data...")
    
    # Clear test audit logs
    await audit_logger.clear_test_logs()
    print("Cleared test audit logs")
    
    print()
    print("🎉 Audit logging demo completed successfully!")
    print("📁 Check audit_export.json and audit_export.csv for exported logs")


if __name__ == "__main__":
    asyncio.run(main())
