#!/usr/bin/env python3
"""
Fortress API Client Example

This example demonstrates how to use the Fortress REST API
for database management, table operations, and data CRUD.
"""

import requests
import json
import uuid
from datetime import datetime
from typing import Dict, Any, List

class FortressClient:
    """Simple Fortress REST API client"""
    
    def __init__(self, base_url: str = "http://localhost:8080", api_key: str = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers.update({"X-API-Key": api_key})
    
    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make HTTP request to the API"""
        url = f"{self.base_url}{endpoint}"
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response.json()
    
    # ==================== DATABASE MANAGEMENT ====================
    
    def create_database(self, name: str, algorithm: str = "aegis256", 
                       key_rotation_interval: str = "23h", 
                       storage_path: str = "./data") -> Dict[str, Any]:
        """Create a new database"""
        data = {
            "name": name,
            "algorithm": algorithm,
            "key_rotation_interval": key_rotation_interval,
            "storage_path": storage_path
        }
        return self._request("POST", "/api/v1/databases", json=data)
    
    def list_databases(self) -> Dict[str, Any]:
        """List all databases"""
        return self._request("GET", "/api/v1/databases")
    
    def get_database(self, name: str) -> Dict[str, Any]:
        """Get database information"""
        return self._request("GET", f"/api/v1/databases/{name}")
    
    def delete_database(self, name: str) -> Dict[str, Any]:
        """Delete a database"""
        return self._request("DELETE", f"/api/v1/databases/{name}")
    
    # ==================== TABLE MANAGEMENT ====================
    
    def create_table(self, database: str, table_name: str, columns: List[Dict[str, Any]], 
                    encryption: str = "balanced") -> Dict[str, Any]:
        """Create a new table"""
        data = {
            "name": table_name,
            "columns": columns,
            "encryption": encryption
        }
        return self._request("POST", f"/api/v1/databases/{database}/tables", json=data)
    
    def list_tables(self, database: str) -> Dict[str, Any]:
        """List all tables in a database"""
        return self._request("GET", f"/api/v1/databases/{database}/tables")
    
    def get_table_schema(self, database: str, table: str) -> Dict[str, Any]:
        """Get table schema"""
        return self._request("GET", f"/api/v1/databases/{database}/tables/{table}/schema")
    
    def drop_table(self, database: str, table: str) -> Dict[str, Any]:
        """Drop a table"""
        return self._request("DELETE", f"/api/v1/databases/{database}/tables/{table}")
    
    # ==================== DATA OPERATIONS ====================
    
    def insert_data(self, database: str, table: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Insert a single record"""
        return self._request("POST", f"/api/v1/databases/{database}/tables/{table}/data", json=data)
    
    def query_data(self, database: str, table: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Query data from a table"""
        return self._request("GET", f"/api/v1/databases/{database}/tables/{table}/data", params=params or {})
    
    def bulk_insert(self, database: str, table: str, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Bulk insert multiple records"""
        return self._request("POST", f"/api/v1/databases/{database}/tables/{table}/bulk", json={"data": data})
    
    def update_data(self, database: str, table: str, record_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Update a record"""
        return self._request("PUT", f"/api/v1/databases/{database}/tables/{table}/data/{record_id}", json=data)
    
    def delete_data(self, database: str, table: str, record_id: str) -> Dict[str, Any]:
        """Delete a record"""
        return self._request("DELETE", f"/api/v1/databases/{database}/tables/{table}/data/{record_id}")
    
    # ==================== QUERY OPERATIONS ====================
    
    def execute_query(self, database: str, sql: str, parameters: List[Any] = None) -> Dict[str, Any]:
        """Execute a SQL query"""
        data = {
            "sql": sql,
            "parameters": parameters or []
        }
        return self._request("POST", f"/api/v1/databases/{database}/query", json=data)
    
    # ==================== ENCRYPTION MANAGEMENT ====================
    
    def rotate_keys(self, database: str, table: str) -> Dict[str, Any]:
        """Rotate encryption keys"""
        return self._request("POST", f"/api/v1/databases/{database}/tables/{table}/rotate-keys")
    
    def rotate_keys_zero_downtime(self, database: str, table: str) -> Dict[str, Any]:
        """Rotate keys with zero downtime"""
        return self._request("POST", f"/api/v1/databases/{database}/tables/{table}/rotate-keys-zero-downtime")
    
    def get_rotation_status(self, database: str, table: str) -> Dict[str, Any]:
        """Get key rotation status"""
        return self._request("GET", f"/api/v1/databases/{database}/tables/{table}/rotation-status")
    
    def get_encryption_metadata(self, database: str, table: str) -> Dict[str, Any]:
        """Get encryption metadata"""
        return self._request("GET", f"/api/v1/databases/{database}/tables/{table}/encryption-metadata")
    
    # ==================== HEALTH AND METRICS ====================
    
    def health_check(self) -> Dict[str, Any]:
        """Check API health"""
        return self._request("GET", "/health")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get API metrics"""
        return self._request("GET", "/metrics")


def main():
    """Example usage of the Fortress API"""
    
    # Initialize client
    client = FortressClient("http://localhost:8080")
    
    print("🚀 Fortress API Example")
    print("=" * 50)
    
    try:
        # Check health
        print("\n📊 Checking API health...")
        health = client.health_check()
        print(f"✅ API Status: Healthy")
        
        # Create database
        print("\n🗄️  Creating database...")
        db_name = f"example_db_{uuid.uuid4().hex[:8]}"
        db_response = client.create_database(
            name=db_name,
            algorithm="aegis256",
            key_rotation_interval="23h",
            storage_path=f"./data/{db_name}"
        )
        print(f"✅ Database created: {db_name}")
        
        # Create users table
        print("\n📋 Creating users table...")
        table_columns = [
            {"name": "id", "type": "uuid", "primary_key": True, "nullable": False},
            {"name": "name", "type": "text", "nullable": False},
            {"name": "email", "type": "text", "nullable": False},
            {"name": "password", "type": "encrypted", "nullable": False, "encryption": "fortress"},
            {"name": "created_at", "type": "timestamp", "nullable": False}
        ]
        table_response = client.create_table(db_name, "users", table_columns, "balanced")
        print(f"✅ Table created: users")
        
        # Insert sample data
        print("\n📝 Inserting sample users...")
        users = [
            {
                "id": str(uuid.uuid4()),
                "name": "Alice Johnson",
                "email": "alice@example.com",
                "password": "super_secret_password_123",
                "created_at": datetime.utcnow().isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "name": "Bob Smith",
                "email": "bob@example.com", 
                "password": "another_secure_password_456",
                "created_at": datetime.utcnow().isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "name": "Charlie Brown",
                "email": "charlie@example.com",
                "password": "yet_another_password_789",
                "created_at": datetime.utcnow().isoformat()
            }
        ]
        
        # Insert users one by one
        for user in users:
            response = client.insert_data(db_name, "users", user)
            print(f"✅ Inserted user: {user['name']}")
        
        # Query all users
        print("\n🔍 Querying all users...")
        query_response = client.query_data(db_name, "users")
        print(f"✅ Found {query_response['data']['total_count']} users")
        
        # Execute SQL query
        print("\n🔍 Executing SQL query...")
        sql_response = client.execute_query(
            db_name, 
            "SELECT name, email FROM users WHERE name LIKE ?",
            ["Alice%"]
        )
        print(f"✅ SQL query returned {sql_response['data']['total_count']} results")
        
        # Get encryption metadata
        print("\n🔐 Getting encryption metadata...")
        encryption_meta = client.get_encryption_metadata(db_name, "users")
        print(f"✅ Table encryption: {encryption_meta['data']['table_encryption']}")
        print(f"✅ Zero-downtime rotation: {encryption_meta['data']['zero_downtime_enabled']}")
        
        # Update a user
        print("\n✏️  Updating a user...")
        if users:
            user_id = users[0]["id"]
            update_data = {"email": "alice.updated@example.com"}
            update_response = client.update_data(db_name, "users", user_id, update_data)
            print(f"✅ Updated user email")
        
        # List tables
        print("\n📋 Listing tables...")
        tables_response = client.list_tables(db_name)
        print(f"✅ Database has {tables_response['data']['total_count']} tables")
        
        # Get table schema
        print("\n📋 Getting table schema...")
        schema_response = client.get_table_schema(db_name, "users")
        columns = schema_response['data']['columns']
        print(f"✅ Users table has {len(columns)} columns")
        
        # Clean up - delete table and database
        print("\n🧹 Cleaning up...")
        client.drop_table(db_name, "users")
        print("✅ Dropped users table")
        
        client.delete_database(db_name)
        print(f"✅ Deleted database: {db_name}")
        
        print("\n🎉 Example completed successfully!")
        
    except requests.exceptions.ConnectionError:
        print("❌ Error: Could not connect to Fortress API server")
        print("💡 Make sure the server is running on http://localhost:8080")
        print("💡 You can start it with: cargo run --bin fortress-server")
        
    except requests.exceptions.HTTPError as e:
        print(f"❌ HTTP Error: {e}")
        try:
            error_data = e.response.json()
            print(f"   Details: {error_data}")
        except:
            pass
            
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
