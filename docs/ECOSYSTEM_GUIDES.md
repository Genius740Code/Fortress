# Fortress Ecosystem Guides

Comprehensive guides for using Fortress across different programming languages and platforms.

## Table of Contents

- [Overview](#overview)
- [Rust Ecosystem](#rust-ecosystem)
- [Python Ecosystem](#python-ecosystem)
- [Node.js/JavaScript Ecosystem](#nodejsjavascript-ecosystem)
- [Go Ecosystem](#go-ecosystem)
- [Java Ecosystem](#java-ecosystem)
- [.NET Ecosystem](#net-ecosystem)
- [Ruby Ecosystem](#ruby-ecosystem)
- [PHP Ecosystem](#php-ecosystem)
- [Mobile Development](#mobile-development)
- [Web Framework Integration](#web-framework-integration)
- [Cloud Platform Integration](#cloud-platform-integration)

## Overview

Fortress provides native SDKs and integrations for major programming languages and platforms. Each ecosystem offers:

- **Native SDKs**: Optimized for the specific language
- **Type Safety**: Full type definitions and validation
- **Async Support**: Non-blocking operations where supported
- **Error Handling**: Language-appropriate error handling
- **Documentation**: Comprehensive examples and guides

## Rust Ecosystem

### Packages

| Package | Description | Version |
|---------|-------------|---------|
| `fortress-core` | Core Fortress library | 1.0.0 |
| `fortress-cli` | Command-line interface | 1.0.0 |
| `fortress-server` | Server binary | 1.0.0 |

### Installation

```toml
[dependencies]
fortress-core = "1.0.0"
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
```

### Key Features

- **Zero-copy operations**: Maximum performance
- **Compile-time guarantees**: Type safety at compile time
- **Async/await**: Full async support with tokio
- **Memory safety**: Rust's ownership model
- **Cross-platform**: Linux, macOS, Windows

### Examples

#### Basic Usage
```rust
use fortress_core::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct User {
    id: String,
    name: String,
    email: String,
    ssn: String, // Will be encrypted
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fortress = Fortress::builder()
        .with_algorithm(Aegis256::new())
        .build()
        .await?;

    let db = fortress.create_database("myapp").await?;
    let table = db.create_table("users", vec![
        FieldDefinition::new("id", FieldType::Text),
        FieldDefinition::new("name", FieldType::Text),
        FieldDefinition::new("email", FieldType::Text),
        FieldDefinition::new("ssn", FieldType::Encrypted),
    ]).await?;

    let user = User {
        id: "123".to_string(),
        name: "Alice Johnson".to_string(),
        email: "alice@example.com".to_string(),
        ssn: "123-45-6789".to_string(),
    };

    let result = table.insert(&user).await?;
    println!("User inserted: {}", result.id);

    Ok(())
}
```

#### Field-Level Encryption
```rust
use fortress_core::encryption::FieldEncryptionManager;

#[derive(Serialize, Deserialize)]
struct UserProfile {
    name: String,
    email: String,
    ssn: String, // Will be encrypted
    credit_card: String, // Will be encrypted
}

async fn encrypt_sensitive_fields() -> Result<(), FortressError> {
    let manager = FieldEncryptionManager::new(config).await?;
    
    let profile = UserProfile {
        name: "Alice Johnson".to_string(),
        email: "alice@example.com".to_string(),
        ssn: "123-45-6789".to_string(),
        credit_card: "4111-1111-1111-1111".to_string(),
    };
    
    let encrypted = manager.encrypt_fields(&profile).await?;
    println!("SSN encrypted: {}", encrypted.ssn);
    
    Ok(())
}
```

#### Key Management
```rust
use fortress_core::key::KeyManager;

async fn key_management_example() -> Result<(), FortressError> {
    let manager = KeyManager::new().await?;
    
    // Generate new key
    let key = manager.generate_key(&Aegis256::new())?;
    println!("Generated key: {}", key.id);
    
    // Rotate key
    let rotated_key = manager.rotate_key(&key.id).await?;
    println!("Rotated key: {}", rotated_key.id);
    
    // List keys
    let keys = manager.list_keys().await?;
    for key in keys {
        println!("Key: {} (Algorithm: {})", key.id, key.algorithm);
    }
    
    Ok(())
}
```

### Framework Integration

#### Actix Web
```rust
use actix_web::{web, App, HttpServer, Result};
use fortress_core::prelude::*;

async fn create_user(
    fortress: web::Data<Fortress>,
    user: web::Json<User>,
) -> Result<web::Json<User>> {
    let db = fortress.get_database("myapp").await?;
    let table = db.get_table("users").await?;
    
    let result = table.insert(&user.into_inner()).await?;
    Ok(web::Json(result))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let fortress = Fortress::builder().build().await?;
    
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(fortress.clone()))
            .route("/users", web::post().to(create_user))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

#### Axum
```rust
use axum::{extract::State, response::Json, routing::post, Router};
use fortress_core::prelude::*;

async fn create_user(
    State(fortress): State<Fortress>,
    Json(user): Json<User>,
) -> Result<Json<User>, FortressError> {
    let db = fortress.get_database("myapp").await?;
    let table = db.get_table("users").await?;
    
    let result = table.insert(&user).await?;
    Ok(Json(result))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fortress = Fortress::builder().build().await?;
    
    let app = Router::new()
        .route("/users", post(create_user))
        .with_state(fortress);
    
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}
```

## Python Ecosystem

### Packages

| Package | Description | Version |
|---------|-------------|---------|
| `fortress-db` | Main Fortress client | 1.0.0 |
| `fortress-cli` | Command-line interface | 1.0.0 |

### Installation

```bash
# Basic installation
pip install fortress-db

# With development dependencies
pip install fortress-db[dev]

# With all optional dependencies
pip install fortress-db[all]
```

### Key Features

- **Async Support**: Full async/await with asyncio
- **Type Hints**: Complete type annotations
- **Pydantic Integration**: Data validation and serialization
- **Context Managers**: Resource management
- **Rich Error Handling**: Detailed exceptions

### Examples

#### Basic Usage
```python
from fortress import Fortress
from fortress.models import User
import asyncio

async def main():
    fortress = Fortress(
        server_url="http://localhost:8080",
        api_key="your-api-key"
    )

    db = await fortress.create_database("myapp")
    
    table = await db.create_table("users", [
        {"name": "id", "type": "text", "primary_key": True},
        {"name": "name", "type": "text"},
        {"name": "email", "type": "text", "unique": True},
        {"name": "ssn", "type": "encrypted", "sensitivity": "high"}
    ])

    user = await table.insert({
        "id": "123",
        "name": "Alice Johnson",
        "email": "alice@example.com",
        "ssn": "123-45-6789"
    })

    print(f"User created: {user['name']}")

asyncio.run(main())
```

#### Pydantic Models
```python
from pydantic import BaseModel
from fortress import Fortress
from typing import Optional

class User(BaseModel):
    id: str
    name: str
    email: str
    ssn: Optional[str] = None  # Will be encrypted

async def create_user_with_validation():
    fortress = Fortress("http://localhost:8080")
    db = await fortress.create_database("myapp")
    
    # Pydantic handles validation
    user = User(
        id="123",
        name="Alice Johnson",
        email="alice@example.com",
        ssn="123-45-6789"
    )
    
    table = await db.create_table("users", User.schema())
    result = await table.insert(user.dict())
    
    return result
```

#### Context Manager
```python
from fortress import Fortress
from contextlib import asynccontextmanager

@asynccontextmanager
async def fortress_transaction():
    fortress = Fortress("http://localhost:8080")
    async with fortress.transaction() as tx:
        yield tx

async def atomic_operations():
    async with fortress_transaction() as tx:
        # All operations are atomic
        user1 = await tx.insert("users", {"name": "Alice"})
        user2 = await tx.insert("users", {"name": "Bob"})
        
        # If any operation fails, all are rolled back
        return [user1, user2]
```

### Framework Integration

#### FastAPI
```python
from fastapi import FastAPI, Depends, HTTPException
from fortress import Fortress
from pydantic import BaseModel

app = FastAPI()
fortress = Fortress("http://localhost:8080")

class UserCreate(BaseModel):
    name: str
    email: str
    ssn: str

async def get_fortress():
    return fortress

@app.post("/users")
async def create_user(
    user: UserCreate,
    fortress: Fortress = Depends(get_fortress)
):
    try:
        db = await fortress.get_database("myapp")
        table = await db.get_table("users")
        result = await table.insert(user.dict())
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
```

#### Django Integration
```python
# fortress_django/models.py
from django.db import models
from fortress import Fortress

class EncryptedField(models.TextField):
    def __init__(self, *args, **kwargs):
        self.fortress = Fortress("http://localhost:8080")
        super().__init__(*args, **kwargs)

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return self.fortress.decrypt(value)

    def to_python(self, value):
        if value is None:
            return value
        return self.fortress.encrypt(value)

class User(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    ssn = EncryptedField()

    class Meta:
        app_label = 'fortress_django'
```

## Node.js/JavaScript Ecosystem

### Packages

| Package | Description | Version |
|---------|-------------|---------|
| `fortress-db` | Main Fortress client | 1.0.0 |
| `fortress-cli` | Command-line interface | 1.0.0 |
| `@types/fortress-db` | TypeScript definitions | 1.0.0 |

### Installation

```bash
# npm
npm install fortress-db

# yarn
yarn add fortress-db

# TypeScript support
npm install @types/fortress-db
```

### Key Features

- **Promise-based**: Full async/await support
- **TypeScript**: Complete type definitions
- **Event-driven**: Event emitter for real-time updates
- **Stream Support**: Node.js stream integration
- **Middleware**: Express/Koa middleware

### Examples

#### Basic Usage
```javascript
const { Fortress } = require('fortress-db');

async function main() {
    const fortress = new Fortress({
        serverUrl: 'http://localhost:8080',
        apiKey: 'your-api-key'
    });

    const db = await fortress.createDatabase('myapp');
    
    const table = await db.createTable('users', [
        { name: 'id', type: 'text', primaryKey: true },
        { name: 'name', type: 'text' },
        { name: 'email', type: 'text', unique: true },
        { name: 'ssn', type: 'encrypted', sensitivity: 'high' }
    ]);

    const user = await table.insert({
        id: '123',
        name: 'Alice Johnson',
        email: 'alice@example.com',
        ssn: '123-45-6789'
    });

    console.log(`User created: ${user.name}`);
}

main().catch(console.error);
```

#### TypeScript Usage
```typescript
import { Fortress, User, TableSchema } from 'fortress-db';

interface AppUser {
    id: string;
    name: string;
    email: string;
    ssn?: string;
}

async function main() {
    const fortress = new Fortress<AppUser>({
        serverUrl: 'http://localhost:8080',
        apiKey: 'your-api-key'
    });

    const schema: TableSchema = [
        { name: 'id', type: 'text', primaryKey: true },
        { name: 'name', type: 'text' },
        { name: 'email', type: 'text', unique: true },
        { name: 'ssn', type: 'encrypted', sensitivity: 'high' }
    ];

    const db = await fortress.createDatabase('myapp');
    const table = await db.createTable<AppUser>('users', schema);

    const user = await table.insert({
        id: '123',
        name: 'Alice Johnson',
        email: 'alice@example.com',
        ssn: '123-45-6789'
    });

    console.log(`User: ${user.name}`);
}
```

#### Event-Driven Updates
```javascript
const { Fortress } = require('fortress-db');
const EventEmitter = require('events');

class FortressApp extends EventEmitter {
    constructor() {
        super();
        this.fortress = new Fortress({
            serverUrl: 'http://localhost:8080'
        });
        
        this.setupEventHandlers();
    }

    setupEventHandlers() {
        this.fortress.on('dataChange', (event) => {
            this.emit('userUpdate', event);
        });

        this.fortress.on('keyRotation', (event) => {
            this.emit('securityEvent', event);
        });
    }

    async createUser(userData) {
        const result = await this.fortress
            .getDatabase('myapp')
            .getTable('users')
            .insert(userData);
        
        this.emit('userCreated', result);
        return result;
    }
}

const app = new FortressApp();

app.on('userCreated', (user) => {
    console.log(`New user: ${user.name}`);
});

app.on('userUpdate', (event) => {
    console.log(`User updated: ${event.userId}`);
});
```

### Framework Integration

#### Express.js
```javascript
const express = require('express');
const { Fortress } = require('fortress-db');

const app = express();
const fortress = new Fortress({
    serverUrl: 'http://localhost:8080',
    apiKey: process.env.FORTRESS_API_KEY
});

// Middleware
app.use(express.json());

// Routes
app.post('/users', async (req, res) => {
    try {
        const db = await fortress.getDatabase('myapp');
        const table = await db.getTable('users');
        const user = await table.insert(req.body);
        res.json(user);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Fortress middleware for authentication
const fortressAuth = (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    // Verify token with Fortress
    fortress.verifyToken(token)
        .then(decoded => {
            req.user = decoded;
            next();
        })
        .catch(() => {
            res.status(401).json({ error: 'Invalid token' });
        });
};

app.get('/protected-data', fortressAuth, (req, res) => {
    res.json({ message: 'Protected data', user: req.user });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
```

#### Koa.js
```javascript
const Koa = require('koa');
const Router = require('@koa/router');
const { Fortress } = require('fortress-db');

const app = new Koa();
const router = new Router();
const fortress = new Fortress({
    serverUrl: 'http://localhost:8080'
});

// Fortress middleware
const fortressMiddleware = async (ctx, next) => {
    const token = ctx.headers.authorization?.replace('Bearer ', '');
    if (!token) {
        ctx.status = 401;
        ctx.body = { error: 'No token provided' };
        return;
    }

    try {
        ctx.state.user = await fortress.verifyToken(token);
        await next();
    } catch (error) {
        ctx.status = 401;
        ctx.body = { error: 'Invalid token' };
    }
};

router.post('/users', async (ctx) => {
    const db = await fortress.getDatabase('myapp');
    const table = await db.getTable('users');
    const user = await table.insert(ctx.request.body);
    ctx.body = user;
});

router.get('/protected', fortressMiddleware, async (ctx) => {
    ctx.body = { message: 'Protected data', user: ctx.state.user };
});

app.use(router.routes());
app.listen(3000);
```

## Go Ecosystem

### Packages

| Package | Description | Version |
|---------|-------------|---------|
| `fortress-go` | Main Fortress client | 1.0.0 |
| `fortress-cli` | Command-line interface | 1.0.0 |

### Installation

```bash
# Go modules
go get github.com/fortress-security/fortress/fortress-go

# CLI tool
go install github.com/fortress-security/fortress/fortress-go/cmd/fortress-cli@latest
```

### Key Features

- **Goroutines**: Concurrent operations
- **Context Support**: Cancellation and timeouts
- **Interfaces**: Clean abstractions
- **Error Handling**: Explicit error handling
- **Performance**: High-performance HTTP client

### Examples

#### Basic Usage
```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/fortress-security/fortress/fortress-go"
)

type User struct {
    ID    string `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
    SSN   string `json:"ssn"` // Will be encrypted
}

func main() {
    client, err := fortress.NewClient(&fortress.Config{
        ServerURL: "http://localhost:8080",
        APIKey:    "your-api-key",
    })
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    db, err := client.CreateDatabase(ctx, "myapp")
    if err != nil {
        log.Fatal(err)
    }

    schema := []fortress.FieldDefinition{
        {Name: "id", Type: "text", PrimaryKey: true},
        {Name: "name", Type: "text"},
        {Name: "email", Type: "text", Unique: true},
        {Name: "ssn", Type: "encrypted", Sensitivity: "high"},
    }

    table, err := db.CreateTable(ctx, "users", schema)
    if err != nil {
        log.Fatal(err)
    }

    user := User{
        ID:    "123",
        Name:  "Alice Johnson",
        Email: "alice@example.com",
        SSN:   "123-45-6789",
    }

    result, err := table.Insert(ctx, user)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("User created: %s\n", result.Name)
}
```

#### Concurrent Operations
```go
package main

import (
    "context"
    "fmt"
    "sync"
    "time"

    "github.com/fortress-security/fortress/fortress-go"
)

func main() {
    client, _ := fortress.NewClient(&fortress.Config{
        ServerURL: "http://localhost:8080",
    })

    ctx := context.Background()
    db, _ := client.GetDatabase(ctx, "myapp")
    table, _ := db.GetTable(ctx, "users")

    // Concurrent insertions
    var wg sync.WaitGroup
    users := make([]User, 100)

    for i := 0; i < 100; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()
            
            user := User{
                ID:    fmt.Sprintf("user-%d", id),
                Name:  fmt.Sprintf("User %d", id),
                Email: fmt.Sprintf("user%d@example.com", id),
            }
            
            result, err := table.Insert(ctx, user)
            if err != nil {
                fmt.Printf("Error inserting user %d: %v\n", id, err)
                return
            }
            
            users[id] = result
        }(i)
    }

    wg.Wait()
    fmt.Printf("Inserted %d users\n", len(users))
}
```

### Framework Integration

#### Gin Web Framework
```go
package main

import (
    "net/http"
    "strconv"

    "github.com/gin-gonic/gin"
    "github.com/fortress-security/fortress/fortress-go"
)

type User struct {
    Name  string `json:"name"`
    Email string `json:"email"`
    SSN   string `json:"ssn"`
}

func main() {
    client, _ := fortress.NewClient(&fortress.Config{
        ServerURL: "http://localhost:8080",
    })

    r := gin.Default()

    // Middleware to add Fortress client to context
    r.Use(func(c *gin.Context) {
        c.Set("fortress", client)
        c.Next()
    })

    r.POST("/users", func(c *gin.Context) {
        client := c.MustGet("fortress").(*fortress.Client)
        
        var user User
        if err := c.ShouldBindJSON(&user); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        db, _ := client.GetDatabase(c.Request.Context(), "myapp")
        table, _ := db.GetTable(c.Request.Context(), "users")
        
        result, err := table.Insert(c.Request.Context(), user)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
            return
        }

        c.JSON(http.StatusCreated, result)
    })

    r.GET("/users/:id", func(c *gin.Context) {
        client := c.MustGet("fortress").(*fortress.Client)
        id := c.Param("id")

        db, _ := client.GetDatabase(c.Request.Context(), "myapp")
        table, _ := db.GetTable(c.Request.Context(), "users")
        
        var user User
        err := table.Get(c.Request.Context(), id, &user)
        if err != nil {
            c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
            return
        }

        c.JSON(http.StatusOK, user)
    })

    r.Run(":8080")
}
```

## Java Ecosystem

### Maven Dependencies

```xml
<dependency>
    <groupId>org.fortress</groupId>
    <artifactId>fortress-java</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Gradle Dependencies

```gradle
implementation 'org.fortress:fortress-java:1.0.0'
```

### Examples

#### Basic Usage
```java
import org.fortress.Fortress;
import org.fortress.FortressClient;
import org.fortress.models.User;

public class FortressExample {
    public static void main(String[] args) {
        FortressClient client = Fortress.builder()
            .serverUrl("http://localhost:8080")
            .apiKey("your-api-key")
            .build();

        // Create database
        Database db = client.createDatabase("myapp");
        
        // Create table
        Table<User> table = db.createTable("users", User.class);
        
        // Insert user
        User user = new User();
        user.setId("123");
        user.setName("Alice Johnson");
        user.setEmail("alice@example.com");
        user.setSsn("123-45-6789"); // Will be encrypted
        
        User result = table.insert(user);
        System.out.println("User created: " + result.getName());
    }
}
```

#### Spring Boot Integration
```java
@RestController
@RequestMapping("/users")
public class UserController {
    
    @Autowired
    private FortressClient fortressClient;
    
    @PostMapping
    public User createUser(@RequestBody User user) {
        Database db = fortressClient.getDatabase("myapp");
        Table<User> table = db.getTable("users");
        return table.insert(user);
    }
    
    @GetMapping("/{id}")
    public User getUser(@PathVariable String id) {
        Database db = fortressClient.getDatabase("myapp");
        Table<User> table = db.getTable("users");
        return table.get(id);
    }
}

@Configuration
public class FortressConfig {
    
    @Bean
    public FortressClient fortressClient() {
        return Fortress.builder()
            .serverUrl("http://localhost:8080")
            .apiKey("${fortress.api.key}")
            .build();
    }
}
```

## .NET Ecosystem

### NuGet Packages

```bash
dotnet add package Fortress.Net
```

### Examples

#### Basic Usage
```csharp
using Fortress;
using Fortress.Models;

public class Program
{
    public static async Task Main(string[] args)
    {
        var client = new FortressClient(new FortressOptions
        {
            ServerUrl = "http://localhost:8080",
            ApiKey = "your-api-key"
        });

        // Create database
        var db = await client.CreateDatabaseAsync("myapp");
        
        // Create table
        var table = await db.CreateTableAsync<User>("users");
        
        // Insert user
        var user = new User
        {
            Id = "123",
            Name = "Alice Johnson",
            Email = "alice@example.com",
            Ssn = "123-45-6789" // Will be encrypted
        };
        
        var result = await table.InsertAsync(user);
        Console.WriteLine($"User created: {result.Name}");
    }
}

public class User
{
    public string Id { get; set; }
    public string Name { get; set; }
    public string Email { get; set; }
    [Encrypted(Sensitivity = "high")]
    public string Ssn { get; set; }
}
```

#### ASP.NET Core Integration
```csharp
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly IFortressClient _fortressClient;

    public UsersController(IFortressClient fortressClient)
    {
        _fortressClient = fortressClient;
    }

    [HttpPost]
    public async Task<ActionResult<User>> CreateUser([FromBody] CreateUserRequest request)
    {
        var db = await _fortressClient.GetDatabaseAsync("myapp");
        var table = await db.GetTableAsync<User>("users");
        
        var user = new User
        {
            Id = Guid.NewGuid().ToString(),
            Name = request.Name,
            Email = request.Email,
            Ssn = request.Ssn
        };
        
        var result = await table.InsertAsync(user);
        return CreatedAtAction(nameof(GetUser), new { id = result.Id }, result);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<User>> GetUser(string id)
    {
        var db = await _fortressClient.GetDatabaseAsync("myapp");
        var table = await db.GetTableAsync<User>("users");
        
        var user = await table.GetAsync(id);
        if (user == null)
        {
            return NotFound();
        }
        
        return Ok(user);
    }
}

public class CreateUserRequest
{
    public string Name { get; set; }
    public string Email { get; set; }
    public string Ssn { get; set; }
}

// Startup.cs
public void ConfigureServices(IServiceCollection services)
{
    services.AddFortressClient(options =>
    {
        options.ServerUrl = "http://localhost:8080";
        options.ApiKey = Configuration["Fortress:ApiKey"];
    });
    
    services.AddControllers();
}
```

## Mobile Development

### React Native

```bash
npm install fortress-react-native
```

```javascript
import { Fortress } from 'fortress-react-native';

const fortress = new Fortress({
    serverUrl: 'https://your-fortress-server.com',
    apiKey: 'your-api-key'
});

async function createUser(userData) {
    try {
        const db = await fortress.getDatabase('myapp');
        const table = await db.getTable('users');
        const user = await table.insert(userData);
        return user;
    } catch (error) {
        console.error('Error creating user:', error);
        throw error;
    }
}
```

### Flutter

```yaml
dependencies:
  fortress_flutter: ^1.0.0
```

```dart
import 'package:fortress_flutter/fortress_flutter.dart';

class UserService {
  final Fortress _fortress = Fortress(
    serverUrl: 'https://your-fortress-server.com',
    apiKey: 'your-api-key',
  );

  Future<User> createUser(UserData userData) async {
    try {
      final db = await _fortress.getDatabase('myapp');
      final table = await db.getTable('users');
      return await table.insert(userData);
    } catch (e) {
      throw Exception('Failed to create user: $e');
    }
  }
}
```

## Web Framework Integration

### Next.js

```javascript
// pages/api/users.js
import { Fortress } from 'fortress-db';

const fortress = new Fortress({
    serverUrl: process.env.FORTRESS_URL,
    apiKey: process.env.FORTRESS_API_KEY,
});

export default async function handler(req, res) {
    if (req.method === 'POST') {
        try {
            const db = await fortress.getDatabase('myapp');
            const table = await db.getTable('users');
            const user = await table.insert(req.body);
            res.status(201).json(user);
        } catch (error) {
            res.status(400).json({ error: error.message });
        }
    } else {
        res.setHeader('Allow', ['POST']);
        res.status(405).end(`Method ${req.method} Not Allowed`);
    }
}
```

### Rails

```ruby
# Gemfile
gem 'fortress-ruby'

# app/models/user.rb
class User < ApplicationRecord
  include Fortress::Model
  
  encrypts :ssn, :credit_card
  
  validates :name, presence: true
  validates :email, presence: true, uniqueness: true
end

# app/controllers/users_controller.rb
class UsersController < ApplicationController
  def create
    @user = User.new(user_params)
    
    if @user.save
      render json: @user, status: :created
    else
      render json: @user.errors, status: :unprocessable_entity
    end
  end

  private

  def user_params
    params.require(:user).permit(:name, :email, :ssn)
  end
end
```

## Cloud Platform Integration

### AWS Lambda

```javascript
// lambda-handler.js
const { Fortress } = require('fortress-db');

const fortress = new Fortress({
    serverUrl: process.env.FORTRESS_URL,
    apiKey: process.env.FORTRESS_API_KEY,
});

exports.handler = async (event) => {
    const { name, email, ssn } = JSON.parse(event.body);
    
    try {
        const db = await fortress.getDatabase('myapp');
        const table = await db.getTable('users');
        const user = await table.insert({ name, email, ssn });
        
        return {
            statusCode: 201,
            body: JSON.stringify(user),
        };
    } catch (error) {
        return {
            statusCode: 400,
            body: JSON.stringify({ error: error.message }),
        };
    }
};
```

### Google Cloud Functions

```python
# main.py
import os
from fortress import Fortress

fortress = Fortress(
    server_url=os.environ.get('FORTRESS_URL'),
    api_key=os.environ.get('FORTRESS_API_KEY')
)

def create_user(request):
    request_json = request.get_json()
    
    try:
        db = await fortress.get_database('myapp')
        table = await db.get_table('users')
        user = await table.insert(request_json)
        
        return {'user': user}, 201
    except Exception as e:
        return {'error': str(e)}, 400
```

### Azure Functions

```csharp
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Fortress;

public static class CreateUserFunction
{
    [FunctionName("CreateUser")]
    public static async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post", Route = "users")] HttpRequest req,
        ILogger log)
    {
        var client = new FortressClient(Environment.GetEnvironmentVariable("FORTRESS_URL"));
        
        var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
        var userData = JsonSerializer.Deserialize<UserData>(requestBody);
        
        try {
            var db = await client.GetDatabaseAsync("myapp");
            var table = await db.GetTableAsync<User>("users");
            var user = await table.InsertAsync(userData);
            
            return new OkObjectResult(user);
        } catch (Exception ex) {
            return new BadRequestObjectResult(new { error = ex.Message });
        }
    }
}
```

---

This guide provides comprehensive ecosystem coverage for Fortress. For more detailed information about specific integrations, see the individual ecosystem documentation or visit our [GitHub repository](https://github.com/fortress-security/fortress).
