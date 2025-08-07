# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a C++ RESTful API server built using httplib and nlohmann/json libraries. It provides a complete CRUD API for user management with Docker containerization and optional Nginx reverse proxy.

## Architecture

### Core Components
- **main.cpp**: Single-file application containing the entire server implementation
- **UserService class**: Thread-safe SQLite database wrapper with mutex protection for concurrent access
- **CacheManager class**: Redis-based caching system for improved performance
- **httplib::Server**: HTTP server handling RESTful endpoints
- **JSON serialization**: Using nlohmann/json for request/response handling
- **SQLite database**: Persistent data storage with automatic schema initialization
- **Redis cache**: High-performance caching layer for user data and JWT blacklisting
- **Structured logging**: Multi-sink logging with console and rotating file outputs

### Key Design Patterns
- Thread-safe database operations using `std::mutex` and `lock_guard`
- Redis caching layer with cache-aside pattern for optimal performance
- JWT token blacklisting for secure authentication invalidation
- Thread-safe cache operations with mutex protection
- CORS middleware implemented as pre-routing handler
- RESTful API design with proper HTTP status codes
- Prepared statements for SQL injection prevention
- Automatic database initialization with sample data
- Comprehensive request/response logging with structured format

## Development Commands

### Local Development
```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get update && apt-get install -y g++ cmake git pkg-config libssl-dev zlib1g-dev libsqlite3-dev sqlite3 libhiredis-dev wget curl build-essential

# Manual compilation (requires Redis++ library)
# Note: For local development, install redis-plus-plus from source
g++ -std=c++17 -pthread -O2 -I/usr/local/include -o api_server main.cpp -lsqlite3 -lssl -lcrypto -lredis++ -lhiredis

# Run the server locally
./api_server
```

### Docker Development
```bash
# Build and start with Docker Compose
docker-compose up --build

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Restart services
docker-compose restart
```

### Authentication & API Testing
```bash
# Health check (no auth required)
curl http://localhost:8080/api/health

# Register new user
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "newuser", "email": "user@example.com", "password": "password123"}'

# Login (get JWT token)
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Use JWT token for protected endpoints
TOKEN="your-jwt-token-here"

# Get all users (protected)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/users

# Create user (protected)
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "Alice Johnson", "email": "alice@example.com"}'

# Get user by ID (protected)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/users/1

# Update user (protected)
curl -X PUT http://localhost:8080/api/users/1 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "Updated Name", "email": "updated@example.com"}'

# Delete user (protected)
curl -X DELETE http://localhost:8080/api/users/1 \
  -H "Authorization: Bearer $TOKEN"

# Check cache statistics (protected)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/cache/stats

# Logout user (blacklist JWT token)
curl -X POST http://localhost:8080/api/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

### Redis Cache Testing
```bash
# Test cache behavior
# 1. Create a user (gets cached automatically)
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "Cache Test User", "email": "cache@example.com"}'

# 2. Get user by ID (first request loads from DB, subsequent from cache)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/users/3
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/users/3  # This should be served from cache

# 3. Check Redis directly (if Redis client is available)
docker exec cpp-api-redis redis-cli keys "*"
docker exec cpp-api-redis redis-cli get "user:3"

# 4. Update user (invalidates cache)
curl -X PUT http://localhost:8080/api/users/3 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "Updated Cache User", "email": "updated-cache@example.com"}'
```

## Dependencies

### Required Libraries
- **httplib**: Header-only HTTP server library (downloaded in Dockerfile)
- **nlohmann/json**: Modern JSON library for C++ (downloaded in Dockerfile)
- **jwt-cpp**: Header-only JWT library for token-based authentication (downloaded in Dockerfile)
- **spdlog**: Fast C++ logging library with structured logging support (downloaded in Dockerfile)
- **redis-plus-plus**: C++ Redis client library (compiled in Dockerfile)
- **SQLite3**: Lightweight database engine for persistent data storage
- **OpenSSL**: Cryptography library for JWT signing and password hashing

### System Requirements
- C++17 compiler (g++)
- pthread support
- SQLite3 development libraries (libsqlite3-dev)
- OpenSSL development libraries (libssl-dev, libcrypto)
- hiredis library (libhiredis-dev) for Redis connectivity
- Docker and Docker Compose for containerized development
- Redis server for caching (provided via Docker Compose)

## API Endpoints

| Method | Endpoint | Description | Auth Required | Status Codes |
|--------|----------|-------------|---------------|--------------|
| GET | `/api/health` | Health check with Redis status | No | 200 |
| POST | `/api/auth/register` | Register new user | No | 201, 400, 409 |
| POST | `/api/auth/login` | User login | No | 200, 401 |
| POST | `/api/auth/logout` | User logout (blacklist JWT) | Yes | 200, 401 |
| GET | `/api/users` | Get all users | Yes | 200, 401 |
| GET | `/api/users/:id` | Get user by ID (with caching) | Yes | 200, 401, 404 |
| POST | `/api/users` | Create new user (cache after creation) | Yes | 201, 400, 401 |
| PUT | `/api/users/:id` | Update user (invalidate cache) | Yes | 200, 400, 401, 404 |
| DELETE | `/api/users/:id` | Delete user (invalidate cache) | Yes | 200, 401, 404 |
| GET | `/api/cache/stats` | Get Redis cache statistics | Yes | 200, 401 |

## Configuration

### Server Configuration
- Default port: 8080 (configured in main.cpp)
- Database file: users.db (created automatically in container)
- Log files: /app/logs/api_server.log (rotating, 5MB max, 3 files)
- CORS enabled for all origins
- Health check with Docker Compose integration

### Docker Services
- **api-server**: Main C++ application with SQLite database and Redis caching
- **redis**: Redis server for caching and JWT blacklisting (port 6379)
- **nginx**: Optional reverse proxy on port 80

### Redis Caching Configuration
- **User Data TTL**: 30 minutes (1800 seconds)
- **JWT Blacklist TTL**: 24 hours (86400 seconds)
- **Cache Keys**: Format `user:{id}` for user data, `jwt_blacklist:{jti}` for blacklisted tokens
- **Thread Safety**: All cache operations protected by mutex
- **Fallback**: Application continues to work if Redis is unavailable
- **Statistics**: Available via `/api/cache/stats` endpoint

### Database Schema
```sql
-- Users table (for API data)
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE
);

-- Authentication table
CREATE TABLE auth_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Authentication
- **JWT Token**: 24-hour expiration time
- **Password Hashing**: SHA-256 with OpenSSL
- **Default Admin**: username: `admin`, password: `admin123`
- **Token Format**: `Bearer <jwt-token>` in Authorization header

### Logging System
- **Library**: spdlog v1.12.0 with structured logging
- **Log Levels**: DEBUG, INFO, WARN, ERROR, CRITICAL
- **Console Output**: Colored logs at INFO level and above
- **File Output**: Rotating logs at DEBUG level (/app/logs/api_server.log)
- **File Rotation**: 5MB per file, maximum 3 files
- **Log Categories**:
  - `api`: General API operations and request logging
  - `auth`: Authentication and authorization events
  - `database`: Database operations and initialization

### Log Format
```
Console: [YYYY-MM-DD HH:MM:SS.mmm] [logger] [LEVEL] [thread ID] message
File:    [YYYY-MM-DD HH:MM:SS.mmm] [logger] [level] [thread ID] message
```

### Common Log Events
- Server startup and endpoint listing
- Database initialization and schema creation
- All HTTP requests with method, path, status, IP, and user agent
- Authentication attempts (success/failure)
- JWT token generation and verification
- User registration and login events
- Database operations (create, read, update, delete)
- Error conditions and exceptions

## Common Development Patterns

### Adding New Endpoints
1. Define handler function in main.cpp
2. Register with server using appropriate HTTP method
3. Handle JSON parsing with try-catch for error handling
4. Use mutex-protected UserService methods for database operations
5. Return proper HTTP status codes and JSON responses

### Error Handling
- Use try-catch blocks for JSON parsing and database operations
- Return structured JSON error responses
- Include proper HTTP status codes (400, 404, 500)
- Mutex protection ensures thread-safe database access

### Database Operations
- All operations use prepared statements to prevent SQL injection
- Database connection is established once at startup
- Transactions are implicit for single operations
- Database file persists data between server restarts

### Data Model Extension
- Modify User struct for new fields
- Update database schema creation in initializeDatabase()
- Update userToJson() function for JSON serialization
- Modify UserService SQL queries for new fields
- Update API request/response validation

### Authentication Integration
- Use `authenticateRequest()` middleware for protected endpoints
- JWT tokens contain user ID, username, email, and expiration
- Tokens are validated on each protected request
- Password validation uses secure SHA-256 hashing
- Registration includes username uniqueness validation

### Logging Integration
- Use appropriate loggers: `spdlog::get("api")`, `spdlog::get("auth")`, `spdlog::get("database")`
- Log at appropriate levels: DEBUG for detailed info, INFO for important events, WARN for issues, ERROR for failures
- Include relevant context in log messages (usernames, IDs, operation details)
- Log both successful operations and failures for audit trails
- Use structured logging with consistent message formats

### Monitoring and Debugging
- View real-time logs: `docker-compose logs -f api-server`
- Access log files in container: `docker exec -it cpp-api-server cat /app/logs/api_server.log`
- Log rotation prevents disk space issues
- Thread-safe logging supports concurrent request handling
- Separate log categories enable focused debugging

### Security Considerations
- All user management endpoints require valid JWT authentication
- Passwords are hashed using SHA-256 before storage
- JWT tokens expire after 24 hours
- SQL injection prevention through prepared statements
- CORS headers properly configured for cross-origin requests
- Comprehensive audit logging for security monitoring