# C++ RESTful API Server

A lightweight RESTful API server built with C++ using httplib and nlohmann/json libraries. The server provides a complete CRUD API for user management with Docker support.

## Features

- **RESTful API** with standard HTTP methods (GET, POST, PUT, DELETE)
- **JSON** request/response handling
- **CORS** support for cross-origin requests
- **SQLite database** with persistent data storage and automatic schema initialization
- **Thread-safe** database operations with mutex protection
- **Redis caching** with automatic user data caching and TTL management
- **JWT authentication** with token generation and blacklisting
- **Docker** containerization
- **Docker Compose** orchestration with Redis and Nginx reverse proxy
- **Health check** endpoint
- **Error handling** with proper HTTP status codes
- **Structured logging** with automatic rotation and local persistence

## API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/health` | Health check with Redis status | No |
| POST | `/api/auth/register` | Register new user | No |
| POST | `/api/auth/login` | User login | No |
| POST | `/api/auth/logout` | User logout (blacklist JWT) | Yes |
| GET | `/api/users` | Get all users | Yes |
| GET | `/api/users/:id` | Get user by ID (with caching) | Yes |
| POST | `/api/users` | Create new user (cache after creation) | Yes |
| PUT | `/api/users/:id` | Update user (invalidate cache) | Yes |
| DELETE | `/api/users/:id` | Delete user (invalidate cache) | Yes |
| GET | `/api/cache/stats` | Get Redis cache statistics | Yes |

## Quick Start with Docker Compose

1. **Clone and build:**
   ```bash
   git clone <repository>
   cd cpp-rest-api
   docker-compose up --build
   ```

2. **Test the API:**
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

   # Update user (protected)
   curl -X PUT http://localhost:8080/api/users/1 \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"name": "Updated Name", "email": "updated@example.com"}'

   # Delete user (protected)
   curl -X DELETE http://localhost:8080/api/users/1 \
     -H "Authorization: Bearer $TOKEN"
   ```

## Local Development

### Prerequisites

- g++ compiler (C++17 support)
- SQLite3 development libraries (libsqlite3-dev)
- OpenSSL development libraries (libssl-dev, libcrypto)
- hiredis library (libhiredis-dev) for Redis connectivity
- curl (for testing)
- jq (optional, for JSON formatting)

### Install Dependencies (Ubuntu/Debian)

```bash
sudo apt-get update && apt-get install -y g++ cmake git pkg-config libssl-dev zlib1g-dev libsqlite3-dev sqlite3 libhiredis-dev wget curl build-essential
```

### Build and Run Locally

```bash
# Manual compilation (requires Redis++ library)
# Note: For local development, install redis-plus-plus from source
g++ -std=c++17 -pthread -O2 -I/usr/local/include -o api_server main.cpp -lsqlite3 -lssl -lcrypto -lredis++ -lhiredis

# Run the server
./api_server
```

## Docker Commands

```bash
# Build and start services
docker-compose up --build

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Restart services
docker-compose restart
```

## Logging

The application uses structured logging with spdlog and automatic log rotation:

- **Log location**: `/app/logs/api_server.log` (in container)
- **Log rotation**: Automatic rotation at 5MB with 3 backup files
- **Log levels**: DEBUG (file), INFO+ (console)
- **Format**: Timestamped with logger name and thread information
- **Log Categories**: `api`, `auth`, `database`

### Accessing Logs

```bash
# View live logs from Docker
docker-compose logs -f api-server

# Access log files in container
docker exec -it cpp-api-server cat /app/logs/api_server.log

# Follow log file in real-time from container
docker exec -it cpp-api-server tail -f /app/logs/api_server.log
```

## Redis Caching

The application includes Redis-based caching for improved performance:

- **User data caching**: 30-minute TTL for user records
- **JWT token blacklisting**: 24-hour TTL for revoked tokens
- **Automatic failover**: Application continues without Redis if unavailable
- **Thread-safe operations**: Mutex-protected cache operations

### Cache Configuration

Redis connection settings can be configured via environment variables in `docker-compose.yml`:

```yaml
environment:
  - REDIS_HOST=redis
  - REDIS_PORT=6379
```

### Cache Behavior

- **Cache hits**: Faster user data retrieval
- **Cache misses**: Automatic fallback to SQLite database
- **Connection failures**: Graceful degradation without Redis
- **Automatic cleanup**: TTL-based expiration
- **Cache Keys**: `user:{id}` for user data, `jwt_blacklist:{jti}` for blacklisted tokens

## JWT Authentication

The application includes JWT-based authentication with token management:

- **Token generation**: HS256 algorithm with configurable expiration
- **Token blacklisting**: Redis-based revocation system
- **User claims**: Username, email, and ID embedded in tokens
- **Automatic expiration**: 24-hour default token lifetime

### JWT Configuration

```cpp
// JWT Secret (configure via environment variable in production)
const string JWT_SECRET = "your-secret-key-change-in-production";
```

**Security Note**: Always use a strong, randomly generated secret in production and store it as an environment variable.

### Token Structure

Generated tokens include:
- **Issuer**: cpp-api-server
- **Subject**: Username
- **Claims**: username, email
- **Expiration**: 24 hours from issue time
- **JTI**: Unique token identifier for blacklisting

## SQLite Database

The application uses SQLite for persistent data storage with automatic schema management:

- **Database file**: `users.db` (created automatically)
- **Auto-initialization**: Tables and sample data created on first run
- **Thread-safe operations**: Mutex-protected database access
- **Prepared statements**: SQL injection protection
- **Automatic schema**: Users and auth_users tables with proper constraints

### Database Schema

**Users Table:**
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE
);
```

**Auth Users Table:**
```sql
CREATE TABLE auth_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Sample Data

The application automatically creates sample data on first run:
- **Users**: John Doe, Jane Smith
- **Admin User**: username: `admin`, password: `admin123`

### Data Flow

1. **Primary storage**: SQLite database for persistence
2. **Cache layer**: Redis for frequently accessed data and JWT blacklisting
3. **Fallback**: Graceful operation if Redis is unavailable
4. **Thread safety**: Mutex protection for concurrent access
5. **Authentication**: JWT tokens with 24-hour expiration and blacklisting support

## Project Structure

```
.
├── main.cpp              # Main application source
├── Dockerfile           # Docker container configuration
├── docker-compose.yml   # Docker Compose orchestration
├── nginx.conf           # Nginx reverse proxy configuration
├── Makefile            # Build and utility commands
├── logs/                # Application logs (Docker volume mount)
├── users.db             # SQLite database file (created automatically)
└── README.md           # This file
```

## API Usage Examples

### Create User
```bash
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Alice Johnson",
    "email": "alice@example.com"
  }'
```

Response:
```json
{
  "id": 3,
  "name": "Alice Johnson",
  "email": "alice@example.com"
}
```

### Get All Users
```bash
curl http://localhost:8080/api/users
```

Response:
```json
{
  "users": [
    {
      "id": 1,
      "name": "John Doe",
      "email": "john@example.com"
    },
    {
      "id": 2,
      "name": "Jane Smith",
      "email": "jane@example.com"
    }
  ],
  "count": 2
}
```

### Update User
```bash
curl -X PUT http://localhost:8080/api/users/1 \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Updated",
    "email": "john.updated@example.com"
  }'
```

### Error Handling

The API returns appropriate HTTP status codes:

- `200` - Success
- `201` - Created
- `400` - Bad Request (invalid JSON, missing fields)
- `404` - Not Found
- `500` - Internal Server Error

Example error response:
```json
{
  "error": "User not found",
  "id": 999
}
```

## Architecture

- **httplib**: Lightweight HTTP server library (header-only)
- **nlohmann/json**: Modern JSON library for C++ (header-only)
- **jwt-cpp**: JWT token generation and validation (header-only)
- **redis-plus-plus**: Redis client for caching and JWT blacklisting
- **sqlite3**: Embedded SQL database for persistent storage
- **spdlog**: High-performance structured logging library (header-only)
- **Thread-safe storage**: Mutex-protected database and cache operations
- **Redis caching**: User data caching with 30-minute TTL
- **JWT blacklisting**: Token revocation via Redis with 24-hour TTL
- **CORS enabled**: Cross-origin resource sharing support
- **Nginx proxy**: Load balancing and reverse proxy (optional)

## Configuration

The server runs on port 8080 by default. You can modify the port in `main.cpp`:

```cpp
server.listen("0.0.0.0", 8080);  // Change port here
```

For Docker, update the port mapping in `docker-compose.yml`:

```yaml
ports:
  - "8080:8080"  # host:container
```

## Performance & Production Features

This implementation includes several production-ready features:

✅ **Already Implemented:**
- SQLite database with persistent storage
- Redis caching with automatic TTL management
- JWT authentication with token blacklisting
- Structured logging with rotation
- Health checks and monitoring
- Docker containerization with orchestration

🔄 **For Enhanced Production Use:**
- Alternative database backends (PostgreSQL, MySQL)
- Connection pooling
- Rate limiting
- Configuration management via environment variables
- SSL/TLS termination
- Monitoring and metrics collection

## Testing

```bash
# Test health check (no auth)
curl http://localhost:8080/api/health

# Test authentication flow
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' | \
  jq -r '.token')

# Test protected endpoints
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/users
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/cache/stats
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - see LICENSE file for details.