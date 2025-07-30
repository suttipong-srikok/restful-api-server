# C++ RESTful API Server

A lightweight RESTful API server built with C++ using httplib and nlohmann/json libraries. The server provides a complete CRUD API for user management with Docker support.

## Features

- **RESTful API** with standard HTTP methods (GET, POST, PUT, DELETE)
- **JSON** request/response handling
- **CORS** support for cross-origin requests
- **Thread-safe** in-memory data storage
- **Docker** containerization
- **Docker Compose** orchestration with Nginx reverse proxy
- **Health check** endpoint
- **Error handling** with proper HTTP status codes

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/users` | Get all users |
| GET | `/api/users/:id` | Get user by ID |
| POST | `/api/users` | Create new user |
| PUT | `/api/users/:id` | Update user |
| DELETE | `/api/users/:id` | Delete user |

## Quick Start with Docker Compose

1. **Clone and build:**
   ```bash
   git clone <repository>
   cd cpp-rest-api
   docker-compose up --build
   ```

2. **Test the API:**
   ```bash
   # Health check
   curl http://localhost:8080/api/health

   # Get all users
   curl http://localhost:8080/api/users

   # Create a new user
   curl -X POST http://localhost:8080/api/users \
     -H "Content-Type: application/json" \
     -d '{"name": "Alice Johnson", "email": "alice@example.com"}'

   # Get user by ID
   curl http://localhost:8080/api/users/1

   # Update user
   curl -X PUT http://localhost:8080/api/users/1 \
     -H "Content-Type: application/json" \
     -d '{"name": "John Updated", "email": "john.updated@example.com"}'

   # Delete user
   curl -X DELETE http://localhost:8080/api/users/1
   ```

## Local Development

### Prerequisites

- g++ compiler (C++17 support)
- make
- curl (for testing)
- jq (optional, for JSON formatting)

### Install Dependencies (Ubuntu/Debian)

```bash
make install-deps
```

### Build and Run Locally

```bash
# Build the application
make

# Run the server
make run

# Or run directly
./api_server
```

### Development with Debug Symbols

```bash
make debug
```

## Docker Commands

```bash
# Build and start services
make docker-up

# View logs
make docker-logs

# Stop services
make docker-down

# Restart services
make docker-restart
```

## Project Structure

```
.
├── main.cpp              # Main application source
├── Dockerfile           # Docker container configuration
├── docker-compose.yml   # Docker Compose orchestration
├── nginx.conf           # Nginx reverse proxy configuration
├── Makefile            # Build and utility commands
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

- **httplib**: Lightweight HTTP server library
- **nlohmann/json**: Modern JSON library for C++
- **Thread-safe storage**: Mutex-protected in-memory data store
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

## Performance

This is a basic implementation suitable for development and small-scale applications. For production use, consider:

- Database integration (PostgreSQL, MySQL, SQLite)
- Connection pooling
- Caching (Redis)
- Authentication/Authorization
- Rate limiting
- Logging framework
- Configuration management

## Testing

```bash
# Run basic API tests
make test
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - see LICENSE file for details.