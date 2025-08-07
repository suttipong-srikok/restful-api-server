#include <httplib.h>
#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>
#include <sqlite3.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/fmt/ostr.h>
#include <sw/redis++/redis++.h>
#include <iostream>
#include <vector>
#include <string>
#include <mutex>
#include <memory>
#include <sstream>
#include <ctime>
#include <algorithm>
#include <openssl/sha.h>
#include <random>
#include <iomanip>
#include <chrono>

using json = nlohmann::json;
using namespace std;

// Forward declarations
struct User;
struct AuthUser;

// User structures
struct User {
    int id;
    string name;
    string email;
};

struct AuthUser {
    int id;
    string username;
    string email;
    string password_hash;
    string created_at;
};

// Redis Cache Manager
class CacheManager {
private:
    sw::redis::Redis* redis;
    mutex cache_mutex;
    const int DEFAULT_TTL = 300; // 5 minutes default TTL
    const int USER_TTL = 1800;   // 30 minutes for user data
    const int JWT_TTL = 86400;   // 24 hours for JWT blacklist

public:
    CacheManager(const string& redis_host = "redis", int redis_port = 6379) {
        auto cache_logger = spdlog::get("api");
        try {
            sw::redis::ConnectionOptions connection_options;
            connection_options.host = redis_host;
            connection_options.port = redis_port;
            connection_options.connect_timeout = chrono::milliseconds(100);
            connection_options.socket_timeout = chrono::milliseconds(100);
            
            redis = new sw::redis::Redis(connection_options);
            
            // Test connection
            redis->ping();
            cache_logger->info("Redis connection established successfully to {}:{}", redis_host, redis_port);
        } catch (const exception& e) {
            cache_logger->error("Failed to connect to Redis at {}:{}: {}", redis_host, redis_port, e.what());
            redis = nullptr;
        }
    }

    ~CacheManager() {
        if (redis) {
            delete redis;
        }
    }

    bool isConnected() const {
        return redis != nullptr;
    }

    // User caching
    bool cacheUser(int user_id, const User& user) {
        if (!redis) return false;
        
        lock_guard<mutex> lock(cache_mutex);
        auto cache_logger = spdlog::get("api");
        
        try {
            json user_json = {
                {"id", user.id},
                {"name", user.name},
                {"email", user.email}
            };
            
            string key = "user:" + to_string(user_id);
            redis->setex(key, USER_TTL, user_json.dump());
            
            cache_logger->debug("Cached user data for ID: {}", user_id);
            return true;
        } catch (const exception& e) {
            cache_logger->warn("Failed to cache user {}: {}", user_id, e.what());
            return false;
        }
    }

    optional<User> getCachedUser(int user_id) {
        if (!redis) return nullopt;
        
        lock_guard<mutex> lock(cache_mutex);
        auto cache_logger = spdlog::get("api");
        
        try {
            string key = "user:" + to_string(user_id);
            auto cached_data = redis->get(key);
            
            if (cached_data) {
                json user_json = json::parse(*cached_data);
                User user;
                user.id = user_json["id"];
                user.name = user_json["name"];
                user.email = user_json["email"];
                
                cache_logger->debug("Cache hit for user ID: {}", user_id);
                return user;
            }
        } catch (const exception& e) {
            cache_logger->warn("Failed to get cached user {}: {}", user_id, e.what());
        }
        
        cache_logger->debug("Cache miss for user ID: {}", user_id);
        return nullopt;
    }

    void invalidateUser(int user_id) {
        if (!redis) return;
        
        lock_guard<mutex> lock(cache_mutex);
        auto cache_logger = spdlog::get("api");
        
        try {
            string key = "user:" + to_string(user_id);
            redis->del(key);
            cache_logger->debug("Invalidated cache for user ID: {}", user_id);
        } catch (const exception& e) {
            cache_logger->warn("Failed to invalidate user cache {}: {}", user_id, e.what());
        }
    }

    // JWT token blacklisting
    bool blacklistToken(const string& jti, int exp_time) {
        if (!redis) return false;
        
        lock_guard<mutex> lock(cache_mutex);
        auto auth_logger = spdlog::get("auth");
        
        try {
            string key = "blacklist:" + jti;
            int ttl = exp_time - time(nullptr);
            if (ttl > 0) {
                redis->setex(key, ttl, "1");
                auth_logger->info("Blacklisted JWT token: {}", jti);
                return true;
            }
        } catch (const exception& e) {
            auth_logger->warn("Failed to blacklist token {}: {}", jti, e.what());
        }
        
        return false;
    }

    bool isTokenBlacklisted(const string& jti) {
        if (!redis) return false;
        
        lock_guard<mutex> lock(cache_mutex);
        
        try {
            string key = "blacklist:" + jti;
            return redis->exists(key) > 0;
        } catch (const exception& e) {
            auto auth_logger = spdlog::get("auth");
            auth_logger->warn("Failed to check token blacklist {}: {}", jti, e.what());
            return false;
        }
    }

    // General cache operations
    bool setCache(const string& key, const string& value, int ttl = -1) {
        if (!redis) return false;
        
        lock_guard<mutex> lock(cache_mutex);
        
        try {
            if (ttl > 0) {
                redis->setex(key, ttl, value);
            } else {
                redis->set(key, value);
            }
            return true;
        } catch (const exception& e) {
            auto cache_logger = spdlog::get("api");
            cache_logger->warn("Failed to set cache key {}: {}", key, e.what());
            return false;
        }
    }

    optional<string> getCache(const string& key) {
        if (!redis) return nullopt;
        
        lock_guard<mutex> lock(cache_mutex);
        
        try {
            return redis->get(key);
        } catch (const exception& e) {
            auto cache_logger = spdlog::get("api");
            cache_logger->warn("Failed to get cache key {}: {}", key, e.what());
            return nullopt;
        }
    }

    // Cache statistics
    json getCacheStats() {
        if (!redis) return json{{"connected", false}};
        
        lock_guard<mutex> lock(cache_mutex);
        
        try {
            auto info = redis->info("memory");
            auto keyspace = redis->info("keyspace");
            
            return json{
                {"connected", true},
                {"memory_info", info},
                {"keyspace_info", keyspace}
            };
        } catch (const exception& e) {
            return json{{"connected", true}, {"error", e.what()}};
        }
    }
};

// Logging setup
void setupLogging() {
    try {
        // Create logs directory
        system("mkdir -p /app/logs");
        
        // Create a multi-sink logger with both console and file output
        auto console_sink = make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::info);
        console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%n] [%^%l%$] [thread %t] %v");
        
        auto file_sink = make_shared<spdlog::sinks::rotating_file_sink_mt>("/app/logs/api_server.log", 1048576 * 5, 3);
        file_sink->set_level(spdlog::level::debug);
        file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%n] [%l] [thread %t] %v");
        
        // Create loggers
        vector<spdlog::sink_ptr> sinks {console_sink, file_sink};
        auto logger = make_shared<spdlog::logger>("api", sinks.begin(), sinks.end());
        logger->set_level(spdlog::level::debug);
        logger->flush_on(spdlog::level::info);
        spdlog::register_logger(logger);
        
        auto auth_logger = make_shared<spdlog::logger>("auth", sinks.begin(), sinks.end());
        auth_logger->set_level(spdlog::level::debug);
        auth_logger->flush_on(spdlog::level::info);
        spdlog::register_logger(auth_logger);
        
        auto db_logger = make_shared<spdlog::logger>("database", sinks.begin(), sinks.end());
        db_logger->set_level(spdlog::level::debug);
        db_logger->flush_on(spdlog::level::info);
        spdlog::register_logger(db_logger);
        
        // Set default logger
        spdlog::set_default_logger(logger);
        
        spdlog::info("Logging system initialized successfully");
    } catch (const spdlog::spdlog_ex& ex) {
        cout << "Log initialization failed: " << ex.what() << endl;
    }
}

// Data structures
// JWT Secret (in production, use environment variable)
const string JWT_SECRET = "your-secret-key-change-in-production";

// Utility functions
string hashPassword(const string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password.c_str(), password.length());
    SHA256_Final(hash, &sha256);
    
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setfill('0') << setw(2) << (unsigned)hash[i];
    }
    return ss.str();
}

string generateToken(const AuthUser& user) {
    auto auth_logger = spdlog::get("auth");
    
    try {
        auto token = jwt::create()
            .set_issuer("cpp-api-server")
            .set_type("JWT")
            .set_id(to_string(user.id))
            .set_subject(user.username)
            .set_audience("cpp-api-client")
            .set_issued_at(chrono::system_clock::now())
            .set_expires_at(chrono::system_clock::now() + chrono::hours{24})
            .set_payload_claim("username", jwt::claim(user.username))
            .set_payload_claim("email", jwt::claim(user.email))
            .sign(jwt::algorithm::hs256{JWT_SECRET});
        
        auth_logger->info("JWT token generated for user: {} (ID: {})", user.username, user.id);
        return token;
    } catch (const exception& e) {
        auth_logger->error("Failed to generate JWT token for user {}: {}", user.username, e.what());
        throw;
    }
}

bool verifyToken(const string& token, AuthUser& user, CacheManager* cache = nullptr) {
    auto auth_logger = spdlog::get("auth");
    
    try {
        auto decoded = jwt::decode(token);
        
        // Check if token is blacklisted
        if (cache && cache->isConnected()) {
            string jti = decoded.get_id();
            if (cache->isTokenBlacklisted(jti)) {
                auth_logger->warn("JWT token verification failed: token blacklisted (JTI: {})", jti);
                return false;
            }
        }
        
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{JWT_SECRET})
            .with_issuer("cpp-api-server");
        
        verifier.verify(decoded);
        
        user.id = stoi(decoded.get_id());
        user.username = decoded.get_subject();
        user.email = decoded.get_payload_claim("email").as_string();
        
        auth_logger->debug("JWT token verified successfully for user: {} (ID: {})", user.username, user.id);
        return true;
    } catch (const exception& e) {
        auth_logger->warn("JWT token verification failed: {}", e.what());
        return false;
    }
}

class UserService {
private:
    sqlite3* db;
    mutex db_mutex;
    CacheManager* cache;

    void executeSQL(const string& sql) {
        char* errMsg = 0;
        int rc = sqlite3_exec(db, sql.c_str(), 0, 0, &errMsg);
        if (rc != SQLITE_OK) {
            string error = "SQL error: ";
            if (errMsg) {
                error += errMsg;
                sqlite3_free(errMsg);
            }
            throw runtime_error(error);
        }
    }

public:
    UserService(const string& dbPath = "users.db", CacheManager* cacheManager = nullptr) : cache(cacheManager) {
        auto db_logger = spdlog::get("database");
        
        int rc = sqlite3_open(dbPath.c_str(), &db);
        if (rc) {
            db_logger->error("Failed to open database at {}: {}", dbPath, sqlite3_errmsg(db));
            throw runtime_error("Can't open database: " + string(sqlite3_errmsg(db)));
        }
        
        db_logger->info("Database opened successfully: {}", dbPath);
        if (cache && cache->isConnected()) {
            db_logger->info("Cache integration enabled");
        } else {
            db_logger->info("Cache integration disabled - running without Redis");
        }
        initializeDatabase();
    }

    ~UserService() {
        if (db) {
            sqlite3_close(db);
        }
    }

    void initializeDatabase() {
        lock_guard<mutex> lock(db_mutex);
        auto db_logger = spdlog::get("database");
        
        db_logger->info("Initializing database schema");
        
        // Create users table
        string createUsersTable = R"(
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE
            );
        )";
        executeSQL(createUsersTable);
        db_logger->debug("Users table created/verified");
        
        // Create auth_users table for authentication
        string createAuthTable = R"(
            CREATE TABLE IF NOT EXISTS auth_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        )";
        executeSQL(createAuthTable);
        db_logger->debug("Auth_users table created/verified");
        
        // Insert sample data if tables are empty
        sqlite3_stmt* stmt;
        string countQuery = "SELECT COUNT(*) FROM users";
        sqlite3_prepare_v2(db, countQuery.c_str(), -1, &stmt, NULL);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int count = sqlite3_column_int(stmt, 0);
            if (count == 0) {
                executeSQL("INSERT INTO users (name, email) VALUES ('John Doe', 'john@example.com')");
                executeSQL("INSERT INTO users (name, email) VALUES ('Jane Smith', 'jane@example.com')");
                db_logger->info("Inserted sample users data");
            }
        }
        sqlite3_finalize(stmt);
        
        // Insert sample auth user if table is empty
        string authCountQuery = "SELECT COUNT(*) FROM auth_users";
        sqlite3_prepare_v2(db, authCountQuery.c_str(), -1, &stmt, NULL);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int count = sqlite3_column_int(stmt, 0);
            if (count == 0) {
                string hashedPassword = hashPassword("admin123");
                string insertAdmin = "INSERT INTO auth_users (username, email, password_hash) VALUES ('admin', 'admin@example.com', ?)";
                sqlite3_stmt* insertStmt;
                sqlite3_prepare_v2(db, insertAdmin.c_str(), -1, &insertStmt, NULL);
                sqlite3_bind_text(insertStmt, 1, hashedPassword.c_str(), -1, SQLITE_STATIC);
                sqlite3_step(insertStmt);
                sqlite3_finalize(insertStmt);
                db_logger->info("Created default admin user");
            }
        }
        sqlite3_finalize(stmt);
        
        db_logger->info("Database initialization completed successfully");
    }

    vector<User> getAllUsers() {
        lock_guard<mutex> lock(db_mutex);
        vector<User> users;
        sqlite3_stmt* stmt;
        
        string query = "SELECT id, name, email FROM users";
        int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);
        
        if (rc == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                User user;
                user.id = sqlite3_column_int(stmt, 0);
                user.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                user.email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                users.push_back(user);
            }
        }
        sqlite3_finalize(stmt);
        return users;
    }

    User* getUserById(int id) {
        static User user; // Static to persist beyond function scope
        
        // Try cache first
        if (cache && cache->isConnected()) {
            auto cached_user = cache->getCachedUser(id);
            if (cached_user.has_value()) {
                user = cached_user.value();
                return &user;
            }
        }
        
        // Cache miss - fetch from database
        lock_guard<mutex> lock(db_mutex);
        sqlite3_stmt* stmt;
        
        string query = "SELECT id, name, email FROM users WHERE id = ?";
        int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);
        
        if (rc == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, id);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                user.id = sqlite3_column_int(stmt, 0);
                user.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                user.email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                sqlite3_finalize(stmt);
                
                // Cache the result
                if (cache && cache->isConnected()) {
                    cache->cacheUser(id, user);
                }
                
                return &user;
            }
        }
        sqlite3_finalize(stmt);
        return nullptr;
    }

    User createUser(const string& name, const string& email) {
        lock_guard<mutex> lock(db_mutex);
        auto db_logger = spdlog::get("database");
        sqlite3_stmt* stmt;
        
        db_logger->debug("Creating user: name='{}', email='{}'", name, email);
        
        string query = "INSERT INTO users (name, email) VALUES (?, ?)";
        int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);
        
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, email.c_str(), -1, SQLITE_STATIC);
            
            if (sqlite3_step(stmt) == SQLITE_DONE) {
                int newId = sqlite3_last_insert_rowid(db);
                sqlite3_finalize(stmt);
                
                User newUser = {newId, name, email};
                
                // Cache the new user
                if (cache && cache->isConnected()) {
                    cache->cacheUser(newId, newUser);
                }
                
                db_logger->info("User created successfully: ID={}, name='{}', email='{}'", newId, name, email);
                return newUser;
            }
        }
        sqlite3_finalize(stmt);
        db_logger->error("Failed to create user: name='{}', email='{}'", name, email);
        throw runtime_error("Failed to create user");
    }

    bool updateUser(int id, const string& name, const string& email) {
        lock_guard<mutex> lock(db_mutex);
        sqlite3_stmt* stmt;
        
        string query = "UPDATE users SET name = ?, email = ? WHERE id = ?";
        int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);
        
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, email.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 3, id);
            
            int result = sqlite3_step(stmt);
            bool success = result == SQLITE_DONE && sqlite3_changes(db) > 0;
            sqlite3_finalize(stmt);
            
            // Invalidate cache if update was successful
            if (success && cache && cache->isConnected()) {
                cache->invalidateUser(id);
            }
            
            return success;
        }
        sqlite3_finalize(stmt);
        return false;
    }

    bool deleteUser(int id) {
        lock_guard<mutex> lock(db_mutex);
        sqlite3_stmt* stmt;
        
        string query = "DELETE FROM users WHERE id = ?";
        int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);
        
        if (rc == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, id);
            int result = sqlite3_step(stmt);
            bool success = result == SQLITE_DONE && sqlite3_changes(db) > 0;
            sqlite3_finalize(stmt);
            
            // Invalidate cache if delete was successful
            if (success && cache && cache->isConnected()) {
                cache->invalidateUser(id);
            }
            
            return success;
        }
        sqlite3_finalize(stmt);
        return false;
    }

    // Authentication methods
    AuthUser* authenticateUser(const string& username, const string& password) {
        lock_guard<mutex> lock(db_mutex);
        auto auth_logger = spdlog::get("auth");
        static AuthUser user;
        sqlite3_stmt* stmt;
        
        auth_logger->debug("Attempting authentication for user: {}", username);
        
        string query = "SELECT id, username, email, password_hash, created_at FROM auth_users WHERE username = ?";
        int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);
        
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                user.id = sqlite3_column_int(stmt, 0);
                user.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                user.email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                user.password_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
                user.created_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
                
                sqlite3_finalize(stmt);
                
                // Verify password
                if (user.password_hash == hashPassword(password)) {
                    auth_logger->info("Authentication successful for user: {} (ID: {})", username, user.id);
                    return &user;
                } else {
                    auth_logger->warn("Authentication failed for user '{}': invalid password", username);
                }
            } else {
                auth_logger->warn("Authentication failed for user '{}': user not found", username);
            }
        }
        sqlite3_finalize(stmt);
        return nullptr;
    }

    AuthUser registerUser(const string& username, const string& email, const string& password) {
        lock_guard<mutex> lock(db_mutex);
        auto auth_logger = spdlog::get("auth");
        sqlite3_stmt* stmt;
        
        auth_logger->debug("Registering new user: username='{}', email='{}'", username, email);
        
        string hashedPassword = hashPassword(password);
        string query = "INSERT INTO auth_users (username, email, password_hash) VALUES (?, ?, ?)";
        int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);
        
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, email.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, hashedPassword.c_str(), -1, SQLITE_STATIC);
            
            if (sqlite3_step(stmt) == SQLITE_DONE) {
                int newId = sqlite3_last_insert_rowid(db);
                sqlite3_finalize(stmt);
                
                AuthUser newUser;
                newUser.id = newId;
                newUser.username = username;
                newUser.email = email;
                newUser.password_hash = hashedPassword;
                newUser.created_at = "now";
                
                auth_logger->info("User registered successfully: username='{}', email='{}', ID={}", username, email, newId);
                return newUser;
            }
        }
        sqlite3_finalize(stmt);
        auth_logger->error("Failed to register user: username='{}', email='{}'", username, email);
        throw runtime_error("Failed to register user");
    }

    bool isUsernameTaken(const string& username) {
        lock_guard<mutex> lock(db_mutex);
        sqlite3_stmt* stmt;
        
        string query = "SELECT COUNT(*) FROM auth_users WHERE username = ?";
        int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);
        
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                int count = sqlite3_column_int(stmt, 0);
                sqlite3_finalize(stmt);
                return count > 0;
            }
        }
        sqlite3_finalize(stmt);
        return false;
    }

    bool isEmailTaken(const string& email) {
        lock_guard<mutex> lock(db_mutex);
        sqlite3_stmt* stmt;
        
        string query = "SELECT COUNT(*) FROM auth_users WHERE email = ?";
        int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);
        
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                int count = sqlite3_column_int(stmt, 0);
                sqlite3_finalize(stmt);
                return count > 0;
            }
        }
        sqlite3_finalize(stmt);
        return false;
    }
};

// Convert User to JSON
json userToJson(const User& user) {
    return json{
        {"id", user.id},
        {"name", user.name},
        {"email", user.email}
    };
}

// Request logging function
void logRequest(const httplib::Request& req, const httplib::Response& res) {
    auto logger = spdlog::get("api");
    string userAgent = req.get_header_value("User-Agent");
    string clientIP = req.get_header_value("X-Real-IP");
    if (clientIP.empty()) {
        clientIP = req.get_header_value("X-Forwarded-For");
    }
    if (clientIP.empty()) {
        clientIP = "unknown";
    }
    
    logger->info("{} {} {} - {} - {} - {}", 
                 req.method, 
                 req.path, 
                 req.version, 
                 res.status, 
                 clientIP, 
                 userAgent.empty() ? "unknown" : userAgent);
}

// JWT Middleware function
bool authenticateRequest(const httplib::Request& req, httplib::Response& res, AuthUser& user, CacheManager* cache = nullptr) {
    auto auth_logger = spdlog::get("auth");
    auto authHeader = req.get_header_value("Authorization");
    
    if (authHeader.empty()) {
        auth_logger->warn("Authentication failed: Authorization header missing for {} {}", req.method, req.path);
        json error = {{"error", "Authorization header missing"}};
        res.status = 401;
        res.set_content(error.dump(), "application/json");
        return false;
    }
    
    // Extract token from "Bearer <token>"
    if (authHeader.substr(0, 7) != "Bearer ") {
        auth_logger->warn("Authentication failed: Invalid authorization format for {} {}", req.method, req.path);
        json error = {{"error", "Invalid authorization format. Use: Bearer <token>"}};
        res.status = 401;
        res.set_content(error.dump(), "application/json");
        return false;
    }
    
    string token = authHeader.substr(7);
    
    if (!verifyToken(token, user, cache)) {
        auth_logger->warn("Authentication failed: Invalid/expired/blacklisted token for {} {}", req.method, req.path);
        json error = {{"error", "Invalid or expired token"}};
        res.status = 401;
        res.set_content(error.dump(), "application/json");
        return false;
    }
    
    auth_logger->debug("Authentication successful for user {} accessing {} {}", user.username, req.method, req.path);
    return true;
}

int main() {
    // Initialize logging first
    setupLogging();
    
    auto logger = spdlog::get("api");
    logger->info("Starting RESTful API Server");
    
    // Initialize cache manager
    string redis_host = getenv("REDIS_HOST") ? getenv("REDIS_HOST") : "redis";
    int redis_port = getenv("REDIS_PORT") ? atoi(getenv("REDIS_PORT")) : 6379;
    
    CacheManager cacheManager(redis_host, redis_port);
    
    httplib::Server server;
    UserService userService("users.db", &cacheManager);

    // CORS middleware
    server.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // Request logging middleware
    server.set_post_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        logRequest(req, res);
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // Handle OPTIONS requests for CORS
    server.Options(R"(/.*)", [](const httplib::Request&, httplib::Response& res) {
        return;
    });

    // GET /api/health - Health check
    server.Get("/api/health", [&cacheManager](const httplib::Request&, httplib::Response& res) {
        json response = {
            {"status", "healthy"},
            {"message", "API is running"},
            {"timestamp", time(nullptr)},
            {"cache", {
                {"redis_connected", cacheManager.isConnected()}
            }}
        };
        res.set_content(response.dump(), "application/json");
    });

    // GET /api/cache/stats - Cache statistics (Protected)
    server.Get("/api/cache/stats", [&cacheManager](const httplib::Request& req, httplib::Response& res) {
        AuthUser authUser;
        if (!authenticateRequest(req, res, authUser, &cacheManager)) {
            return;
        }
        
        json stats = cacheManager.getCacheStats();
        res.set_content(stats.dump(), "application/json");
    });

    // POST /api/auth/register - Register new user
    server.Post("/api/auth/register", [&userService](const httplib::Request& req, httplib::Response& res) {
        auto logger = spdlog::get("api");
        logger->debug("Registration request received");
        
        try {
            json body = json::parse(req.body);
            
            if (!body.contains("username") || !body.contains("email") || !body.contains("password")) {
                json error = {
                    {"error", "Missing required fields: username, email, password"}
                };
                res.status = 400;
                res.set_content(error.dump(), "application/json");
                return;
            }
            
            string username = body["username"];
            string email = body["email"];
            string password = body["password"];
            
            // Validate input
            if (username.length() < 3) {
                logger->warn("Registration failed: Username too short for '{}'", username);
                json error = {{"error", "Username must be at least 3 characters"}};
                res.status = 400;
                res.set_content(error.dump(), "application/json");
                return;
            }
            
            if (password.length() < 6) {
                logger->warn("Registration failed: Password too short for user '{}'", username);
                json error = {{"error", "Password must be at least 6 characters"}};
                res.status = 400;
                res.set_content(error.dump(), "application/json");
                return;
            }
            
            // Check if username or email already exists
            if (userService.isUsernameTaken(username)) {
                json error = {{"error", "Username already exists"}};
                res.status = 409;
                res.set_content(error.dump(), "application/json");
                return;
            }
            
            if (userService.isEmailTaken(email)) {
                json error = {{"error", "Email already exists"}};
                res.status = 409;
                res.set_content(error.dump(), "application/json");
                return;
            }
            
            AuthUser newUser = userService.registerUser(username, email, password);
            string token = generateToken(newUser);
            
            logger->info("User registration completed successfully: username='{}', email='{}', ID={}", username, email, newUser.id);
            
            json response = {
                {"message", "User registered successfully"},
                {"user", {
                    {"id", newUser.id},
                    {"username", newUser.username},
                    {"email", newUser.email}
                }},
                {"token", token}
            };
            res.status = 201;
            res.set_content(response.dump(), "application/json");
            
        } catch (const exception& e) {
            logger->error("Registration failed with exception: {}", e.what());
            json error = {
                {"error", "Registration failed"},
                {"message", e.what()}
            };
            res.status = 400;
            res.set_content(error.dump(), "application/json");
        }
    });

    // POST /api/auth/login - Login user
    server.Post("/api/auth/login", [&userService](const httplib::Request& req, httplib::Response& res) {
        auto logger = spdlog::get("api");
        logger->debug("Login request received");
        
        try {
            json body = json::parse(req.body);
            
            if (!body.contains("username") || !body.contains("password")) {
                json error = {
                    {"error", "Missing required fields: username, password"}
                };
                res.status = 400;
                res.set_content(error.dump(), "application/json");
                return;
            }
            
            string username = body["username"];
            string password = body["password"];
            
            AuthUser* user = userService.authenticateUser(username, password);
            
            if (user) {
                string token = generateToken(*user);
                
                logger->info("Login successful for user: {} (ID: {})", user->username, user->id);
                
                json response = {
                    {"message", "Login successful"},
                    {"user", {
                        {"id", user->id},
                        {"username", user->username},
                        {"email", user->email}
                    }},
                    {"token", token}
                };
                res.set_content(response.dump(), "application/json");
            } else {
                logger->warn("Login failed: Invalid credentials for username '{}'", username);
                json error = {
                    {"error", "Invalid credentials"}
                };
                res.status = 401;
                res.set_content(error.dump(), "application/json");
            }
            
        } catch (const exception& e) {
            logger->error("Login failed with exception: {}", e.what());
            json error = {
                {"error", "Login failed"},
                {"message", e.what()}
            };
            res.status = 400;
            res.set_content(error.dump(), "application/json");
        }
    });

    // GET /api/users - Get all users (Protected)
    server.Get("/api/users", [&userService, &cacheManager](const httplib::Request& req, httplib::Response& res) {
        AuthUser authUser;
        if (!authenticateRequest(req, res, authUser, &cacheManager)) {
            return;
        }
        
        auto users = userService.getAllUsers();
        json usersJson = json::array();
        
        for (const auto& user : users) {
            usersJson.push_back(userToJson(user));
        }
        
        json response = {
            {"users", usersJson},
            {"count", users.size()}
        };
        res.set_content(response.dump(), "application/json");
    });

    // GET /api/users/:id - Get user by ID (Protected)
    server.Get(R"(/api/users/(\d+))", [&userService, &cacheManager](const httplib::Request& req, httplib::Response& res) {
        AuthUser authUser;
        if (!authenticateRequest(req, res, authUser, &cacheManager)) {
            return;
        }
        
        int id = stoi(req.matches[1]);
        User* user = userService.getUserById(id);
        
        if (user) {
            res.set_content(userToJson(*user).dump(), "application/json");
        } else {
            json error = {
                {"error", "User not found"},
                {"id", id}
            };
            res.status = 404;
            res.set_content(error.dump(), "application/json");
        }
    });

    // POST /api/users - Create new user (Protected)
    server.Post("/api/users", [&userService, &cacheManager](const httplib::Request& req, httplib::Response& res) {
        AuthUser authUser;
        if (!authenticateRequest(req, res, authUser, &cacheManager)) {
            return;
        }
        
        try {
            json body = json::parse(req.body);
            
            if (!body.contains("name") || !body.contains("email")) {
                json error = {
                    {"error", "Missing required fields: name, email"}
                };
                res.status = 400;
                res.set_content(error.dump(), "application/json");
                return;
            }
            
            string name = body["name"];
            string email = body["email"];
            
            User newUser = userService.createUser(name, email);
            res.status = 201;
            res.set_content(userToJson(newUser).dump(), "application/json");
            
        } catch (const exception& e) {
            json error = {
                {"error", "Invalid JSON format"},
                {"message", e.what()}
            };
            res.status = 400;
            res.set_content(error.dump(), "application/json");
        }
    });

    // PUT /api/users/:id - Update user (Protected)
    server.Put(R"(/api/users/(\d+))", [&userService, &cacheManager](const httplib::Request& req, httplib::Response& res) {
        AuthUser authUser;
        if (!authenticateRequest(req, res, authUser, &cacheManager)) {
            return;
        }
        
        try {
            int id = stoi(req.matches[1]);
            json body = json::parse(req.body);
            
            if (!body.contains("name") || !body.contains("email")) {
                json error = {
                    {"error", "Missing required fields: name, email"}
                };
                res.status = 400;
                res.set_content(error.dump(), "application/json");
                return;
            }
            
            string name = body["name"];
            string email = body["email"];
            
            if (userService.updateUser(id, name, email)) {
                User* updatedUser = userService.getUserById(id);
                res.set_content(userToJson(*updatedUser).dump(), "application/json");
            } else {
                json error = {
                    {"error", "User not found"},
                    {"id", id}
                };
                res.status = 404;
                res.set_content(error.dump(), "application/json");
            }
            
        } catch (const exception& e) {
            json error = {
                {"error", "Invalid request"},
                {"message", e.what()}
            };
            res.status = 400;
            res.set_content(error.dump(), "application/json");
        }
    });

    // DELETE /api/users/:id - Delete user (Protected)
    server.Delete(R"(/api/users/(\d+))", [&userService, &cacheManager](const httplib::Request& req, httplib::Response& res) {
        AuthUser authUser;
        if (!authenticateRequest(req, res, authUser, &cacheManager)) {
            return;
        }
        
        int id = stoi(req.matches[1]);
        
        if (userService.getUserById(id)) {
            userService.deleteUser(id);
            json response = {
                {"message", "User deleted successfully"},
                {"id", id}
            };
            res.set_content(response.dump(), "application/json");
        } else {
            json error = {
                {"error", "User not found"},
                {"id", id}
            };
            res.status = 404;
            res.set_content(error.dump(), "application/json");
        }
    });

    // Start server
    logger->info("Starting server on http://0.0.0.0:8080");
    logger->info("Available API endpoints:");
    logger->info("  GET    /api/health");
    logger->info("  POST   /api/auth/register");
    logger->info("  POST   /api/auth/login");
    logger->info("  GET    /api/users (Protected)");
    logger->info("  GET    /api/users/:id (Protected)");
    logger->info("  POST   /api/users (Protected)");
    logger->info("  PUT    /api/users/:id (Protected)");
    logger->info("  DELETE /api/users/:id (Protected)");
    logger->info("Default login: admin / admin123");

    if (!server.listen("0.0.0.0", 8080)) {
        logger->critical("Failed to start server on port 8080");
        return 1;
    }

    return 0;
}