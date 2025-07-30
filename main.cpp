#include <httplib.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <mutex>

using json = nlohmann::json;
using namespace std;

// Simple in-memory data store
struct User {
    int id;
    string name;
    string email;
};

class UserService {
private:
    vector<User> users;
    mutex users_mutex;
    int next_id = 1;

public:
    UserService() {
        // Add some sample data
        users.push_back({1, "John Doe", "john@example.com"});
        users.push_back({2, "Jane Smith", "jane@example.com"});
        next_id = 3;
    }

    vector<User> getAllUsers() {
        lock_guard<mutex> lock(users_mutex);
        return users;
    }

    User* getUserById(int id) {
        lock_guard<mutex> lock(users_mutex);
        for (auto& user : users) {
            if (user.id == id) {
                return &user;
            }
        }
        return nullptr;
    }

    User createUser(const string& name, const string& email) {
        lock_guard<mutex> lock(users_mutex);
        User newUser = {next_id++, name, email};
        users.push_back(newUser);
        return newUser;
    }

    bool updateUser(int id, const string& name, const string& email) {
        lock_guard<mutex> lock(users_mutex);
        for (auto& user : users) {
            if (user.id == id) {
                user.name = name;
                user.email = email;
                return true;
            }
        }
        return false;
    }

    bool deleteUser(int id) {
        lock_guard<mutex> lock(users_mutex);
        users.erase(
            remove_if(users.begin(), users.end(), 
                     [id](const User& user) { return user.id == id; }),
            users.end()
        );
        return true;
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

int main() {
    httplib::Server server;
    UserService userService;

    // CORS middleware
    server.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // Handle OPTIONS requests for CORS
    server.Options(R"(/.*)", [](const httplib::Request&, httplib::Response& res) {
        return;
    });

    // GET /api/health - Health check
    server.Get("/api/health", [](const httplib::Request&, httplib::Response& res) {
        json response = {
            {"status", "healthy"},
            {"message", "API is running"},
            {"timestamp", time(nullptr)}
        };
        res.set_content(response.dump(), "application/json");
    });

    // GET /api/users - Get all users
    server.Get("/api/users", [&userService](const httplib::Request&, httplib::Response& res) {
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

    // GET /api/users/:id - Get user by ID
    server.Get(R"(/api/users/(\d+))", [&userService](const httplib::Request& req, httplib::Response& res) {
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

    // POST /api/users - Create new user
    server.Post("/api/users", [&userService](const httplib::Request& req, httplib::Response& res) {
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

    // PUT /api/users/:id - Update user
    server.Put(R"(/api/users/(\d+))", [&userService](const httplib::Request& req, httplib::Response& res) {
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

    // DELETE /api/users/:id - Delete user
    server.Delete(R"(/api/users/(\d+))", [&userService](const httplib::Request& req, httplib::Response& res) {
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
    cout << "Starting server on http://0.0.0.0:8080" << endl;
    cout << "API endpoints:" << endl;
    cout << "  GET    /api/health" << endl;
    cout << "  GET    /api/users" << endl;
    cout << "  GET    /api/users/:id" << endl;
    cout << "  POST   /api/users" << endl;
    cout << "  PUT    /api/users/:id" << endl;
    cout << "  DELETE /api/users/:id" << endl;

    if (!server.listen("0.0.0.0", 8080)) {
        cerr << "Failed to start server" << endl;
        return 1;
    }

    return 0;
}