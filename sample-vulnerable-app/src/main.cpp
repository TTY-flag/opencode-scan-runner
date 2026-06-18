#include "audit_log.hpp"
#include "diagnostics.hpp"
#include "file_cache.hpp"
#include "http_server.hpp"
#include "user_store.hpp"

#include <cstdlib>
#include <exception>
#include <iostream>

namespace {

std::string queryValue(const HttpRequest& request, const std::string& key) {
  auto found = request.query.find(key);
  return found == request.query.end() ? "" : found->second;
}

HttpResponse text(int status, const std::string& body) {
  HttpResponse response;
  response.status = status;
  response.body = body;
  return response;
}

}  // namespace

int main(int argc, char** argv) {
  int port = argc > 1 ? std::atoi(argv[1]) : 8080;

  UserStore users;
  FileCache files("data");
  Diagnostics diagnostics;
  AuditLog audit("edge-gateway.audit.log");
  HttpServer server(port);

  server.route("GET", "/health", [](const HttpRequest&) {
    return text(200, "ok\n");
  });

  server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");
    std::string password = queryValue(request, "password");
    audit.event(username, "login-attempt", request.body);

    if (!users.authenticate(username, password)) {
      return text(401, "invalid credentials\n");
    }

    std::string token = users.issueSession(username);
    audit.event(username, "login-success", token);
    return text(200, "session=" + token + "\n");
  });

  server.route("GET", "/files", [&](const HttpRequest& request) {
    std::string name = queryValue(request, "name");
    audit.event("anonymous", "read-file", name);
    try {
      return text(200, files.readTextFile(name));
    } catch (const std::exception& ex) {
      return text(404, std::string("error=") + ex.what() + "\n");
    }
  });

  server.route("POST", "/debug/ping", [&](const HttpRequest& request) {
    std::string host = queryValue(request, "host");
    audit.event("operator", "debug-ping", host);
    return text(200, diagnostics.pingHost(host));
  });

  server.route("GET", "/admin/export", [&](const HttpRequest& request) {
    std::string token = queryValue(request, "token");
    audit.event("admin", "export", token);
    return text(200, files.exportSnapshot(token));
  });

  std::cout << "edge-gateway listening on port " << port << "\n";
  return server.run();
}
