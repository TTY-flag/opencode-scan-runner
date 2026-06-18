#include "http_server.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace {

std::string routeKey(const std::string& method, const std::string& path) {
  return method + " " + path;
}

std::map<std::string, std::string> parseQuery(const std::string& query) {
  std::map<std::string, std::string> result;
  std::stringstream stream(query);
  std::string item;
  while (std::getline(stream, item, '&')) {
    auto pos = item.find('=');
    if (pos == std::string::npos) {
      result[item] = "";
    } else {
      result[item.substr(0, pos)] = item.substr(pos + 1);
    }
  }
  return result;
}

}  // namespace

HttpServer::HttpServer(int port) : port_(port) {}

void HttpServer::route(const std::string& method, const std::string& path, Handler handler) {
  handlers_[routeKey(method, path)] = std::move(handler);
}

HttpRequest HttpServer::parseRequest(const std::string& raw) const {
  HttpRequest request;
  std::istringstream stream(raw);
  std::string target;

  stream >> request.method >> target;
  auto queryPos = target.find('?');
  if (queryPos == std::string::npos) {
    request.path = target;
  } else {
    request.path = target.substr(0, queryPos);
    request.query = parseQuery(target.substr(queryPos + 1));
  }

  std::string line;
  std::getline(stream, line);
  while (std::getline(stream, line) && line != "\r") {
    auto sep = line.find(':');
    if (sep != std::string::npos) {
      request.headers[line.substr(0, sep)] = line.substr(sep + 1);
    }
  }

  std::ostringstream body;
  body << stream.rdbuf();
  request.body = body.str();
  return request;
}

std::string HttpServer::serializeResponse(const HttpResponse& response) const {
  std::ostringstream stream;
  stream << "HTTP/1.1 " << response.status << " OK\r\n";
  stream << "Content-Type: " << response.contentType << "\r\n";
  stream << "Content-Length: " << response.body.size() << "\r\n";
  stream << "Connection: close\r\n\r\n";
  stream << response.body;
  return stream.str();
}

int HttpServer::run() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    throw std::runtime_error("socket failed");
  }

  int reuse = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  sockaddr_in address {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(static_cast<uint16_t>(port_));

  if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
    close(fd);
    throw std::runtime_error("bind failed");
  }

  if (listen(fd, 16) < 0) {
    close(fd);
    throw std::runtime_error("listen failed");
  }

  for (;;) {
    int client = accept(fd, nullptr, nullptr);
    if (client < 0) {
      continue;
    }

    char buffer[4096];
    std::memset(buffer, 0, sizeof(buffer));
    ssize_t n = recv(client, buffer, sizeof(buffer) - 1, 0);
    if (n <= 0) {
      close(client);
      continue;
    }

    HttpRequest request = parseRequest(std::string(buffer, static_cast<size_t>(n)));
    auto handler = handlers_.find(routeKey(request.method, request.path));

    HttpResponse response;
    if (handler == handlers_.end()) {
      response.status = 404;
      response.body = "not found\n";
    } else {
      response = handler->second(request);
    }

    std::string raw = serializeResponse(response);
    send(client, raw.data(), raw.size(), 0);
    close(client);
  }
}
