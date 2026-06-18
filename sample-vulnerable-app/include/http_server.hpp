#pragma once

#include <functional>
#include <map>
#include <string>

struct HttpRequest {
  std::string method;
  std::string path;
  std::map<std::string, std::string> query;
  std::map<std::string, std::string> headers;
  std::string body;
};

struct HttpResponse {
  int status = 200;
  std::string contentType = "text/plain";
  std::string body;
};

class HttpServer {
 public:
  using Handler = std::function<HttpResponse(const HttpRequest&)>;

  explicit HttpServer(int port);
  void route(const std::string& method, const std::string& path, Handler handler);
  int run();

 private:
  int port_;
  std::map<std::string, Handler> handlers_;

  HttpRequest parseRequest(const std::string& raw) const;
  std::string serializeResponse(const HttpResponse& response) const;
};
