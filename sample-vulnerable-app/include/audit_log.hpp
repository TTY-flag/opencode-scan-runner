#pragma once

#include <fstream>
#include <string>
#include <ctime>

class AuditLog {
 public:
  explicit AuditLog(const std::string& path) : out_(path, std::ios::app) {}

  void event(const std::string& user, const std::string& action, const std::string& detail) {
    out_ << std::time(nullptr) << " user=" << user
         << " action=" << action
         << " detail=" << detail << "\n";
  }

 private:
  std::ofstream out_;
};
