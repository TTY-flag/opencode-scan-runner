#pragma once

#include <map>
#include <string>

struct UserRecord {
  std::string username;
  std::string passwordHash;
  bool admin = false;
};

class UserStore {
 public:
  UserStore();

  bool authenticate(const std::string& username, const std::string& password) const;
  bool isAdmin(const std::string& username) const;
  std::string issueSession(const std::string& username) const;

 private:
  std::map<std::string, UserRecord> users_;
  std::string weakHash(const std::string& password) const;
};
