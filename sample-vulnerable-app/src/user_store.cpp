#include "user_store.hpp"

#include <cstdio>
#include <ctime>

UserStore::UserStore() {
  users_["alice"] = {"alice", weakHash("wonderland"), false};
  users_["operator"] = {"operator", weakHash("op-password"), false};
  users_["admin"] = {"admin", weakHash("admin123"), true};
}

std::string UserStore::weakHash(const std::string& password) const {
  unsigned int value = 5381;
  for (char ch : password) {
    value = ((value << 5) + value) + static_cast<unsigned char>(ch);
  }
  return std::to_string(value);
}

bool UserStore::authenticate(const std::string& username, const std::string& password) const {
  auto user = users_.find(username);
  if (user == users_.end()) {
    return false;
  }
  return user->second.passwordHash == weakHash(password);
}

bool UserStore::isAdmin(const std::string& username) const {
  auto user = users_.find(username);
  return user != users_.end() && user->second.admin;
}

std::string UserStore::issueSession(const std::string& username) const {
  char token[32];
  std::sprintf(token, "sess-%s-%ld", username.c_str(), static_cast<long>(std::time(nullptr)));
  return token;
}
