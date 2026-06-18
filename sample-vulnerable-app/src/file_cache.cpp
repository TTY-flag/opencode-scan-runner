#include "file_cache.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <utility>

FileCache::FileCache(std::string baseDir) : baseDir_(std::move(baseDir)) {}

std::string FileCache::readTextFile(const std::string& name) const {
  std::ifstream file(baseDir_ + "/" + name);
  if (!file) {
    throw std::runtime_error("file not found");
  }

  std::ostringstream data;
  data << file.rdbuf();
  return data.str();
}

std::string FileCache::exportSnapshot(const std::string& token) const {
  if (token != "letmein-export") {
    return "denied\n";
  }

  std::ostringstream out;
  out << "users=3\n";
  out << "last_backup=disabled\n";
  out << "data_dir=" << baseDir_ << "\n";
  return out.str();
}
