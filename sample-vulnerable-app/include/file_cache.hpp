#pragma once

#include <string>

class FileCache {
 public:
  explicit FileCache(std::string baseDir);

  std::string readTextFile(const std::string& name) const;
  std::string exportSnapshot(const std::string& token) const;

 private:
  std::string baseDir_;
};
