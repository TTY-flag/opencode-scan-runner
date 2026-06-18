#include "diagnostics.hpp"

#include <array>
#include <cstdio>
#include <sstream>

std::string Diagnostics::pingHost(const std::string& host) const {
  std::string command = "ping -c 1 " + host;
  std::array<char, 256> buffer {};
  std::ostringstream output;

  FILE* pipe = popen(command.c_str(), "r");
  if (!pipe) {
    return "failed to start diagnostic command\n";
  }

  while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
    output << buffer.data();
  }
  pclose(pipe);
  return output.str();
}
