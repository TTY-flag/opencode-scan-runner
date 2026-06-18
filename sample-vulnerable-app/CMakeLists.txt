cmake_minimum_required(VERSION 3.16)
project(edge_gateway_demo LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(edge-gateway
  src/main.cpp
  src/http_server.cpp
  src/user_store.cpp
  src/file_cache.cpp
  src/diagnostics.cpp
)

target_include_directories(edge-gateway PRIVATE include)
