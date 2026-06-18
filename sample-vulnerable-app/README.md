# Edge Gateway Demo

This is a small C++17 demo service for the OpenCode security scanner runner.

It models a lightweight edge gateway with:

- HTTP request routing
- user authentication and session issuing
- file download from a data directory
- diagnostic command execution
- audit logging

Build locally on Linux:

```sh
cmake -S . -B build
cmake --build build
./build/edge-gateway 8080
```

Example endpoints:

```text
GET  /health
GET  /files?name=welcome.txt
POST /login?user=alice&password=wonderland
POST /debug/ping?host=127.0.0.1
GET  /admin/export?token=letmein-export
```

The project intentionally contains several realistic security smells for scanner validation.
