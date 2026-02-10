#!/bin/bash
docker run -it --rm \
  --network csce413_assignment2_vulnerable_network \
  -v "$(pwd)/port_scanner:/app" \
  -w /app \
  python:3.9-slim \
  python3 main.py "$@"