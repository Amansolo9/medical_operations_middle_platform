#!/bin/sh
set -e

run_pytest() {
  if [ -x ".venv/Scripts/python.exe" ]; then
    .venv/Scripts/python.exe -m pytest -q "$@"
    return
  fi

  if [ -x ".venv/bin/python" ]; then
    .venv/bin/python -m pytest -q "$@"
    return
  fi

  if command -v pytest >/dev/null 2>&1; then
    pytest -q "$@"
    return
  fi

  docker compose run --rm web python -m pytest -q "$@"
}

echo "Running unit tests..."
run_pytest unit_tests

echo "Running API tests..."
run_pytest API_tests
