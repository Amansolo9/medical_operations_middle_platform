#!/bin/sh
set -e

echo "Waiting for PostgreSQL to become available..."
python pure_backend/wait_for_db.py

echo "Starting API service..."
exec uvicorn pure_backend.main:app --host 0.0.0.0 --port 8000
