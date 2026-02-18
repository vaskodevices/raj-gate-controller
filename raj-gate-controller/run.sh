#!/usr/bin/env bash
set -e

# Initialize database and admin user
python3 /app/app.py &
APP_PID=$!

echo "Raj Gate Controller started (PID: $APP_PID)"
wait $APP_PID
