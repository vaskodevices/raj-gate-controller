#!/usr/bin/with-contenv bashio

bashio::log.info "Starting Raj Gate Controller..."

exec python3 /app/app.py
