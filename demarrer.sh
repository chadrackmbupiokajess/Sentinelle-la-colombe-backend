#!/usr/bin/env bash
# Lance le backend Sentinelle, accessible depuis tout le réseau (tablettes, téléphones).
cd "$(dirname "$0")"
[ -f .venv/bin/activate ] && source .venv/bin/activate
python3 main.py
