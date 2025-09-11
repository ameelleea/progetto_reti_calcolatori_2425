#!/bin/bash

set -e

# Config
INTERFACE="wlp3s0"
HOST="localhost"
PORT=3000

echo "[1/6] Pulizia eventuali container residui..."
docker compose down

echo "[2/6] Avvio server Node in Docker..."
docker compose up --build -d

echo "[3/6] Pulizia eventuali virtual environment Python vecchi..."
if [ -d "./venv" ]; then
    echo "Rimuovo ./venv esistente..."
    rm -rf ./venv
fi

echo "[4/6] Creazione nuovo virtual environment Python con pip..."
python3 -m venv --upgrade-deps venv
source ./venv/bin/activate

echo "[5/6] Installazione package netsniffer in modalità editable..."
pip install --upgrade pip setuptools wheel
pip install -e .

echo "[6/6] Avvio sniffer sulla rete locale con permessi root..."
sudo ./venv/bin/netsniffer --iface "$INTERFACE" -H "$HOST" -p "$PORT"




