# Monitoraggio in tempo reale della rete locale

## Descrizione
Progetto per l'esame di Reti di Calcolatori.
Il sistema cattura pacchetti nella LAN, li analizza e li mostra in una dashboard web in tempo reale.

## Struttura
- `sniffer/` → cattura e analisi pacchetti
- `web/` → server Flask + dashboard
- `docs/` → documentazione

## Setup
```bash
git clone <repo>
cd network-monitor
pip install -r requirements.txt
sudo python web/app.py
