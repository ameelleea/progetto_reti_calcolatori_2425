#!/bin/bash

# Path allo script Python dei demo attacchi
DEMO_SCRIPT="./demo_attack/demo_attack.py"

# Funzione per stampare il menu
show_menu() {
    echo "=============================="
    echo "  Demo Attacchi Rete"
    echo "=============================="
    echo "1) ARP Spoofing"
    echo "2) SYN Flood"
    echo "3) ICMP Flood"
    echo "4) TCP Reset Attack"
    echo "5) UDP Amplification"
    echo "6) DNS Tunneling"
    echo "7) DDoS Simulation"
    echo "8) Tutti gli attacchi"
    echo "0) Esci"
    echo "=============================="
}

while true; do
    show_menu
    read -p "Seleziona un attacco (0-8): " choice
    case $choice in
        1) python3 "$DEMO_SCRIPT" arp ;;
        2) python3 "$DEMO_SCRIPT" syn ;;
        3) python3 "$DEMO_SCRIPT" icmp ;;
        4) python3 "$DEMO_SCRIPT" tcpreset ;;
        5) python3 "$DEMO_SCRIPT" udp ;;
        6) python3 "$DEMO_SCRIPT" dns ;;
        7) python3 "$DEMO_SCRIPT" ddos ;;
        8) python3 "$DEMO_SCRIPT" all ;;
        0) echo "Uscita."; break ;;
        *) echo "Scelta non valida, riprova." ;;
    esac
    echo "Premi INVIO per continuare..."
    read
done
