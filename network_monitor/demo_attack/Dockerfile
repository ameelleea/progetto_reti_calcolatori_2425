# Usa un'immagine Python leggera
FROM python:3.12-slim

# Installiamo scapy
RUN pip install scapy

# Copiamo lo script nella cartella del container
WORKDIR /app
COPY demo_attack_simulator.py .

# Comando di default per eseguire lo script
CMD ["python", "demo_attack_simulator.py"]
