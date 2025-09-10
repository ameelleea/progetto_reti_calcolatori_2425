# Usa una immagine base Python
FROM python:3.11-slim

# Imposta la cartella di lavoro
WORKDIR /usr/src/app

# Copia requirements se li hai
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copia il codice Python
COPY . .

# Espone una porta se il socket ascolta (es. 5000)
EXPOSE 5000

# Avvia il package come modulo (grazie a __main__.py)
CMD ["python", "-m", "mypkg"]
