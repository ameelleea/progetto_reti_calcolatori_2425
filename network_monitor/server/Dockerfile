# Usa una immagine base Node
FROM node:20

# Crea la cartella di lavoro
WORKDIR /usr/src/app

# Copia package.json e installa dipendenze
COPY package*.json ./
RUN npm install --production

# Copia il codice
COPY . .

# Espone la porta del server (ad es. 3000)
EXPOSE 3000

# Comando di avvio
CMD ["node", "server.js"]
