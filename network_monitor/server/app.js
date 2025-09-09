const express = require("express");
const fs = require("fs");
const path = require("path");
const { json } = require("body-parser");

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

io.on("connection", (socket) => {
  console.log("Client connesso via WS");
});

server.listen(3000, () => console.log("WS server listening on port 3000"));

// --- API ---
app.get('/traffico', (req, res) => {
  fs.readFile('../sniffer/traffic.json', (err, data) => {
    if (err) return res.status(500).send("Errore nel leggere i dati");
    res.json(JSON.parse(data));
  });
});

// Avvia server
app.listen(PORT, () => {
  console.log(`Server avviato sulla porta ${PORT}`);
});