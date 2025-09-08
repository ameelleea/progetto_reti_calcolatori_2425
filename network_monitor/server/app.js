const express = require("express");
const fs = require("fs");
const path = require("path");
const { json } = require("body-parser");

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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