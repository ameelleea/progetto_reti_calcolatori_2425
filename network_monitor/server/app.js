const express = require("express");
const fs = require("fs");
const path = require("path");
const { json } = require("body-parser");

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- API ---
app.get('/siti', (req, res) => {
  try {
    // Logging della richiesta
    console.log(`\n---\nRequest:\nGET ${req.originalUrl}\n`);

    const queryKeys = Object.keys(req.query);
    const data = loadSitesFromJSON();

    if (queryKeys.length === 0) {
      let response = {
        success: true,
        message: 'Tutti i siti restituiti con successo',
        results: data
      };

      return res.json(response);
    }

    const filtered = data.filter(sito =>
      queryKeys.every(key =>
        sito[key] && sito[key].trim().toLowerCase() === req.query[key].trim().toLowerCase()
      )
    );

    if(filtered.length > 0){
      response = {
        success: true,
        message: `${filtered.length} i siti restituiti con successo`,
        results: filtered
      }
    }else{
      response = {
        success: true,
        message: 'Nessun sito trovato corrispondente ai parametri',
        results: filtered
      }
    }

    console.log(`Response:\n${JSON.stringify(response, null, 2)}\n---`);
    res.json(response);

  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Errore nella lettura dei dati' });
  }
});

// Avvia server
app.listen(PORT, () => {
  console.log(`Server avviato sulla porta ${PORT}`);
});