const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require("path");

const app = express();
const PORT = 3000;
app.use(express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*"
    }
});

io.on('connection', (socket) => {
    console.log('Un client si è connesso:', socket.id);

    socket.on('packet_log_data', (data) => {
        io.emit('packet_log_listener', data);
    });

    socket.on('ip_log_data', (data) => {
        io.emit('ip_log_listener', data);
    });

    socket.on('protocol_traffic_data', (data) => {
        io.emit('protocol_traffic_listener', data);
    });

    socket.on('io_traffic_data', (data) => {
        io.emit('io_traffic_listener', data);
    });

    socket.on('security_alert_listener', (data) => {
        console.log(data);
        io.emit('security_alert_notifier', data);
    });

    socket.on('disconnect', (reason) => {
        console.log(`Client ${socket.id} si è disconnesso. Motivo: ${reason}`);
    });
});


server.listen(3000, () => {
    console.log(`Server WebSocket attivo su http://localhost:${PORT}`);
});
