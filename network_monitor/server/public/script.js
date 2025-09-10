const socket = io("http://localhost:3000");
let traffic_by_ip = {}
let traffic_by_protocol = {}
let io_traffic = {}
let iodatasets = {};

socket.on("packet_log_listener", (data) => {
    // Nuovo dato che vuoi aggiungere
    let newData = Object.keys(data).map(key => data[key]);
    // Aggiungi riga
    table.row.add(newData).draw(false); 

});

socket.on("ip_log_listener", (data) => {
    //console.log("Traffico generato per IP:", data);
    traffic_by_ip = data;

    let newLabels = []
    let newData = []

    console.log(newLabels)
    for(let i=0; i <5; i++){
        if(Object.keys(traffic_by_ip)[i] !== undefined){
            newLabels[i] = Object.keys(traffic_by_ip)[i]
            newData[i] = Object.values(traffic_by_ip)[i]
        }else{
            newLabels[i] = 'N/D';
            newData[i] = 0;
        }
    }

    const max = Math.max(...newData);
    console.log(max)
    const normalizedData = newData.map(v => v/1024);
    console.log(newLabels)
    ipchart.data.labels = newLabels
    //ipchart.data.label = Object.keys(traffic_by_ip);
    ipchart.data.datasets[0].data = normalizedData;
    ipchart.update();

});

socket.on("protocol_traffic_listener", (data) => {
    traffic_by_protocol = data;
    protochart.data.labels = Object.keys(traffic_by_protocol);
    protochart.data.datasets[0].data = Object.values(traffic_by_protocol);
    protochart.update();
});

socket.on("io_traffic_listener", (data) => {
    io_traffic = data;
    for(const key in data){
        iodatasets[key] = Object.entries(io_traffic[key]).map(([k, v]) => ({
        x: parseFloat(k), // chiave come numero
        y: v              // valore
        }));
    }

    iochart.data.datasets[0].data = iodatasets["out"];
    iochart.data.datasets[1].data = iodatasets["in"];
    let max_in = iodatasets["in"][0].x;

    for(let i=0; i < iodatasets["in"].length; i++){
        if(iodatasets["in"][i].x > max_in){
            max_in = iodatasets["in"][i].x;
        }
    }

    let max_out = iodatasets["out"][0].x;
    
    for(let i=0; i < iodatasets["out"].length; i++){
        if(iodatasets["out"][i].x > max_out){
            max_out = iodatasets["out"][i].x;
        }
    }
    if(Math.max(max_in, max_out) > 60){
        iochart.options.scales.x.max = Math.max(max_in, max_out) * 1,1;
    }
    iochart.update();
});


Chart.defaults.font.family = "'Roboto Condensed', sans-serif"; // font globale
Chart.defaults.font.size = 14; // dimensione in px
//Chart.defaults.font.style = 'bold'; // stile: normal, bold, italic
Chart.defaults.color = '#333'; // colore testo globale

bordercolors = ['#F25E86', '#F2B366', '#F2AA6B', '#F28972', '#F27777']
colors = ['#f25e8594', '#f2b36694', '#f2aa6b98', '#f289728f', '#f2777798']
const ipchartEl = document.getElementById('ipchart').getContext('2d');
const iochartEl = document.getElementById('iochart').getContext('2d');
const protochartEl = document.getElementById('protochart').getContext('2d');

const ipchart = new Chart(ipchartEl, {
    type: 'bar',
    data: {
        labels: ['N/D', 'N/D', 'N/D', 'N/D', 'N/D'], // etichette sull'asse X
        datasets: [{
            label: "Valori",
            data: [0,0,0,0,0], // valori sull'asse Y
            backgroundColor: colors,
            borderColor: bordercolors,
            borderWidth: 1
        }]
    },
    options: {
        responsive: false,
        scales: {
        x: {
            title: { display: true, text: 'Indirizzo IP' }
        },
        y: {
            title: { display: true, text: 'Traffico (Kb)' }
        }
    }
}
});

const iochart = new Chart(iochartEl, {
    type: 'line',
        data: {
            labels: Array.from({ length: 13 }, (_, i) => 0 + i * 120),
            datasets: [{
                label: "OUT",
                data: io_traffic["out"],
                borderColor: colors[0],
                backgroundColor: colors[0], // area sotto linea trasparente
                fill: true,
                tension: 0.3
            },{
                label: "IN",
                data: io_traffic["in"],
                borderColor: colors[1],
                backgroundColor: colors[1].replace('1)', '0.2)'), // area sotto linea trasparente
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: false,
            plugins: {
                legend: { position: 'top' }
            },
            scales: {
            x: {
                min: 0,
                max: 60,
                type: 'linear', // importante per valori numerici
                title: { display: true, text: 'Tempo (sec)' }
            },
            y: {
                title: { display: true, text: 'Traffico (Kb)' }
            }
        }
        }
});

const protochart = new Chart(protochartEl, {
    type: 'pie', // tipologia di grafico: bar, line, pie, etc.
    data: {
        labels: Object.keys(traffic_by_protocol), // etichette sull'asse X
        datasets: [{
            label: 'Traffico (byte)',
            data: Object.values(traffic_by_protocol), // valori sull'asse Y
            backgroundColor: colors,
            borderColor: bordercolors,
            borderWidth: 1
        }]
    },
    options: {
        responsive: false,
        scales: {
            y: { beginAtZero: true }
        }
    }
});

let table = $('#myTable').DataTable({
    pageLength: 10,
    order: [[0, 'desc']]
});

