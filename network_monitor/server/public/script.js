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
    aggiornaGrafico(traffic_by_protocol, colors, bordercolors)
    //protochart.data.labels = Object.keys(traffic_by_protocol);
    //protochart.data.datasets[0].data = Object.values(traffic_by_protocol);
    //protochart.update();
});

socket.on('security_alert_notifier', (data) => {
    let alert_message = document.getElementById('alert-box').querySelector('span');
    alert_message.innerHTML = data;
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

bordercolors = ['#84A98C', '#52796F', '#354F52', '#2F3E46', '#CAD2C5']
colors = ['#84a98c94', '#52796f86', '#354f5291', '#2f3e468f', '#cad2c5c7']
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
            title: { display: true, text: 'Indirizzo IP', font: {weight: 'bold'} }
        },
        y: {
            title: { display: true, text: 'Traffico (Kb)', font: {weight: 'bold'} }
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
            borderColor: colors[3],
            borderWidth: 3,   // linea più spessa
            fill: false,
            tension: 0.2,
            pointRadius: 0,
            pointHoverRadius: 0
        },{
            label: "IN",
            data: io_traffic["in"],
            borderColor: colors[1],
            borderWidth: 3,
            fill: false,
            tension: 0.2,
            pointRadius: 0,
            pointHoverRadius: 0
        }]
    },
    options: {
        responsive: false,
        plugins: {
            legend: {
                position: 'top',
                labels: {
                    usePointStyle: false, // fa vedere la linea
                    boxWidth: 40,
                    boxHeight: 2
                }
            }
        },
        scales: {
            x: {
                min: 0,
                max: 60,
                type: 'linear',
                title: {
                    display: true,
                    text: 'Tempo (sec)',
                    font: {
                        weight: 'bold',
                }
            },
            y: {
                title: { display: true, text: 'Traffico (Kb)', font: {weight: 'bold'}}
            }
            }
        }
    }
});

function aggiornaGrafico(dati, colori, bordi) {
    protochart.data.labels = Object.keys(dati);
    protochart.data.datasets[0].data = Object.values(dati);
    protochart.data.datasets[0].backgroundColor = colori;
    protochart.data.datasets[0].borderColor = bordi;

    // mostra legenda e datalabels
    protochart.options.plugins.legend.display = true;
    protochart.options.plugins.datalabels.display = true;

    // datalabels solo percentuali
    protochart.options.plugins.datalabels.formatter = (value, context) => {
        const data = context.chart.data.datasets[0].data;
        const total = data.reduce((sum, val) => sum + val, 0);
        const percentage = ((value / total) * 100).toFixed(0);
        return `${percentage}%`;
    };

    protochart.update();
}


// inizializzazione grafico "vuoto"
const protochart = new Chart(protochartEl, {
    type: 'pie',
    data: {
        labels: [], // nessuna etichetta all'inizio
        datasets: [{
            label: 'Traffico (byte)',
            data: [1], // un solo valore per fare un cerchio pieno
            backgroundColor: colors[0], // colore grigio chiaro
            borderColor: bordercolors[0],
            borderWidth: 1
        }]
    },
    options: {
        responsive: false,
        plugins: {
            legend: {
                display: false // nascondiamo la legenda inizialmente
            },
            datalabels: {
                display: false // niente etichette inizialmente
            }
        },
        scales: {
            y: { display: false },
            x: { display: false }
        }
    },
    plugins: [ChartDataLabels]
});



let table = $('#myTable').DataTable({
    pageLength: 10,
    order: [[0, 'desc']]
});

