//Costanti
const socket = io("http://localhost:3000");
const ipchartEl = document.getElementById('ipchart').getContext('2d');
const iochartEl = document.getElementById('iochart').getContext('2d');
const protochartEl = document.getElementById('protochart').getContext('2d');

let traffic_by_ip = {}
let traffic_by_protocol = {}
let io_traffic = {}
let iodatasets = {};

//Setting grafici
Chart.defaults.font.family = "'Roboto Condensed', sans-serif";
Chart.defaults.font.size = 14; 
Chart.defaults.color = '#333'; 
bordercolors = ['#84A98C', '#52796F', '#354F52', '#2F3E46', '#CAD2C5']
colors = ['#84a98c94', '#52796f86', '#354f5291', '#2f3e468f', '#cad2c5c7']


//Funzioni di utility
function showAlert(message) {
    const alertBox = document.getElementById('alert-box');
    alertBox.innerHTML = message;
    alertBox.style.opacity = '1';
    alertBox.style.transform = 'translateY(0)';
    
    setTimeout(() => {
        alertBox.style.opacity = '0';
        alertBox.style.transform = 'translateY(-10px)';
    }, 10000);
}

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

//WebSocket
socket.on("packet_log_listener", (data) => {
    let newData = Object.keys(data).map(key => data[key]);
    table.row.add(newData).draw(false); 

});

socket.on("ip_log_listener", (data) => {
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
    ipchart.data.datasets[0].data = normalizedData;
    ipchart.update();

});

socket.on("protocol_traffic_listener", (data) => {
    traffic_by_protocol = data;
    aggiornaGrafico(traffic_by_protocol, colors, bordercolors)
});

socket.on('security_alert_notifier', (data) => {
    showAlert(data);
});

socket.on("io_traffic_listener", (data) => {
    io_traffic = data;
    for(const key in data){
        iodatasets[key] = Object.entries(io_traffic[key]).map(([k, v]) => ({
        x: parseFloat(k), 
        y: v              
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


//Grafici
const ipchart = new Chart(ipchartEl, {
    type: 'bar',
    data: {
        labels: ['N/D', 'N/D', 'N/D', 'N/D', 'N/D'], 
        datasets: [{
            label: null,
            data: [0,0,0,0,0], 
            backgroundColor: colors,
            borderColor: bordercolors,
            borderWidth: 1
        }]
    },
    options: {
        plugins: {
            legend: {
                display: false
            }
        },
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
            borderWidth: 3,   
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
                    usePointStyle: false, 
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


// inizializzazione grafico "vuoto"
const protochart = new Chart(protochartEl, {
type: 'pie',
data: {
    labels: [], 
    datasets: [{
        label: 'Traffico (byte)',
        data: [1], 
        backgroundColor: colors[0], 
        borderColor: bordercolors[0],
        borderWidth: 1
    }]
},
options: {
    responsive: false,
    plugins: {
        legend: {
            display: false 
        },
        datalabels: {
            display: false 
        }
    },
    scales: {
        y: { display: false },
        x: { display: false }
    }
},
plugins: [ChartDataLabels]
});

//Tabella
let table = $('#myTable').DataTable({
    pageLength: 10,
    order: [[0, 'desc']]
});

