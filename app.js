// static/app.js
const socket = io();

const statusEl = document.getElementById('status');
const tbody = document.querySelector('#packets tbody');

function addRow(pkt) {
  const tr = document.createElement('tr');
  const time = pkt.time_stamp || pkt.timestamp || '';
  tr.innerHTML = `
    <td>${time}</td>
    <td>${pkt.ipsrc || ''}</td>
    <td>${pkt.srcport || ''}</td>
    <td>${pkt.ipdst || ''}</td>
    <td>${pkt.dstport || ''}</td>
    <td>${pkt.transport_layer || ''}</td>
    <td>${pkt.highest_layer || ''}</td>
  `;
  tbody.insertBefore(tr, tbody.firstChild);
  // Keep table to reasonable size
  while (tbody.childElementCount > 200) tbody.removeChild(tbody.lastChild);
}

socket.on('connect', () => {
  statusEl.textContent = 'Connected to server';
});

socket.on('disconnect', () => {
  statusEl.textContent = 'Disconnected';
});

socket.on('recent_packets', (arr) => {
  tbody.innerHTML = '';
  for (let i = arr.length - 1; i >= 0; i--) addRow(arr[i]);
});

socket.on('new_packet', (pkt) => {
  addRow(pkt);
});
