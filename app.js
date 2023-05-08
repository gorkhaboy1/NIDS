var socket = io.connect('http://' + document.domain + ':' + location.port);

socket.on('connect', function() {
	console.log('Socket connected');
});

socket.on('disconnect', function() {
	console.log('Socket disconnected');
});

socket.on('packet', function(packet) {
	console.log(packet);
	var table = document.getElementById("packet-table").getElementsByTagName('tbody')[0];
	var row = table.insertRow(0);
	var timeCell = row.insertCell(0);
	var sizeCell = row.insertCell(1);
	var protocolCell = row.insertCell(2);
	var srcIpCell = row.insertCell(3);
	var dstIpCell = row.insertCell(4);
	var srcPortCell = row.insertCell(5);
	var dstPortCell = row.insertCell(6);
	timeCell.innerHTML = packet.timestamp;
	sizeCell.innerHTML = packet.packet_size;
	protocolCell.innerHTML = packet.protocol;
	srcIpCell.innerHTML = packet.src_ip;
	dstIpCell.innerHTML = packet.dst_ip;
	srcPortCell.innerHTML = packet.src_port;
	dstPortCell.innerHTML = packet.dst_port;
});

function clearTable() {
	var table = document.getElementById("packet-table").getElementsByTagName('tbody')[0];
	table.innerHTML = '';
}
