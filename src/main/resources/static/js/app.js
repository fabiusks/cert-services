/**
 * Main Aplication Javascript File
 */

$(document).ready(function() {
	console.log("cert-services ready.");
	getPKIListData();
});

function fillPKITable(data) {
	var table = document.createElement("table");
	
	if(data.length > 0) {
		for(var i = 0; i < data.length; i++) {
			var tr = document.createElement("tr");
			var td = document.createElement("td");
			td.innerHTML = data[i].name;
			tr.appendChild(td);
			table.appendChild(tr);
		}
	} else {
		var tr = document.createElement("tr");
		var td = document.createElement("td");
		
		td.innerHTML = "No PKIs currently generated.";
		tr.appendChild(td);
		table.appendChild(tr);
	}
	
	document.getElementById("pkiList").appendChild(table);
}

function getPKIListData() {
	console.log("cert-services - Retrieving PKI list.");
	
	$.ajax( {
		type: "GET",
		url: "http://localhost:8080/rest/pki/list",
		success: function(data) {
			fillPKITable(data);
		},
		
		error: function(data) {
			alerta("cert-services - error while listing PKIs: " + data);
		}
	});
}