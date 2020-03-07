const url=window.location.origin

var certsTable = null;
var statesTable = null;

const StateValueMap = {
    '0': 'Invalid',
    '1': 'Valid',
    '-1': 'Unknown'
}

function loadCerts() {
    $.ajax({
        'url': url + '/certs',
        'type': 'GET',
        'success': function (data) {
            resp = JSON.parse(data);
            for (el of resp) {
                certsTable.row.add([
                    el['commonName'],
                    el['fingerprint'],
                    el['issuerFingerprint'],
                    el['domains'],
                    el['expired']
                ]).draw(false);
            }
        }
    });
}

function loadStates() {
    $.ajax({
        'url': url + '/states',
        'type': 'GET',
        'success' : function (data) {
            resp = JSON.parse(data);
            for (el of resp) {
                statesTable.row.add([
                    el['host'],
                    el['sni'],
                    StateValueMap[(el['valid']).toString()],
                    el['description']
                ]).draw(false);
            }
        }
    });
}

function onlinecheck(query) {
    args = query.split("/")
    _url = url + '/check?host=' + args[0]
    if (args.length > 1) _url += "&sni" + args[1]
    $.ajax({
        'url': _url,
        'type': 'GET',
        'success': function (data) {
            resp = JSON.parse(data)
            $("#onlinecheck-status").text(StateValueMap[resp["valid"]])
            $("#onlinecheck-msg").text(StateValueMap[resp["description"]])
            certs = ""
            for (cert of resp["certificates"]) {                
                $("#onlinecheck-certificates").append($("li").text(cert.toString()))
            }
        }
    })
}

$(document).ready(function() {
    $("#btn-onlinecheck").click(function () {
        onlinecheck($("#onlinecheck-query").val())
    })
    certsTable = $('#certsTable').DataTable({
        "createdRow": function(row, data, dataIndex) {
            if( data[4] < 35 ){
                $(row).addClass('danger');
            }
        }
    });
    statesTable = $('#statesTable').DataTable({
        "createdRow": function(row, data, dataIndex) {
            if( data[2] == 'Invalid' ){
                $(row).addClass('danger');
            }
        }
    });
    loadCerts();
    loadStates();
    $('a[data-toggle="tab"]').on('shown.bs.tab', function(e){
        $($.fn.dataTable.tables(true)).DataTable()
           .columns.adjust();
     });
} );