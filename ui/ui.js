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
                    el['subjectHash'],
                    el['issuerHash'],
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
                    `<a href="https://${el['sni']}">${el['sni']}</a>`,
                    StateValueMap[(el['valid']).toString()],
                    el['description']
                ]).draw(false);
            }
        }
    });
}

function loadStatecerts() {
    $.ajax({
        'url': url + '/statecerts',
        'type': 'GET',
        'success' : function (data) {
            resp = JSON.parse(data);
            for (el of resp) {
                for (cert of el.certificates) {                
                    statecertsTable.row.add({
                        "host": `${el["host"]} > <a href="https://${el["sni"]}">${el['sni']}</a>`,
                        "type": el["type"],
                        "valid": StateValueMap[(el['valid']).toString()],
                        "description": el["description"],
                        "expired": cert["expired"],
                        "fingerprint": cert["fingerprint"],
                        "subjectHash": cert["subjectHash"],
                        "issuerHash": cert["issuerHash"],
                        "commonName": cert["commonName"],
                        "notAfter": cert["notAfter"],
                        "notBefore": cert["notBefore"]
                    }).draw();
                }
            }
        }
    });
}

function formatCert(d) {
    return '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">'+
        '<tr>'+
            '<td>Subject hash:</td>'+
            '<td>'+d.subjectHash+'</td>'+
        '</tr>'+
        '<tr>'+
            '<td>Issuer hash:</td>'+
            '<td>'+d.issuerHash+'</td>'+
        '</tr>'+
        '<tr>'+
            '<td>Common name:</td>'+
            '<td>'+d.commonName+'</td>'+
        '</tr>'+
        '<tr>'+
            '<td>Valid time:</td>'+
            '<td>'+d.notBefore+' - '+d.notAfter+'</td>'+
        '</tr>'+
    '</table>';    
}

function onlinecheck(query) {
    args = query.split("/")
    _url = url + '/check?host=' + args[0]
    if (args.length > 1) _url += "&sni" + args[1]
    $.ajax({
        'url': _url,
        'type': 'GET',
        'error': function(data) {
            console.log(adata)
        },
        'success': function (data) {
            console.log(data)
            resp = JSON.parse(data)
            $("#onlinecheck-status").text(StateValueMap[resp["valid"]])
            $("#onlinecheck-msg").text(resp["description"])
            certs = ""
            $("#onlinecheck-certificates").empty()
            for (cert of resp["certificates"]) {
                $("#onlinecheck-certificates").append($("<li>").html(
                    `<b>${cert.commonName}</b>
                    <br>domains: <i>${cert.domains}</i>
                    <br>fingerprint: <i>${cert.fingerprint}</i>
                    <br>issuer: <i>${cert.issuerHash}</i>
                    <br>valid time: <i>${cert.notBefore} - ${cert.notAfter}</i>
                    `
                    )
                )
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
    statecertsTable = $('#statecertsTable').DataTable({
        "columns": [
            {
                "className": "details-control",
                "orderable": false,
                "data": null,
                "defaultContent": '+'
            },
            {"data": "host"},
            {"data": "fingerprint"},
            {"data": "type"},
            {"data": "valid"},
            {"data": "description"},
            {"data": "expired"}
        ]
    });
    loadCerts();
    loadStates();
    loadStatecerts();
    $('a[data-toggle="tab"]').on('shown.bs.tab', function(e){
        $($.fn.dataTable.tables(true)).DataTable()
           .columns.adjust();
     });
     $('#statecertsTable tbody').on('click', 'td.details-control', function () {
        var tr = $(this).closest('tr');
        var row = statecertsTable.row(tr)

        if (row.child.isShown()) {
            row.child.hide();
            tr.removeClass('shown');
            $(this).text('+')
        } else {
            row.child(formatCert(row.data())).show();
            tr.addClass('shown');
            $(this).text('-')
        }
     });
} );