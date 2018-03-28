"use strict";

process.title = 'pim-server';

var fs = require('fs');
var WebSocketServer = require('websocket').server;
var https = require('https');
var forge = require('node-forge');
var rsa = forge.pki.rsa;

function pim_log(str) {
    console.log((new Date()).toLocaleString()+': '+str);
}

var clients = {};

var httpsServer = https.createServer({
    // TODO: These values should change for another server, add a conf file?
    key: fs.readFileSync('/etc/letsencrypt/live/pim.luciencatonnet.com/privkey.pem'),
    cert: fs.readFileSync('/etc/letsencrypt/live/pim.luciencatonnet.com/cert.pem')
});
httpsServer.listen(18765);

var wssServer = new WebSocketServer({
    httpServer: httpsServer
});
wssServer.on('request', function(request) {
    pim_log('New connection: '+request.remoteAddress);
    var connection = request.accept(null, request.origin);
    connection.sendObject = function(obj) { this.send(JSON.stringify(obj)); }
    connection.remoteAddress = request.remoteAddress;
    
    connection.on('message', function(msg) {
        try { msg = JSON.parse(msg.utf8Data); }
        catch(e) { return; }

        switch(msg.type) {
            case 'auth': // Client is trying to authenticate, ask for proof of identity
                var public_key = forge.pki.publicKeyFromPem(msg.public_pem);
                connection.public_pem = msg.public_pem;
                connection.secret = '----PROOF----'+forge.util.bytesToHex(forge.random.getBytesSync(16));
                connection.sendObject({type:'prove-auth',encrypted:public_key.encrypt(connection.secret,'RSAES-PKCS1-V1_5')});
                pim_log('Auth request: '+connection.remoteAddress);
                break;
            case 'auth-proof': // Client sent back proof of authentification
                if(msg.decrypted===connection.secret) { // The proof is correct
                    clients[connection.public_pem] = connection;
                    connection.authenticated = true;
                    connection.sendObject({type:'authenticated'});
                    pim_log('Authenticated: '+connection.remoteAddress);
                } else { // The client is not who they say, close connection
                    connection.close();
                    pim_log('Unauthenticated: '+connection.remoteAddress);
                }
                break;
            case 'relay-msg': // Client wants to pass message to other client
                if(connection.authenticated) { // Only authenticated clients can ask about other clients
                    var other_connection = clients[msg.msg.to];
                    if(other_connection) {
                        other_connection.sendObject({type:'relayed-msg',signature:msg.signature,msg:msg.msg})
                        pim_log('Passing message');
                    } else {
                        pim_log('Client asked for unknown other client');
                    }
                } else {
                    pim_log('Unauthenticated client wants to pass message to other client');
                }
                break;
        }
    });
    connection.on('close', function() {
        pim_log('Disconnected: '+connection.remoteAddress);
    });
});
