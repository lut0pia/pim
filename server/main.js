"use strict";

process.title = 'pim-server';

var fs = require('fs');
var WebSocketServer = require('websocket').server;
var https = require('https');
var forge = require('node-forge');
var rsa = forge.pki.rsa;

var clients = {};

var httpsServer = https.createServer({
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
});
httpsServer.listen(18765);

var wssServer = new WebSocketServer({
    httpServer: httpsServer
});
wssServer.on('request', function(request) {
    console.log('New connection: '+request.remoteAddress);
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
                console.log('Auth request: '+connection.remoteAddress);
                break;
            case 'auth-proof': // Client sent back proof of authentification
                if(msg.decrypted===connection.secret) { // The proof is correct
                    clients[connection.public_pem] = connection;
                    connection.authenticated = true;
                    connection.sendObject({type:'authenticated'});
                    console.log('Authenticated: '+connection.remoteAddress);
                } else { // The client is not who they say, close connection
                    connection.close();
                    console.log('Unauthenticated: '+connection.remoteAddress);
                }
                break;
            case 'peer-msg': // Client wants to pass message to other client
                if(connection.authenticated) { // Only authenticated clients can ask about other clients
                    var other_connection = clients[msg.msg.to];
                    if(other_connection) {
                        other_connection.sendObject({type:'peer-msg',signature:msg.signature,msg:msg.msg})
                        console.log('Passing message');
                    } else {
                        console.log('Client asked for unknown other client');
                    }
                } else {
                    console.log('Unauthenticated client wants to pass message to other client');
                }
                break;
        }
    });
    connection.on('close', function() {
        console.log('Disconnected: '+connection.remoteAddress);
    });
});
