"use strict";

process.title = 'pim-server';

var fs = require('fs');
var WebSocketServer = require('websocket').server;
var https = require('https');
var http = require('http');
var forge = require('node-forge');
var rsa = forge.pki.rsa;
var clients = {};
var server_files = {};

function pim_log(str) {
  console.log((new Date()).toLocaleString()+': '+str);
}

// Cache files that http server will have to serve
fs.readdirSync('../client/').forEach(function(filename) {
  var file_contents = fs.readFileSync('../client/'+filename);
  server_files['/'+filename] = file_contents;
});

function http_callback(request,response) {
  if(request.url=='/') request.url = '/index.html';
  try {
    response.writeHead(200);
    response.end(server_files[request.url]);
  } catch(e) {
    response.writeHead(404);
  }
}

var http_server;
try {
  var server_options = {
    // TODO: These values should change for another server, add a conf file?
    key: fs.readFileSync('/etc/letsencrypt/live/pim.lucien.cat/privkey.pem'),
    cert: fs.readFileSync('/etc/letsencrypt/live/pim.lucien.cat/cert.pem')
  };
  http_server = https.createServer(server_options,http_callback);
} catch(e) {
  http_server = http.createServer(http_callback);
}
http_server.listen(18765);

var ws_server = new WebSocketServer({
  httpServer: http_server
});
ws_server.on('request', function(request) {
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
