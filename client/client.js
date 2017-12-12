var rsa = forge.pki.rsa;

WebSocket.prototype.sendObject = function(obj) { this.send(JSON.stringify(obj)); }

var pim_log = console.log;
var pim_servers = {}; // Connections with servers
var pim_connections = {}; // Connections with peers
var pim_account = {
    shared:{}, // This is what gets shared with peers
    peers:{} // This contains what peers have shared
};
var pim_recvd_peer_msgs = {}; // Hashes of messages received (through servers)
var pim_private_key;

function pim_add_server(url) {
    if(pim_servers[url]) return;
    var ws = new WebSocket(url);
    ws.onopen = function() {
        pim_log('Connected to server: '+url);
        pim_servers[url] = ws;
        pim_auth();
    };
    ws.onclose = function() {
        pim_log('Disconnected from server: '+url);
        pim_servers[url] = null;
    };
    ws.onerror = function() {
        pim_log('Could not connect to server: '+url);
    };
    ws.onmessage = function(msg) {
        try { msg = JSON.parse(msg.data);}
        catch(e) { pim_log(e.message); return; }

        switch(msg.type) {
            case 'prove-auth': // Server has sent us an encrypted message we have to decypher to prove our identity
                var decrypted = pim_private_key.decrypt(msg.encrypted,'RSAES-PKCS1-V1_5');
                if(decrypted.substr(0,13)=='----PROOF----') { // Check header so we don't accidentally decipher anything for a server
                    ws.sendObject({type:'auth-proof',decrypted:decrypted});
                    pim_log('Sending proof to server: '+url);
                } else { // Server is corrupt or buggy?
                    ws.close();
                    pim_log('Server is corrupt: '+url);
                }
                break;
            case 'authenticated':
                ws.authenticated = true;
                pim_log('Authenticated to server: '+url);
                break;
            case 'peer-msg':
                var md = forge.md.sha1.create();
                md.update(JSON.stringify(msg.msg), 'utf8');
                var hash = md.digest().getBytes();
                if(!pim_recvd_peer_msgs[hash]) { // Ensure we don't receive the same message twice (multiple servers can do that)
                    pim_recvd_peer_msgs[hash] = true;
                    var publicKey = forge.pki.publicKeyFromPem(msg.msg.from);
                    if(publicKey.verify(md.digest().bytes(), msg.signature)) { // The message comes from who it says it does
                        pim_recv_peer_msg(ws,msg.msg);
                    } else {
                        pim_log('Received falsified peer message from: '+url);
                    }
                }
                break;
        }
    };
}
function pim_recv_peer_msg(server,msg) {
    switch(msg.type) {
        case 'connect-from':
            pim_connect_from(msg.from,msg.desc);
            break;
        case 'ice-candidate':
            pim_ice_candidate(msg.from,msg.candidate);
            break;
    }
}
function pim_send_peer_msg(msg) {
    msg.from = pim_account.public_pem;
    var publicKey = forge.pki.publicKeyFromPem(msg.to);
    var md = forge.md.sha1.create();
    md.update(JSON.stringify(msg),'utf8');
    pim_broadcast_to_servers({
        type:'peer-msg',
        msg:msg,
        signature:pim_private_key.sign(md)
    });
}
function pim_broadcast_to_servers(obj) {
    for(var i in pim_servers) {
        var server = pim_servers[i];
        if(server && server.authenticated) {
            server.sendObject(obj)
        }
    }
}
function pim_create_account() {
    pim_log('Creating new account');
    var keypair = rsa.generateKeyPair({bits: 1024, e: 0x10001});
    pim_account.public_pem = forge.pki.publicKeyToPem(keypair.publicKey);
    pim_account.private_pem = forge.pki.privateKeyToPem(keypair.privateKey);
    pim_private_key = keypair.privateKey;
    pim_auth();
}
function pim_auth() {
    if(!pim_account.public_pem) return;
    for(var i in pim_servers) {
        var server = pim_servers[i];
        if(server && !server.authenticating) {
            server.sendObject({type:'auth',public_pem:pim_account.public_pem});
            server.authenticating = true;
        }
    }
}
function pim_create_connection(public_pem) {
    var conn = new RTCPeerConnection(null);
    conn.oniceconnectionstatechange = function() {
        if(conn.iceConnectionState=='disconnected') {
            pim_log('Disconnected from peer');
            if(conn.conversation_el) { // Remove conversation UI
                conn.conversation_el.parentNode.removeChild(conn.conversation_el);
            }
            pim_connections[public_pem] = null;
        }
    }
    conn.onicecandidate = function(e) {
        if(e.candidate) {
            pim_log('Sending ICE candidate');
            pim_send_peer_msg({type:'ice-candidate',to:public_pem,candidate:e.candidate});
        }
    };
    conn.ondatachannel = function(e) {
        pim_log("Connection success!");
        conn.recvdatachannel = e.channel;
        e.channel.onmessage = function(msg) {
            try { msg = JSON.parse(msg.data);}
            catch(e) { pim_log(e.message); return; }
            switch(msg.type) {
                case 'chat': pim_recv_chat_message(public_pem,true,msg.text); break;
                case 'shared': pim_recv_shared(public_pem,msg.shared);
            }
        };
        pim_switch_conversation(public_pem);
        pim_share_info();
    };
    conn.senddatachannel = conn.createDataChannel('data');
    conn.sendObject = function(obj) {
        if(conn.recvdatachannel) {
            conn.senddatachannel.send(JSON.stringify(obj));
        }
    };
    pim_connections[public_pem] = conn;
    return conn;
}
function pim_connect_to(public_pem) {
    var connection = pim_create_connection(public_pem,true);
    pim_log('Attempting connection with other user');
    connection.onnegotiationneeded = function() {
        connection.createOffer().then(function(offer) {
            pim_log('Local offer created');
            return connection.setLocalDescription(offer);
        }).then(function() {
            pim_log('Sending offer');
            var desc = connection.localDescription;
            pim_send_peer_msg({type:'connect-from',to:public_pem,desc:desc});
        });
    };
}
function pim_connect_from(public_pem,remoteDesc) {
    pim_log('Remote offer received');
    if(pim_connections[public_pem]) { // Already trying to connect to that user
        pim_log('Was already establishing contact');
        var connection = pim_connections[public_pem]
        connection.setRemoteDescription(remoteDesc);
    } else { // Unexpected connection attempt
        // TODO: Should ask if user wants to connect
        var connection = pim_create_connection(public_pem); 
        connection.setRemoteDescription(remoteDesc);
        connection.createAnswer().then(function(answer) {
            pim_log('Local answer created');
            return connection.setLocalDescription(answer);
        }).then(function() {
            var desc = connection.localDescription;
            pim_send_peer_msg({type:'connect-from',to:public_pem,desc:desc});
        });
    }
}
function pim_ice_candidate(public_pem,candidate) {
    if(pim_connections[public_pem]) {
        pim_log('Received ICE candidate');
        var connection = pim_connections[public_pem]
        connection.addIceCandidate(new RTCIceCandidate(candidate));
    } else {
        pim_log('Received ICE candidate for unwanted connection');
    }
}

// Conversation
function pim_switch_conversation(public_pem) {
    var hash = pim_sha1(public_pem);
    var element_id = 'conversation_'+hash;
    var conversation_el = document.getElementById(element_id);
    if(!conversation_el) { // New conversation: create UI
        conversation_el = document.createElement('conversation');
        conversation_el.id = element_id;
        var name_el = document.createElement('name');
        var messages_el = document.createElement('messages');
        var input_el = document.createElement('input');
        input_el.type = 'text';
        input_el.placeholder = 'Type your message here';
        input_el.addEventListener('keydown',function(e) {
            if(e.keyCode==13) { // Code for return
                pim_send_chat_message(public_pem,input_el.value);
                input_el.value = '';
            }
        });
        conversation_el.appendChild(name_el);
        conversation_el.appendChild(messages_el);
        conversation_el.appendChild(input_el);
        document.getElementById('conversations').appendChild(conversation_el); // TODO: remove getElementById

        var connection = pim_connections[public_pem]; // TODO: this should be defined, check it?
        connection.messages_el = messages_el; // Used by pim_recv_chat_message
        connection.name_el = name_el; // Used by pim_recv_shared
        connection.conversation_el = conversation_el;
    }
}
function pim_send_chat_message(public_pem,text) {
    if(text=='') return; // Don't send empty messages
    var conn = pim_connections[public_pem];
    conn.sendObject({type:'chat',text:text});
    // Simulate receiving your own message, simplifies codepath
    pim_recv_chat_message(public_pem,false,text);
}
function pim_recv_chat_message(public_pem,incoming,text) {
    var message_el = document.createElement('message');
    message_el.innerHTML = pim_html_entities(text);
    message_el.className = incoming?'from':'to';
    // TODO: handle urls, images, videos, emojis
    var connection = pim_connections[public_pem];
    connection.messages_el.appendChild(message_el);
    connection.messages_el.scrollBy(0,128);
}

// Personal information
var pim_share_info_tm = null;
function pim_share_info() {
    // We use a unique timeout to avoid sharing information repeatedly
    if(pim_share_info_tm) {
        clearTimeout(pim_share_info_tm);
    }
    pim_share_info_tm = setTimeout(function() {
        pim_log('Sharing info with peers...');
        for(var i in pim_connections) {
            var connection = pim_connections[i];
            if(connection) {
                connection.sendObject({type:'shared',shared:pim_account.shared});
            }
        }
    },1000);
}
function pim_recv_shared(public_pem,shared) {
    pim_account.peers[public_pem] = shared;
    var connection = pim_connections[public_pem];
    connection.name_el.innerHTML = shared.name;
}

// Utilities
function pim_normalize_public_key_pem(public_pem) {
    try {
        return forge.pki.publicKeyToPem(forge.pki.publicKeyFromPem(public_pem));
    } catch(e) { return null; }
}
function pim_html_entities(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function pim_sha1(text) {
    var md = forge.md.sha1.create();
    md.update(text, 'utf8');
    return md.digest().toHex();
}

window.addEventListener('load',function() {
    pim_add_server('ws://127.0.0.1:18765'); // For debugging purposes
    pim_add_server('ws://pim.luciencatonnet.com:18765');
    
    try {
        pim_account = JSON.parse(localStorage.pim_account);
        pim_private_key = forge.pki.privateKeyFromPem(pim_account.privateKeyPem);
    } catch(e) {
        pim_create_account();
    }
    
    document.getElementById('my_public_key').value = pim_account.public_pem;
    document.getElementById('my_name').value = pim_account.shared.name || 'Unknown';

    document.getElementById('connect_button').addEventListener('click',function() {
        var input_el = document.getElementById('public_key_field');
        var public_pem = input_el.value;
        input_el.value = '';
        public_pem = pim_normalize_public_key_pem(public_pem);
        if(public_pem && public_pem!=pim_account.public_pem) {
            if(!pim_connections[public_pem]) {
                pim_connect_to(public_pem);
            }
        }
    });
    document.getElementById('my_name').addEventListener('keyup',function() {
        pim_account.shared.name = this.value;
        pim_share_info();
    });
});
window.addEventListener('unload',function() {
    // Save account state so we can load it back next time
    localStorage.pim_account = JSON.stringify(pim_account);
});
