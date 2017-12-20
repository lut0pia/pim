var pim_rtc_conf = {iceServers:[]};

function Connection(id) {
    var conn = this;
    this.state = 'waiting';
    this.authenticated = false;
    this.public_pem = pim_normalize_public_pem(id);
    if(this.public_pem) {
        this.type = 'peer';
    } else { // TODO: check it's a valid url?
        this.type = 'server';
        this.url = id; 
    }
    this.connect();
    this.retry_count = 0;
    this.retry_iterator = 0;

    // Create UI element
    document.getElementById('connections')
    .appendChild(this.connection_el = document.createElement('connection'));
}
Connection.prototype.connect = function() {
    this.state = 'waiting';
    switch(this.type) {
        case 'peer':
            this.reset_rtc();
            var rtc = this.rtc;
            this.rtc.onnegotiationneeded = function() {
                pim_log('Creating offer');
                this.createOffer().then(function(offer) {
                    pim_log('Local offer created');
                    return rtc.setLocalDescription(offer);
                }).then(function() {
                    rtc.conn.rtc_signal.desc = rtc.localDescription;
                    rtc.conn.conditional_send_signal();
                }).catch(pim_log);
            }
            break;
        case 'server':
            this.type = 'server';
            this.websocket = new WebSocket(this.url);
            this.websocket.conn = this;
            this.websocket.onopen = function() {
                pim_log('Connected to: '+this.conn.url);
                this.conn.state = 'ready';
                this.conn.send({type:'auth',public_pem:pim_account.public_pem});
            }
            this.websocket.onclose = function() {
                this.conn.state = 'disconnected';
                pim_log('Disconnected from: '+this.conn.url);
            }
            this.websocket.onerror = function() {
                pim_log('Could not connect to: '+this.conn.url);
            }
            this.websocket.onmessage = function(e) {
                this.conn.recv(e.data);
            }
            break;
    }
}
Connection.prototype.reset_rtc = function() {
    this.state = 'waiting';
    var rtc = this.rtc = new RTCPeerConnection(pim_rtc_conf);
    this.rtc_send = this.rtc.createDataChannel('data');
    this.rtc.conn = this;
    this.rtc.oniceconnectionstatechange = function() {
        if(this.iceConnectionState=='disconnected') {
            this.conn.state = 'disconnected';
            pim_log('Disconnected from peer');
        }
    }
    this.rtc.onicecandidate = function(e) {
        this.conn.rtc_signal.ice_candidates.push(e.candidate);
        this.conn.conditional_send_signal();
    }
    this.rtc.ondatachannel = function(e) {
        pim_log("Connection success!");
        this.conn.rtc_recv = e.channel;
        this.conn.rtc_recv.conn = this.conn;
        e.channel.onmessage = function(e) {
            this.conn.recv(e.data);
        }
        this.conn.state = 'ready';
        pim_share_info(); // TODO: this probably shouldn't be here
    }
    this.rtc_signal = {
        ice_candidates:[]
    };
}
Connection.prototype.conditional_send_signal = function() {
    if(this.rtc_signal.desc && this.rtc_signal.ice_candidates.indexOf(null)>0) {
        pim_log('Sending '+this.rtc_signal.desc.type+' signal');
        this.send_relayed({type:'signal',signal:this.rtc_signal});
    }
}
Connection.prototype.friendly_name = function() {
    switch(this.type) {
        case 'server': return this.url;
        case 'peer':
            try {
                return pim_account.peers[this.public_pem].shared.name;
            } catch(e) {}
    }
    return '';
}
Connection.prototype.send = function(obj) {
    if(this.state=='ready') {
        var obj_str = JSON.stringify(obj);
        switch(this.type) {
            case 'peer': return this.rtc_send.send(obj_str);
            case 'server': return this.websocket.send(obj_str);
        }
    } else {
        // TODO: put in queue
    }
}
Connection.prototype.recv = function(msg) {
    try { msg = JSON.parse(msg); }
    catch(e) { pim_log(e.message); return; }
    var handler = this.handlers[msg.type];
    if(handler) {
        handler(this,msg);
    } else {
        pim_log('Unhandled message type: '+msg.type)
    }
}
Connection.prototype.send_relayed = function(msg) {
    msg.from = pim_account.public_pem;
    msg.to = this.public_pem;
    var md = forge.md.sha1.create();
    md.update(JSON.stringify(msg),'utf8');
    // TODO: only broadcast to small reliable subset for efficiency
    pim_server_broadcast({
        type:'relay-msg',
        msg:msg,
        signature:pim_private_key.sign(md)
    });
}
Connection.prototype.handlers = {}
Connection.prototype.handlers['prove-auth'] = function(conn,msg) {
    // Server has sent us an encrypted message we have to decypher to prove our identity
    var decrypted = pim_private_key.decrypt(msg.encrypted,'RSAES-PKCS1-V1_5');
    if(decrypted.substr(0,13)=='----PROOF----') { // Check header so we don't accidentally decipher anything for a server
        conn.send({type:'auth-proof',decrypted:decrypted});
        pim_log('Sending proof to server: '+conn.url);
    } else { // Server is corrupt or buggy?
        conn.close();
        pim_log('Server is corrupt: '+conn.url);
    }
}
Connection.prototype.handlers.authenticated = function(conn,msg) {
    // Server confirmed that we're not authenticated
    conn.authenticated = true;
    pim_log('Authenticated to: '+conn.url);
}
var pim_recvd_relayed_msgs = {}; // Hashes of relayed messages received
Connection.prototype.handlers['relayed-msg'] = function(conn,msg) {
    var md = forge.md.sha1.create();
    md.update(JSON.stringify(msg.msg), 'utf8');
    var hash = md.digest().toHex();
    if(!pim_recvd_relayed_msgs[hash]) { // Ensure we don't receive the same message twice
        pim_recvd_relayed_msgs[hash] = true;
        var public_key = forge.pki.publicKeyFromPem(msg.msg.from);
        if(public_key.verify(md.digest().bytes(), msg.signature)) { // The message comes from who it says it does
            pim_recv_relayed_msg(conn,msg.msg);
        } else {
            pim_log('Received falsified peer message from: '+conn.url);
        }
    }
}

function pim_recv_relayed_msg(server,msg) {
    if(msg.type!='signal') {
        return; // Could we have any other type of relayed message?
    }
    var conn = pim_connection(msg.from);
    if(conn.state=='ready') {
        return; // Don't fix it if it ain't broke
    }
    conn.retry_iterator = -1; // Delay retry
    var signal = msg.signal;
    var remote_desc = signal.desc;
    pim_log('Remote '+remote_desc.type+' received');
    
    if(remote_desc.type=='answer') { // It's an answer to earlier offer
        conn.rtc.setRemoteDescription(remote_desc);
    } else { // It's an offer
        // TODO: Should ask if user wants to connect in a nice way
        conn.reset_rtc();
        conn.rtc.setRemoteDescription(remote_desc).then(function() {
            return conn.rtc.createAnswer();
        }).then(function(answer) {
            pim_log('Local answer created');
            return conn.rtc.setLocalDescription(answer);
        }).then(function() {
            signal.ice_candidates.forEach(function(candidate) {
                if(candidate) {
                    conn.rtc.addIceCandidate(new RTCIceCandidate(candidate));
                }
            });
            conn.rtc_signal.desc = conn.rtc.localDescription;
            conn.conditional_send_signal();
        });
    }
}

var pim_connections = {};
function pim_connection(id) {
    // TODO: try to normalize id to avoid duplicates
    // Get or create connection to peer/server
    var connection = pim_connections[id];
    if(!connection) {
        connection = new Connection(id);
        pim_connections[id] = connection;
    }
    return connection;
}
function pim_broadcast(obj,cond) {
    for(var i in pim_connections) {
        var connection = pim_connections[i];
        if(!cond || cond(connection)) {
            connection.send(obj);
        }
    }
}
function pim_peer_broadcast(obj) {
    pim_broadcast(obj,function(conn) {
        return conn.type=='peer';
    });
}
function pim_server_broadcast(obj) {
    pim_broadcast(obj,function(conn) {
        return conn.type=='server';
    });
}

// Automatic reconnect interval
setInterval(function() {
    for(var i in pim_connections) {
        var conn = pim_connections[i];
        if(conn.state!='ready') {
            if(++conn.retry_iterator >= Math.pow(2,conn.retry_count)) {
                conn.retry_count = Math.min(conn.retry_count+1,8);
                conn.retry_iterator = 0;
                conn.connect();
            }
        } else {
            conn.retry_count = 0;
            conn.retry_iterator = 0;
        }
        conn.connection_el.setAttribute('type',conn.type);
        conn.connection_el.setAttribute('state',conn.state);
        conn.connection_el.innerText = conn.friendly_name();
    }
},2000);
