var rsa = forge.pki.rsa;

var pim_start_time = Date.now();
var pim_log = function(str){console.log((Date.now()-pim_start_time)/1000+':\t'+str)}
var pim_account = {
    shared:{}, // This is what gets shared with peers
    peers:{} // This contains information about peers
};
var pim_private_key;

function pim_create_account() {
    pim_log('Creating new account');
    var keypair = rsa.generateKeyPair({bits: 1024, e: 0x10001});
    pim_account.public_pem = forge.pki.publicKeyToPem(keypair.publicKey);
    pim_account.private_pem = forge.pki.privateKeyToPem(keypair.privateKey);
    pim_private_key = keypair.privateKey;
}
function pim_peer(public_pem) {
    public_pem = pim_normalize_public_pem(public_pem);
    if(!pim_account.peers[public_pem]) {
        pim_account.peers[public_pem] = {};
    }
    return pim_account.peers[public_pem];
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
        pim_peer_broadcast({type:'shared',shared:pim_account.shared});
    },1000);
}
Connection.prototype.handlers.shared = function(conn,msg) {
    pim_peer(conn.public_pem).shared = msg.shared;
    var conversation = pim_conversations[conn.public_pem];
    if(conversation) {
        conversation.shared_update(msg.shared);
    }
}
Connection.prototype.handlers.chat = function(conn,msg) {
    var conv = pim_start_conversation(conn.public_pem);
    conv.onmessage(msg.text,true);
}

// Utilities
function pim_normalize_public_pem(public_pem) {
    try {
        return forge.pki.publicKeyToPem(forge.pki.publicKeyFromPem(public_pem));
    } catch(e) { return null; }
}
function pim_html_entities(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

window.addEventListener('load',function() {
    try { // Try to restore account from local storage
        pim_account = JSON.parse(localStorage.pim_account);
        pim_private_key = forge.pki.privateKeyFromPem(pim_account.private_pem);
    } catch(e) { // Otherwise create a new one
        pim_create_account();
    }

    // Some static addresses as kickstarter
    pim_connection('ws://127.0.0.1:18765'); // For debugging purposes
    pim_connection('ws://pim.luciencatonnet.com:18765');
    pim_rtc_conf.iceServers.push({url:'stun:pim.luciencatonnet.com'});
    
    document.getElementById('my_public_key').value = pim_account.public_pem;
    document.getElementById('my_name').value = pim_account.shared.name || 'Unknown';
    var known_peers_el = document.getElementById('known_peers');
    for(var public_pem in pim_account.peers) {
        var known_peer_el = document.createElement('input');
        known_peer_el.type = 'button';
        known_peer_el.value = pim_peer_shared(public_pem).name || '...';
        known_peer_el.onclick = function() {
            pim_start_conversation(public_pem);
        };
        known_peers_el.appendChild(known_peer_el);
    }

    document.getElementById('reset_button').addEventListener('click',function() {
        // Remove all peer information
        pim_account = {
            public_pem:pim_account.public_pem,
            private_pem:pim_account.private_pem,
            shared:{},peers:{}
        };
        location.reload();
    });
    document.getElementById('connect_button').addEventListener('click',function() {
        var input_el = document.getElementById('public_key_field');
        pim_start_conversation(input_el.value);
        input_el.value = '';
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
