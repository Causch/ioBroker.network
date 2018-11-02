/**
 *
 * network adapter
 *
 * network device scanner and presence detector
 *
 */

/* jshint -W097 */// jshint strict:false
/*jslint node: true */
'use strict';

const utils =    require(__dirname + '/lib/utils'); // Get common adapter utils
let {spawn}  = require('child_process');
const adapter = new utils.Adapter('network');

// refresh timer for full scan
let refreshTimer = null;
// presence timer
let presenceTimer = null;
// wake on lan repeat timer
let wolTimer = null;

// packet count for precence
let packet_count = 5;
let wol_interval = 60;


let macdb={
    'wol': {},
    'detect': {},
    'ip': {},
    'presence': {}
};


// is called when adapter shuts down - callback has to be called under any circumstances!
adapter.on('unload', function (callback) {
    try {
        if (refreshTimer) clearInterval(refreshTimer);
        if (presenceTimer) clearInterval(presenceTimer);
        if (wolTimer) clearInterval(wolTimer);
        callback();
    } catch (e) {
        callback();
    }
});
// maybe i get a good usage for this later...
adapter.on('message', function (obj) {
    if (typeof obj === 'object' && obj.message) {
        if (obj.command === 'send') {
            // e.g. send email or pushover or whatever
            console.log('send command');

            // Send response in callback if required
            if (obj.callback) adapter.sendTo(obj.from, obj.command, 'Message received', obj.callback);
        }
    }
});

// is called when databases are connected and adapter received configuration.
// start here!
adapter.on('ready', function () {
    main();
});



adapter.on('stateChange', function(id, state) {
    let tmp=id.split('.');
    let state_id=tmp.pop();
    if (state==null) { /** deleted state... */ return; }
    switch (state_id) {
        case 'wol':
            if (state.ack==false) {
                switch (state.val) {
                    case 1:
                        let mac=tmp.pop();
                        adapter.log.info('One time WOL msg to '+mac);
                        adapter.setState(id,0,true);
                        network_wol(mac); // send one paket out
                        break;
                    case 2:
                        adapter.setState(id,2,true); // confirm it
                        break;
                    case 0:
                        adapter.setState(id,0,true); // confirm it
                        break;
                }
            }
            else {
                let mac=tmp.pop();
                macdb.wol[mac]=state.val;
            }
            break;
        case 'detect':
            if (state.ack==false) {
                if (state.val==true) {
                    let mac=tmp.pop();
                    adapter.log.info('detection enabled for mac '+mac);
                    adapter.setState(id,true,true);
                    //wol_direct(mac); // send one paket out
                }
                else {
                    adapter.setState(id,false,true); // confirm it
                }
            }
            else {
                let mac=tmp.pop();
                macdb.detect[mac]=state.val;
            }
            break;
        case 'ip':
            if (state.ack==true) {
                let mac=tmp.pop();
                macdb.ip[mac]=state.val;
            }
            break;
        case 'presence':
            if (state.ack==true) {
                let mac=tmp.pop();
                macdb.presence[mac]=state.val;
            }
            break;
        default:
            break;
    }
});
/**
 * helper function to delay multiple calls
 * especially neccessary when using arp utils,
 * as packets can arrive in different processes
 **/
function delayed_serialized_call(maclist, f_call, t_o, ...restArgs) {

    if (maclist.length==0) return;
    let mac=maclist.pop();

    let call_args=restArgs;
    call_args.unshift(mac);

    f_call.apply(mac);

    call_args=restArgs;
    call_args.unshift(t_o);
    call_args.unshift(delayed_serialized_call);
    setTimeout.apply(null,call_args);
}
/**
 * arping an IP
 * there are 2 different versions of arping, depending on distribution
 * one supports arping a MAC, one not, so we use the common version over IP
 *
 * @param mac     mac address
 * @param cb      the callback routine ( string mac, boolean presence)
 **/
function network_arping(mac, cb, retry ) {
    if (!macdb.ip.hasOwnProperty(mac)) return; // no sense if we have no ip

    let ip=macdb.ip[mac];
    let cl=[ ip, '-f', '-c',packet_count];

    let arping = spawn("arping", cl);
    let buffer = '';
    let errstream = '';

    arping.stdout.on('data', function (data) {
        buffer += data;
    });
    arping.stderr.on('data', function (data) {
        errstream += data;
    });
    adapter.log.debug("arping "+mac);
    arping.on('close', function (code) {
        switch(code) {
            case 0:
                cb(mac,true);
                break;
            case 1:
                if (retry==0 && macdb.presence.hasOwnProperty(mac) && macdb.presence[mac]==0) {
                    // we retry immendiatelly one time, if the last presence was 0
                    setTimeout(network_arping,100,1);
                }
                else {
                    cb(mac,false);
                }
                break;
            default:
                adapter.log.error("Error running arping " + code + " " + errstream);
                break;
        }
    });
}
/**
 *
 * send out wake on lan package to an mac address
 *
 **/
function network_wol(mac) {
    let cl=[mac];
    let ether = spawn("ether-wake", cl);
    let buffer = '';
    let errstream = '';

    ether.stdout.on('data', function (data) {
        buffer += data;
    });
    ether.stderr.on('data', function (data) {
        errstream += data;
    });

    ether.on('close', function (code) {
        if (code !== 0) {
            adapter.log.error("Error running ether-wake " + code + " " + errstream);
            return;
        }
        else {
            adapter.log.info("Wol sent to "+mac);
        }
    });
}


/**
 * arpscan
 * scan localnet for ip/macs and store them in DB
 *
 * @param cb  callback (object list) where is in form list[mac]=ip
 **/
function network_arpscan(cb) {
    let cl=["--localnet"];
    let arp = spawn("arp-scan", cl);
    let buffer = '';
    let errstream = '';

    arp.stdout.on('data', function (data) {
        buffer += data;
    });
    arp.stderr.on('data', function (data) {
        errstream += data;
    });

    arp.on('close', function (code) {
        if (code !== 0) {
            adapter.log.error("Error running arp " + code + " " + errstream);
            return;
        }
        adapter.log.debug(cl+":"+buffer);
        let s=buffer.split("\n");
        let list={};
        for (let a in s) {
            if (s.hasOwnProperty(a)) {
                let line=s[a];
                let temp=line.split("\t");
                if (temp[0].match(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
                    list[temp[1]]=temp[0];
                }
            }
        }
        cb(list);
    });
}
/**
 * loop wake on lan
 *
 **/
function loop_wol() {
    let maclist=[];
    adapter.log.info("Starting wol");
    let db=macdb.wol;
    for (let mac in db) {
        if (db.hasOwnProperty(mac)) {
            switch (db[mac]) {
                case 1: // one time things
                    break;
                case 2:
                    maclist.push(mac);
                    break;
                default:
                    break;

            }
            if (db[mac]>0) {
                adapter.log.info("macdb wol "+mac+" active");
            }
            else {
                adapter.log.info("macdb wol "+mac+" inactive");
            }
        }

    }
    delayed_serialized_call(maclist,network_wol,200);
}

/**
 * presence
 * checks the presence of the entries in the DB
 */
function loop_presence() {
    adapter.log.info("Starting presence scan");
    let db=macdb.detect;
    let maclist={};
    for (let mac in db) {
        if (db.hasOwnProperty(mac)) {
            if (db.detect[mac]==true) {
                adapter.log.info("macdb presence "+mac+" active");
                if (macdb.ip.hasOwnProperty(mac)) {
                    maclist[mac]=macdb.ip[mac];
                }
            }
            else {
                adapter.log.info("macdb presence "+mac+" inactive");
            }
        }
    }
    delayed_serialized_call(maclist,network_arping,500, function(mac, presence) {
        if (!macdb.presence.hasOwnProperty(mac)) {
            macdb.presence[mac]=null;
        }
        if (macdb.presence[mac]!==presence) {
            adapter.setState("hosts.arp."+mac+".presence", presence, true);
        }
    }, 0);
}
/**
 * scanning loop
 **/
function loop_scan() {

    adapter.log.info("Starting full arp scan");
    network_arpscan( function(list) {
        for (let i in list) {
            if (!list.hasOwnProperty(i)) continue;
            let mac=i;
            let ip=list[i];
            adapter.log.debug("FullScan: "+mac);

            adapter.setObjectNotExists('hosts.arp.'+mac, {
                type: 'channel',
                common: {
                    name: 'host '+mac,
                    type: 'string',
                    role: 'indicator'
                },
                native: {}
            });
            adapter.setObjectNotExists('hosts.arp.'+mac+'.mac', {
                type: 'state',
                common: {
                    name: 'MAC addr',
                    type: 'string',
                    role: 'indicator'
                },
                native: {}
            });
            adapter.setObjectNotExists('hosts.arp.'+mac+'.ip', {
                type: 'state',
                common: {
                    name: 'IP Addr',
                    type: 'string',
                    role: 'indicator'
                },
                native: {}
            });
            adapter.setObjectNotExists('hosts.arp.'+mac+'.presence', {
                type: 'state',
                common: {
                    name: 'Presence indicator',
                    type: 'number',
                    role: 'indicator'
                },
                native: {}
            });
            adapter.setObjectNotExists('hosts.arp.'+mac+'.detect', {
                type: 'state',
                common: {
                    name: 'Presence indicator on/off',
                    type: 'boolean',
                    role: 'indicator'
                },
                native: {}
            });
            adapter.setObjectNotExists('hosts.arp.'+mac+'.wol', {
                type: 'state',
                common: {
                    name: 'Wake on LAN',
                    type: 'number',
                    role: 'indicator'
                },
                native: {}
            });
            adapter.setState("hosts.arp."+mac+".ip", { val: ip, ack: true });
            adapter.setState("hosts.arp."+mac+".mac",{ val: mac, ack: true });
            adapter.setState("hosts.arp."+mac+".presence", { val: 1, ack: true });
            //adapter.setState("hosts.arp."+mac+".wol", { val: 0, ack: true });
            //adapter.setState("hosts.arp."+mac+".detect", { val: true, ack: true });
        }
    });
}


function main() {
    adapter.setObjectNotExists('hosts.arp', {
        type: 'device',
        common: {
            name: 'host list',
            type: 'array',
            role: 'indicator'
        },
        native: {}
    });

    adapter.subscribeStates('*');



    let as=adapter.config.arpscan_time||60;
    let ap=adapter.config.arping_time||1;
    packet_count=adapter.config.arping_cnt||5;
    wol_interval=adapter.config.wol_interval||60;


    adapter.log.info("full scan: "+ap+" minutes, presence: "+as+" seconds");
    adapter.log.info("arping paket cnt: "+packet_count);
    adapter.log.info("WOL interval"+wol_interval);


    let w = spawn("which", ["arp-scan"]);
    w.on('close',function(code) {
        if (code==0) {
            refreshTimer = setInterval(loop_scan, as*60000);
            loop_scan();
        }
        else {
            adapter.log.info("arp-scan not installed on this system");
        }
    });
    w = spawn("which", ["arping"]);
    w.on('close', function(code) {
        if (code==0) {
            presenceTimer=setInterval(loop_presence, ap*1000);
        }
        else {
            adapter.log.info("arping not installed on this system");
        }
    });

    w = spawn("which", ["ether-wake"]);
    w.on('close',function(code) {
        if (code==0) {
            wolTimer=setInterval(loop_wol, wol_interval*1000);
            loop_wol();
        }
        else {
            adapter.log.info("ehter-wake not installed on this system");
        }
    });
}
