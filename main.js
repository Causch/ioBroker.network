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
let packet_count = 5;

// is called when adapter shuts down - callback has to be called under any circumstances!
adapter.on('unload', function (callback) {
    try {
        if (refreshTimer) clearInterval(refreshTimer);
        if (presenceTimer) clearInterval(presenceTimer);
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

/**
 * arping an IP
 * there are 2 different versions of arping, depending on distribution
 * one supports arping a MAC, one not, so we use the common version over IP
 *
 * @param maclist a list of mac addresses
 * @param cb      the callback routine ( string mac, boolean presence)
 **/
function arping_ip(maclist, cb ) {
    if (maclist.length>0) {
        let list=maclist;
        let mac=list.pop();
        adapter.log.debug("Start arping: "+mac+ '(hosts.arp.'+mac+'.ip)');
        adapter.getState('hosts.arp.'+mac+'.ip', function(err,ip) {
            if (err!=null) {
                adapter.log.error("Error while reading state "+mac+": "+err);
            }
            else {
                let cl=[ ip.val, '-f', '-c',packet_count];

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
                            cb(mac,false);
                            break;
                        default:
                            adapter.log.error("Error running arping " + code + " " + errstream);
                            break;
                    }

                });
            }
            setTimeout(arping_ip,100,list,cb);
        });
    }
    else {
        adapter.log.debug("Maclist empty");
    }
}
/**
 * arpscan
 * scan localnet for ip/macs and store them in DB
 *
 * @param cb  callback (object list) where is in form list[mac]=ip
 **/
function arpscan(cb) {
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
 * presence
 * checks the presence of the entries in the DB
 *
 *
 */
function presence() {
    adapter.log.info("Starting presence scan");
    adapter.getChannelsOf(function(err2,hostlist) {
        let maclist=[];
        for (let i in hostlist) {
            if (hostlist.hasOwnProperty(i)) {
                let tmp=hostlist[i]._id.split(".");
                let mac=tmp.pop();
                maclist.push(mac);
            }
        }
        adapter.log.debug("presence mac list: "+JSON.stringify(maclist));
        arping_ip( maclist, function(mac,responded) {
            if (responded) {
                adapter.getState("hosts.arp."+mac+".presence", function(err,val) {
                    if (err!=null) {

                    }
                    else {
                        if (val.val==0) {
                            adapter.setState("hosts.arp."+mac+".presence", { val: 1, ack: true });
                            adapter.log.info(mac+" present");
                        }
                    }
                });
            }
            else {
                adapter.getState("hosts.arp."+mac+".presence",function(err,val) {
                    if (err!=null) {

                    }
                    else {
                        if (val.val==1) {
                            adapter.setState("hosts.arp."+mac+".presence", { val: 0, ack: true });
                            adapter.log.info(mac+" not present");
                        }
                    }
                });
            }
         });
    });
}
/*
function presence_arp_scan() {
    adapter.log.debug("Starting presence scan");
    adapter.getChannelsOf(function(err2,hostlist) {
        let maclist={};
        for (let i in hostlist) {
            if (hostlist.hasOwnProperty(i)) {
                let tmp=hostlist[i]._id.split(".");
                let mac=tmp.pop();
                maclist[mac]=1;
            }
        }
        adapter.log.debug("List of macs: "+JSON.stringify(maclist));

        arping_ip( function(list,maclist) {

            let temp={};
            for (let i in maclist) {
                if (maclist.hasOwnProperty(i)) {
                    if (!list.hasOwnProperty(i)) { temp[i]=1; }
                }
            }
            for (let i in list) {
                if (list.hasOwnProperty(i)) {
                  adapter.setState("hosts.arp."+i+".presence", { val: 1, ack: true });
                  adapter.log.info(i+" present");
                }
            }
            for (let i in temp) {
                if (temp.hasOwnProperty(i)) {
                  adapter.setState("hosts.arp."+i+".presence", { val: 0, ack: true });
                  adapter.log.info(i+" not present");
                }
            }
         },maclist);
    });

}*/

function refresh() {
    adapter.log.info("Starting full arp scan");
    arpscan( function(list) {
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
                    name: 'Presence indicator',
                    type: 'number',
                    role: 'indicator'
                },
                native: {}
            });
            adapter.setState("hosts.arp."+mac+".ip", { val: ip, ack: true });
            adapter.setState("hosts.arp."+mac+".mac",{ val: mac, ack: true });
            adapter.setState("hosts.arp."+mac+".presence", { val: 1, ack: true });
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

    let as=adapter.config.arpscan_time||60;
    let ap=adapter.config.arping_time||1;
    packet_count=adapter.config.arping_cnt||5;

    refreshTimer = setInterval(refresh, as*60000);
    presenceTimer=setInterval(presence, ap*1000);
    adapter.log.info("full scan: "+ap+" minutes, presence: "+as+" seconds");
    refresh();
    setTimeout(presence, 3000);
}
