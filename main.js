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

let vendor_list = require(__dirname+'/vendors.js');


let net_config={
    packet_count:   5,
    presence_retry: 3,
    wol: 60,
    presence: 60,
    refresh:  3600,
    check_finished: -1,
    iphone_pkg: 10,
    ether_wake_cmd: null,
};

let net_timers ={
    check_wait: null
};
let net_intervals= {
    presence: null,
    wol: null,
    refresh: null
};

let macdb={
    'wol': {},
    'detect': {},
    'ip': {},
    'presence': {}
};


// is called when adapter shuts down - callback has to be called under any circumstances!
adapter.on('unload', function (callback) {
    try {
        for (let i in net_timers) {
            if (net_timers.hasOwnProperty(i)) {
                clearTimeout(net_timers[i]);
            }
        }
        for (let i in net_intervals) {
            if (net_intervals.hasOwnProperty(i)) {
                clearInterval(net_intervals[i]);
            }
        }
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



adapter.on('stateChange', stateChange);


function stateChange(id, state) {
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
}
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

    f_call.apply(null,call_args);

    call_args.shift();
    call_args.unshift(t_o);
    call_args.unshift(f_call);
    call_args.unshift(maclist);
    call_args.unshift(t_o);
    call_args.unshift(delayed_serialized_call);

    setTimeout.apply(null,call_args);
}

function iphone_wakeup(ip, retry) {
    var dgram = require('dgram');
    var client = dgram.createSocket('udp4');
    client.send('', 0, 0, 5353, ip, function(err, bytes) {
        if (err) throw err;
        adapter.log.info('UDP message sent to '+ ip+ ' '+bytes+" bytes");
        client.close();
        if (retry>0) {
            setTimeout(iphone_wakeup,10, ip, retry-1);
        }
    });
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
    adapter.log.info("arping on "+mac);
    if (!macdb.ip.hasOwnProperty(mac)) return; // no sense if we have no ip

    let ip=macdb.ip[mac];
    let cl=[ ip, '-f', '-c',net_config.packet_count];

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
                if (retry>0 && macdb.presence.hasOwnProperty(mac) && macdb.presence[mac]==true) {
                    // we retry immendiatelly one time, if the last presence was 0
                    adapter.log.info("rescan of "+mac);
                    setTimeout(network_arping,100,mac,cb,retry-1);
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
    adapter.log.info("Etherwakte on "+mac);
    let cl=[mac];
    let ether = spawn(net_config.ether_wake_cmd, cl);
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
            adapter.log.info("Wol sent to "+mac+" "+buffer);
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
    //adapter.log.info("Starting wol");
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
        }

    }
    delayed_serialized_call(maclist,network_wol,200);
}

/**
 * presence
 * checks the presence of the entries in the DB
 */
function loop_presence() {
    //adapter.log.info("Starting presence scan");
    let db=macdb.detect;
    let maclist=[];
    for (let mac in db) {
        if (db.hasOwnProperty(mac)) {
            if (db[mac]==true) {
//                adapter.log.info("macdb presence "+mac+" active");
                if (macdb.ip.hasOwnProperty(mac)) {
                    maclist.push(mac);
                    let ip=macdb.ip[mac];
                    let tmac=mac.replace(/\:/g,'').substr(0,6);
                    if (vendor_list.vendors.hasOwnProperty(tmac) && vendor_list.vendors[tmac].tolower.substr(0,5)=='apple') {
                        iphone_wakeup(ip, net_config.iphone_pkg); // send wakup udp to iphone
                    }
                }
            }
            else {
//                adapter.log.info("macdb presence "+mac+" inactive");
            }
        }
    }

    delayed_serialized_call(maclist,network_arping,500, function(mac, presence) {
        if (!macdb.presence.hasOwnProperty(mac)) {
            macdb.presence[mac]=null;
        }
        if (macdb.presence[mac]!==presence) {
            adapter.setState("hosts.arp."+mac+".presence", presence, true);
            if (presence) {
                adapter.log.warn(mac+" is now present");
            }
            else {
                adapter.log.warn(mac+" is now not present");
            }
        }
    }, net_config.presence_retry);
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
                    role: 'indicator',
                    write: false
                },
                native: {}
            });
            adapter.setObjectNotExists('hosts.arp.'+mac+'.vendor', {
                type: 'state',
                common: {
                    name: 'Vendor',
                    type: 'string',
                    role: 'indicator',
                    write: false
                },
                native: {}
            });
            adapter.setObjectNotExists('hosts.arp.'+mac+'.ip', {
                type: 'state',
                common: {
                    name: 'IP Addr',
                    type: 'string',
                    role: 'indicator',
                    write: false
                },
                native: {}
            });
            adapter.setObjectNotExists('hosts.arp.'+mac+'.presence', {
                type: 'state',
                common: {
                    name: 'Presence indicator',
                    type: 'boolean',
                    role: 'indicator',
                    write: false,
                    def: false
                },
                native: {}
            });
            adapter.setObjectNotExists('hosts.arp.'+mac+'.detect', {
                type: 'state',
                common: {
                    name: 'Detect presence on/off',
                    type: 'boolean',
                    role: 'indicator',
                    def:  false
                },
                native: {}
            });
            adapter.setObjectNotExists('hosts.arp.'+mac+'.wol', {
                type: 'state',
                common: {
                    name: 'Wake on LAN',
                    type: 'number',
                    role: 'indicator',
                    def:  0,
                    states: {
                        0: "off",
                        1: "one time msg",
                        2: "repeated msgs"
                    }
                },
                native: {}
            });


            adapter.setObjectNotExists("hosts.arp."+mac+".dns_name", {
                type: 'state',
                common: {
                    name: "DNS name",
                    type: "array",
                    role: 'indicator',
                    def: "",
                    write: false
                }
            });
            adapter.setState("hosts.arp."+mac+".ip", { val: ip, ack: true });
            adapter.setState("hosts.arp."+mac+".mac",{ val: mac, ack: true });

            let ven=mac.replace(/\:/ig,'').substr(0,6).toUpperCase();
            adapter.log.info("Vendor ID:"+ven);
            if (vendor_list.vendors.hasOwnProperty(ven)) {
                adapter.setState("hosts.arp."+mac+".vendor",{ val: vendor_list.vendors[ven], ack: true });
            }
            else {
                adapter.setState("hosts.arp."+mac+".vendor",{ val: ven, ack: true });
            }


            adapter.setState("hosts.arp."+mac+".presence", { val: 1, ack: true });


            var dns = require('dns');
            dns.reverse(ip, function (err, domains) {
              if (err) {
                adapter.log.warn("Error searching for reverse entry");
                adapter.setState("hosts.arp."+mac+".dns_name",{ val: [ip], ack: true});
              }
              else {
                adapter.setState("hosts.arp."+mac+".dns_name", { val: domains, ack: true});
                for (let i in domains) {
                    if (domains.hasOwnProperty(i)) {
                        let dn=domains[i];
                        let fp='';
                        let dp='';
                        if (dn.indexOf(".")>=0) {
                            fp=dn.substr(0,dn.indexOf("."));
                            dp=dn.substring(dn.indexOf(".")+1,dn.length);
                            dn=dp+'.'+fp;
                        }

                        adapter.setObjectNotExists("hosts.dns."+dn, {
                            type: 'state',
                            common: {
                                name: "Host "+domains[i],
                                type: "string",
                                role: 'indicator',
                                def: "",
                                write: false
                            }
                        });
                        adapter.setObjectNotExists("hosts.dns."+dn+".mac", {
                            type: 'state',
                            common: {
                                name: "MAC address",
                                type: "string",
                                role: 'indicator',
                                def: "",
                                write: false
                            }
                        });
                        adapter.setObjectNotExists("hosts.dns."+dn+".ip", {
                            type: 'state',
                            common: {
                                name: "MAC address",
                                type: "string",
                                role: 'indicator',
                                def: "",
                                write: false
                            }
                        });
                        adapter.setState("hosts.dns."+dn+".ip",ip,true);
                        adapter.setState("hosts.dns."+dn+".mac",mac,true);
                    }
                }
              }
            });
        }
    });
}


function config_check() {
    net_config.check_finished=-1;
    adapter.getStatesOf(function(err,dta) {
        if (err!==null) {
            adapter.log.error("Error in rebuild_internal");
       }
       else {
            net_config.check_finished=dta.length;
            for (let i in dta) {
                if (dta.hasOwnProperty(i)) {
                    let obj=dta[i];
                    let id=obj._id;
                    let check=id.split('.');
                    let name=check.pop();
                    switch (check[3]) {
                        case 'arp':
                            switch (name) {
                                case 'ip':
                                    if (obj.common.type!="string" || obj.common.write!=false) {
                                        adapter.setObject(obj._id, { type: "state", native: obj.native, common: { name: obj.common.name, type: "string", write: false, def: '', role: 'indicator' }});
                                        adapter.log.info("ip redefinition: "+check[4]);
                                    }
                                    break;
                                case 'mac':
                                    if (obj.common.type!="string" || obj.common.write!=false) {
                                        adapter.setObject(obj._id, { type: "state", native: obj.native, common: { name: obj.common.name, type: "string", write: false, def: '', role: 'indicator' }});
                                        adapter.log.info("mac redefinition: "+check[4]);
                                    }
                                    break;
                                case 'presence':
                                    if (obj.common.type!="boolean" || obj.common.write!=false) {
                                        adapter.setObject(obj._id, { type: "state", native: obj.native, common: { name: obj.common.name, type: "boolean", write: false, def: false, role: 'indicator' }});
                                        adapter.log.info("presence redefinition: "+check[4]);
                                    }
                                    break;
                                case 'detect':
                                    if (obj.common.type!="boolean" || obj.common.write!=true) {
                                        adapter.setObject(obj._id, { type: "state", native: obj.native, common: { name: obj.common.name, type: "boolean", write: true, def: false, role: 'indicator' }});
                                        adapter.log.info("detect redefinition: "+check[4]);
                                    }
                                    break;
                                case 'vendor':
                                    if (obj.common.type!="string" || obj.common.write!=false) {
                                        adapter.setObject(obj._id, { type: "state", native: obj.native, common: { name: obj.common.name, type: "string", write: false, def: '', role: 'indicator' }});
                                        adapter.log.info("vendor redefinition: "+check[4]);
                                    }
                                    break;
                                case 'wol':
                                    if (obj.common.type!="number" || obj.common.write!=true || obj.common.states.constructor!==Array ) {
                                        adapter.setObject(obj._id, { type: "state", native: obj.native, common: { name: obj.common.name, type: "boolean", write: true, def: '', role: 'indicator', states: {
                                            0: "off",
                                            1: "one time msg",
                                            2: "repeated msgs"
                                        } }});
                                        adapter.log.info("wol redefinition: "+check[4]);
                                    }
                                    break;
                                case 'dns_name':
                                    if (obj.common.type!="array" || obj.common.write!=false) {
                                        adapter.setObject(obj._id, { type: "state", native: obj.native, common: { name: obj.common.name, type: "array", write: false, def: '', role: 'indicator' }});
                                    }
                                    adapter.log.info("dns_name redefinition: "+check[4]);
                                    break;
                            }
                            break;
                        case 'dns':
                            switch (name) {
                                case 'ip':
                                    break;
                                case 'mac':
                                    break;
                                case 'presence':
                                    break;
                                case 'detect':
                                    break;
                                case 'wol':
                                    break;
                                case 'dns_name':
                                    break;
                            }
                            break;
                    }
                    adapter.log.info("#checks: "+net_config.check_finished);
                    net_config.check_finished--;
                }
            }
        }
    });

}

function wait_for_check() {
    if (net_config.check_finished==0) {
        clearTimeout(net_timers.check_wait);
        adapter.log.info("Checks finished, starting");
        rebuild_internal();
        let w = spawn("which", ["arp-scan"]);
        w.on('close',function(code) {
            if (code==0) {
                adapter.log.info("Refresh: "+net_config.refresh*60000);
                net_intervals.refresh = setInterval(loop_scan, net_config.refresh*60000);
                loop_scan();
            }
            else {
                adapter.log.warn("arp-scan not installed on this system");
            }
        });
        w = spawn("which", ["arping"]);
        w.on('close', function(code) {
            if (code==0) {
                net_intervals.presence=setInterval(loop_presence, net_config.presence*1000);
            }
            else {
                adapter.log.warn("arping not installed on this system");
            }
        });

        w = spawn("which", ["ether-wake"]);
        w.on('close',function(code) {
            if (code==0) {
                net_config.ether_wake_cmd='ether-wake';
                net_intervals.wol=setInterval(loop_wol, net_config.wol*1000);
                loop_wol();
            }
        });
        w = spawn("which", ["etherwake"]);
        w.on('close',function(code) {
            if (code==0) {
                net_intervals.wol=setInterval(loop_wol, net_config.wol*1000);
                net_config.ether_wake_cmd='etherwake';
                loop_wol();
            }
        });
        return;
    }
    else {
        adapter.log.info("Checks #"+net_config.check_finished);
    }
    clearTimeout(net_timers.check_wait);
    net_timers.check_wait=setTimeout(wait_for_check,1000);
}


function rebuild_internal() {
    adapter.getStatesOf(function(err,dta) {
       if (err!==null) {
            adapter.log.error("Error in rebuild_internal");
       }
       else {
        for (let i in dta) {
            if (dta.hasOwnProperty(i)) {
                let o=dta[i];
                adapter.getState(o._id,function(errx,val) {
                    if (errx==null) {
                        if (val==null) {
                            let tmp=o._id.split(".");
                            let st=tmp.pop();
                            switch (st) {
                                case 'wol':
                                    adapter.setState(o._id,0,true);
                                    break;
                                case 'detect':
                                    adapter.setState(o._id,false,true);
                                    break;
                            }
                        }
                        else {
                            stateChange(o._id,{ val: val.val, ack: true});
                        }
                    }
                });
            }
        }
       }
    });
}

function main() {
    adapter.setObjectNotExists('hosts.arp', {
        type: 'device',
        common: {
            name: 'MAC addresses',
            type: 'array',
            role: 'indicator'
        },
        native: {}
    });
    adapter.setObjectNotExists('hosts.dns', {
        type: 'device',
        common: {
            name: 'DNS Names',
            type: 'array',
            role: 'indicator'
        },
        native: {}
    });

    config_check();
    wait_for_check();

    net_config.refresh =(adapter.config.arpscan_time||60);
    net_config.presence=(adapter.config.arping_time||1);
    net_config.packet_count=adapter.config.arping_cnt||5;
    net_config.wol=(adapter.config.wol_interval||60);
    net_config.iphone_pkg=adapter.config.iphone_pkg;
    adapter.log.info("full scan: "+net_config.refresh+" minutes");
    adapter.log.info("presence: "+net_config.presence+" seconds");
    adapter.log.info("arping paket cnt: "+net_config.packet_count);
    adapter.log.info("WOL interval: "+net_config.wol+" seconds");

    adapter.subscribeStates('*');

}
