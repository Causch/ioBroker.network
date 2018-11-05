![Logo](admin/network.png)
# ioBroker.network
=================

This adapter is a network scanner and presence tester using arp-scan and arping. Your should have your iobroker installation running
on a linux machine.

# prerequisite

you need arp-scan and arping installed on your iobroker machine

## Centos
```
sudo yum -y install arp-scan arping net-tools
```

## Debian

```
sudo apt-get install arp-scan arping etherwake
```

# DB

The adapter creates objects in form of:
- network.0.hosts.arp // device
  - 00:11:22:33:44:55 // channel
    - ip              assigned IP adress
    - mac             mac address
    - presence        presence of device ( true / false )
    - detect          presence detection enabled ( true / false writable)
    - dns_name        current dns name entry
    - vendor          mac vendor
    - wol             wake on lan ( 0 = off, 1 = send one packet, 2 = interval sending )


## Installation Steps

1. go to your admin panel
2. select "install from custom url" / "Installieren aus eigener URL"
3. select tab "CUSTOM"
4. enter https://github.com/Causch/ioBroker.network.git
5. click install

# Changelog

### 0.0.1 - 2018.11.02

- initial release

### 0.0.2 - 2018.11.02
- remove -x from arp-scan options
- added packet count for presence scan ( default is 5 ). 

## License
The MIT License (MIT)

Copyright (c) 2018 Fikret Causevic <causch@gmx.de>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
