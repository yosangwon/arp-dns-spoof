# Installation(on Debian-based Linux Distribution)

## Install [Scapy](http://www.secdev.org/projects/scapy/doc/installation.html)
```
% sudo apt-get install tcpdump graphviz imagemagick python-gnuplot python-crypto python-pyx
% pip install scapy
```

## Install [python-NetfilterQueue](https://github.com/fqrouter/python-netfilterqueue)
```
% sudo apt-get install build-essential python-dev libnetfilter-queue-dev
% git clone https://github.com/fqrouter/python-netfilterqueue.git
% cd python-netfilterqueue
% python setup.py install
```

## ...and clone this repository!
```
% git clone https://github.com/devleoper/arp-dns-spoof.git
```

# Usage

## ARP poisoning.
```
% sudo python arp_poison.py -v <victim IP Address> -r <router IP Address>
```

## DNS spoofing.
```
% sudo python dns_packet_spoof.py
```

# References
 * [Reliable DNS spoofing with Python: Scapy + Nfqueue](http://danmcinerney.org/reliable-dns-spoofing-with-python-scapy-nfqueue/)
 * [ARP poisoning with Python](http://danmcinerney.org/arp-poisoning-with-python-2/)
