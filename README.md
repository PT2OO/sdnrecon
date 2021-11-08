# Sdnrecon

Sdnrecon is a reconnaissance framework for SDN network, has the capability of automation.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

What things you need to install the software and how to install them

```
Python 3.6 or later and Python 2.7
Sdnrecon requires the following software...
  From pip3:
    - ipcalc
    - netifaces
    - numpy
    - pandas
    - pyshark
    - python-openflow
    - scapy
    - scipy
    - tabulate
    - XlsxWriter
    - xlrd
  From github:
    - python-openflow-legacy (Older version of Kytos OpenFlow library)
```

### Installing

First download sdnrecon using git
```
git clone https://github.com/phutr4n/sdnrecon.git
```

Then,

```
pip3 install ipcalc,netifaces,numpy,pandas,pyshark,python-openflow,scapy,scipy,tabulate,XlsxWriter,xlrd

cd sdnrecon/sdnpwn
mkdir lib
cd lib
git clone https://github.com/smythtech/python-openflow-legacy
cd python-openflow-legacy
chmod +x setup.py
sudo python3 setup.py install

```


## Functions

Sdnrecon includes 6 modules
  - SDN Network Detector: Determine if the SDN network exists based on Round-trip Time (RTT), OpenFlow packets.
  - Host Discovery tools: Find out the IP, MAC of hosts that exist in the network by using arpscan, pingscan method.
  - Controller Detector: Detect controller type based on Northbound Interface and time interval between LLDP packets.
  - Port Scanner: Find open port, including tcp and udp port. Phantom-host port scanner uses phantom host to scan port bypass firewalls, access control policies and         any rule-flow table.
  - Rule Reconstructor: Detect flow rules and load balancing structures existing in the SDN network.
  - AutoRecon Utility: Run above modules automatically in a specific sequence, which helps to use results from previous modules for the input of next modules.

## Usage

```
cd sdnrecon
python3 main.py

               __       _______                        
     .-----.--|  .-----|   _   .-----.----.-----.-----.
     |__ --|  _  |     |.  l   |  -__|  __|  _  |     |
     |_____|_____|__|__|.  _   |_____|____|_____|__|__|
                       |:  |   |                       
                       |::.|:. |                       
                       `--- ---'                       
      SDNRecon [*] is a reconnaissance framework. 
               [*] targets SDN Network.
               [*] has the capability of automation.
     
      
      [++] Choose a number:
            
            [01] SDN Network Detector
            [02] Host Discovery tools
            [03] Controller Detector 
            [04] Port Scanner 
            [05] Rule Reconstructor
            [06] AutoRecon Utility

    
sdnrecon> 

```
## Built With
- [sdnmap] (https://github.com/SDNMap/sdnmap.git)__ SDNMap
- [sdnpwn] (https://github.com/smythtech/sdnpwn.git)__ sdnpwn
