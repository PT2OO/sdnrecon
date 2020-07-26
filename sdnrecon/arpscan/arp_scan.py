import ipcalc
import sys
import signal
from scapy.all import *
import pandas as pd
import os

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  print("Stopping...")
  exit(0)


def usage():
        print("  Option    Description                 Required")
        print("--------------------------------------  ---------")
        print("  -t", "       IP or Network to scan        Yes")
        print("  -to", "      Timeout (Default 3)          No")
        print("  -e", "       Export result to file .xlsx  No")

def arp_scan(IPs, time_out, interface):
	clients = []
	for ip in IPs:
		arp = ARP(pdst=ip)
		ether = Ether(dst="ff:ff:ff:ff:ff:ff")
		packet = ether/arp
		if (interface == ""):
			result = srp(packet, timeout= time_out, verbose=0)[0]
		else:
			result = srp(packet, iface=interface, timeout= time_out, verbose=0)[0]
		for sent, received in result:
			clients.append({'ip': received.psrc, 'mac': received.hwsrc})
	return clients

def run(params):
        input = ""
        interface = ""
        timeout = 3
        IPs= []
        result = []
        export = False
        scan_hosts=[]
        valid_hosts_ip=[]
        valid_hosts_mac=[]
        lines = []

        signal.signal(signal.SIGINT, signal_handler) #Assign the signal handler


        if ("-t" in params):
                try:
                        input = params[params.index("-t")+1]
                except:
                        usage()
                        exit()
        else:
                print("Give IP or Network to scan ")
                usage()
                exit()
        if ("-i" in params):
                try:
                        interface = params[params.index("-i")+1]
                except:
                        usage()
                        exit() 
        if ("-to" in params):
                try:
                        timeout = int(params[params.index("-to")+1])
                except:
                        usage()
                        exit()
        if ("-e" in params):
                export = True
 
        if "/" in input:
                for x in ipcalc.Network(input):
                        IPs.append(str(x))
        else:
                IPs.append(input)
        for ip in IPs:
                scan_hosts.append(ip)
        print("Performing ARP scan... ")
        result = arp_scan(IPs, timeout, interface)
        if (len(result) == 0):
                print("No available devices")
                valid_hosts_ip.append(x["None"])
                valid_hosts_mac.append(x["None"])
        else:
                print("Available devices in the network:")
                print("IP" + " "*18+"MAC")
                for x in result:
                        print("{:16}    {}".format(x['ip'], x['mac']))
                        valid_hosts_ip.append(x['ip'])
                        valid_hosts_mac.append(x['mac'])
        if export==True:
                row = {'Scan hosts': [], 'IP available hosts': [], 'MAC available hosts': []}
                if (len(scan_hosts) > len(valid_hosts_ip)):
                        x = len(scan_hosts) - len(valid_hosts_ip)
                        for i in range(0,x):
                                valid_hosts_ip.append(" ")
                                valid_hosts_mac.append(" ")                   
                row['Scan hosts'] = scan_hosts
                row['IP available hosts'] = valid_hosts_ip
                row['MAC available hosts'] = valid_hosts_mac
                path = os.getcwd()[0:(int(os.getcwd().find("sdnrecon")))]
                filename=path + "sdnrecon/report/host_discovery/report_arp_scan.xlsx"
                df = pd.DataFrame(row)
                df.to_excel(filename, index = False, header=True)
                print("[##] Result saved to " + "/sdnrecon/report/host_discovery/report_arp_scan.xlsx")


def main():
        if (len(sys.argv) < 1):
                usage()
        else:
                params = sys.argv
                filter(None, params)
                params.pop(0)
                run(params)


if __name__ == '__main__':
        main()


