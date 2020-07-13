import ipcalc
import sys
import signal
from scapy.all import *

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  print("Stopping...")
  exit(0)


def usage():
        print("  Option    Description                Required")
        print("-----------------------------------------------")
        print("  -t", "       IP or Network to scan      Yes")
        print("  -to", "      Timeout (Default 3)        No")

def arp_scan(IPs, time_out):
	clients = []
	for ip in IPs:
		arp = ARP(pdst=ip)
		ether = Ether(dst="ff:ff:ff:ff:ff:ff")
		packet = ether/arp
		result = srp(packet, timeout= time_out, verbose=0)[0]
		for sent, received in result:
			clients.append({'ip': received.psrc, 'mac': received.hwsrc})
	return clients

def run(params):
        input = ""
        timeout = 3
        IPs= []
        result = []

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
        if ("-to" in params):
                try:
                        timeout = int(params[params.index("-to")+1])
                except:
                        usage()
                        exit()
 
        if "/" in input:
                for x in ipcalc.Network(input):
                        IPs.append(str(x))
        else:
                IPs.append(input)
        print("Performing ARP scan... ")
        result = arp_scan(IPs, timeout)
        if (len(result) == 0):
                print("No available devices")
        else:
                print("Available devices in the network:")
                print("IP" + " "*18+"MAC")
                for x in result:
                        print("{:16}    {}".format(x['ip'], x['mac']))


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


