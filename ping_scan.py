import ipcalc
import sys
import signal
from scapy.all import *

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  print("Stopping...")
  exit(0)
def info():
	print("Perform ping scan")

def usage():
        print("  Option    Description                Required")
        print("-----------------------------------------------")
        print("  -t", "       IP or Network to scan      Yes")
        print("  -to", "      Timeout (Default 1)        No")



def ping_scan(IPs, time_out):
	alive_host = []
	for ip in IPs:
		icmp = IP(dst=ip)/ICMP()
		#print(ip)
		resp = sr1(icmp, timeout=time_out, verbose=0)
		if resp != None:
			alive_host.append(ip)
	return alive_host

def run(params):
	input = ""
	timeout = 1
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
		info()
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
	print("Performing ICMP scan... ")
	result = ping_scan(IPs, timeout)
	if (len(result) == 0):
		print("No reachable host")
	else:
		print("Reachable host: ")
		for x in result:
			print(x)

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
