import ipcalc
import sys
import signal
from scapy.all import *
import random
import pandas as pd
import os

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  print("Stopping...")
  exit(0)
def info():
	print("Perform ping scan")

def usage():
        print("  Option    Description                  Required")
        print("---------------------------------------  --------")
        print("  -t", "       IP or Network to scan        Yes")
        print("  -to", "      Timeout (Default 1)          No")
        print("  -e", "       Export result to file .xlsx  No")



def ping_scan(IPs, time_out):
	alive_host = []
	for ip in IPs:
		icmp = IP(dst=ip)/ICMP()
		
		resp = sr1(icmp, timeout=time_out, verbose=0)
		if resp != None:
			alive_host.append(ip)
	return alive_host

def run(params):
	input = ""
	timeout = 0.5
	IPs= []
	result = []
	export = False
	scan_hosts=[]
	active_hosts=[]
	lines=[]

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
	if ("-e" in params):
		export = True

	if "/" in input:
		for x in ipcalc.Network(input):
			IPs.append(str(x))
	else:
		IPs.append(input)
	#print("Scan hosts ")
	for ip in IPs:
		scan_hosts.append(ip)
	result = ping_scan(IPs, timeout)
	if (len(result) == 0):
		print("No reachable host")
		active_hosts.append("None")
	else:
		print("Reachable hosts: ")
		for x in result:
			active_hosts.append(x)
			print(x)
	if export==True:
		row = {'Scan hosts': [], 'Available hosts': []}
		if (len(scan_hosts) > len(active_hosts)):
			x = len(scan_hosts) - len(active_hosts)
			for i in range(0,x):
				active_hosts.append(" ")       
		row['Scan hosts'] = scan_hosts
		row['Available hosts'] = active_hosts
		path = os.getcwd()[0:(int(os.getcwd().find("sdnrecon")))]
		filename=path + "sdnrecon/report/host_discovery/report_ping_scan.xlsx"
		df = pd.DataFrame(row)
		df.to_excel(filename, index = False, header=True)
		print("[##] Result saved to " + "/sdnrecon/report/host_discovery/report_ping_scan.xlsx")
		

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























