from scapy.all import *
import signal
import netifaces
import sys
from scapy.contrib.openflow import _ofp_header
import pandas as pd
import os


def usage():
        print("  Option    Description                   Required")
        print("--------------------------------------------------")
        print("  -i", "       Give an or more interfaces      Yes")
        print("  -e", "       Export result to file .txt      No")
        
def info():
	print("Detect and show informations's multi controller based on OpenFlow packets")

def main():
	opf_version = {"1":"OpenFlow 1.0", "2":"OpenFlow 1.1","3":"OpenFlow 1.2","4":"OpenFlow 1.3","5":"OpenFlow 1.4","6":"OpenFlow 1.5"}
	export=False
	params = sys.argv
	if len(params) < 1:
		info()
		usage()
		exit()
	try:
		ifaces = params[params.index("-i")+1]
	except:
		info()
		usage()
		exit()

	if ("," in ifaces):
		interfaces = ifaces.split(",")
	else:
		interfaces = []
		interfaces.append(ifaces)
	if ("-e" in params):
		export=True
	xIP = []
	controller = 0
	row = {'IP Controller': [], 'MAC Controller': [], 'Port': [], 'MAC Switch': [], 'Port Switch': [], 'OpenFlow Version': []}
	ip,mac,port,sw_mac,sw_port,version=[],[],[],[],[],[]
	for i in interfaces:
		try:
			print(">>Sniffing on " + i)
			packets = sniff(iface=i, timeout=20)
		except:
			print("Sniff error, exiting...")
			exit()
		check=0
		for pkt in packets:
			if check == 1:
				break
			if ("OFPTPacketOut" in str(pkt.summary())):
				controller = controller + 1
				check=1
				print("----C" +str(controller)+"----")
				print("      Controller IP: " + str(pkt[IP].src))
				print("      Controller MAC: " + str(pkt[Ether].src))
				print("      Controller Port: " + str(pkt[TCP].sport))
				print("      Switch MAC: " + str(pkt[Ether].dst))
				print("      Switch Port: " + str(pkt[TCP].dport))
				print(opf_version[str(pkt[TCP].version)])
				ip.append(str(pkt[IP].src))
				mac.append(str(pkt[Ether].src))
				port.append(str(pkt[TCP].sport))
				sw_mac.append(str(pkt[Ether].dst))
				sw_port.append(str(pkt[TCP].dport))
				version.append(opf_version[str(pkt[TCP].version)])

	if controller != 0:
		print("Detected " + str(controller) + " controller")
	else:
		ip.append("No controller detected")
		mac.append(" ")
		port.append(" ")
		sw_mac.append(" ")
		sw_port.append(" ")
		version.append(" ")
		print("No controller detected")

	if export == True:
		row['IP Controller'] = ip
		row['MAC Controller'] = mac
		row['Port'] = port
		row['MAC Switch'] = sw_mac
		row['Port Switch'] = sw_port
		row['OpenFlow Version'] = version
		path = os.getcwd()[0:(int(os.getcwd().find("sdnrecon")))]
		filename=path + "sdnrecon/report/controller_detect/report_multi_controller_detect.xlsx"
		df = pd.DataFrame(row)
		df.to_excel(filename, index = False, header=True)
		print("[##] Result saved to " + "/sdnrecon/report/controller_detect/report_multi_controller_detect.xlsx")


if __name__ == '__main__':
	main()


