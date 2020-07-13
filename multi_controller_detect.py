from scapy.all import *
import signal
import netifaces
import sys
from scapy.contrib.openflow import _ofp_header


def usage():
        print("  Option    Description                   Required")
        print("--------------------------------------------------")
        print("  -i", "       Give an or more interfaces      Yes")
        
def info():
	print("Detect and show informations's multi controller based on OpenFlow packets")

def main():
	opf_version = {"1":"OpenFlow 1.0", "2":"OpenFlow 1.1","3":"OpenFlow 1.2","4":"OpenFlow 1.3","5":"OpenFlow 1.4","6":"OpenFlow 1.5"}
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

	xIP = []
	controller = 0
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

	if controller != 0:
		print("Detected " + str(controller) + " controller")
	else:
		print("No controller detected")


if __name__ == '__main__':
	main()


