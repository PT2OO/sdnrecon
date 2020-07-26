from scapy.all import *
import netifaces
import time
from scipy import stats
from scapy.contrib.openflow import _ofp_header
from os import path



def info():
  print("Determines if a network is likely to be an SDN by observing Round-Trip Times (RTT) for traffic.")
  
def usage():
  print("Option    Description                                                                             Required")
  print("-------  ---------------------------------------------------------------------------------------  ---------")         
  print("-m", "      Protocol to use (ICMP | ARP) OR Detect with OpenFlow (OPF)                               Yes")
  print("-if","     Inteface to capture packet, (OPF required)                                               Yes") 
  print("-t", "      IP of local host to send traffic to (Defaults to default gateway)                        No")
  print("-i", "      Interval at which packets are sent (Default 1)                                           No")
  print("-c", "      Number of packets to send. More packets means better detection accuracy.(Default 10)     No")
  print("-v", "      Enable verbose output                                                                    No")
  



def run(params): 
  global verbose
  opf_version = {"1":"OpenFlow 1.0", "2":"OpenFlow 1.1","3":"OpenFlow 1.2","4":"OpenFlow 1.3","5":"OpenFlow 1.4","6":"OpenFlow 1.5"}

  verbose = False
  testMethod = ""
  dstIP = ""
  count = 10
  interval = 1
  interface = []

  if ("-m" not in params):
    info()
    usage()
    exit()
  else:
    try:
      testMethod = (params[params.index("-m")+1]).lower()
    except:
      usage()
      exit()    

  if("-t" in params):
    dstIP = params[params.index("-t")+1]
  if("-i" in params):
    interval = float(params[params.index("-i")+1])
  if("-c" in params):
    count = int(params[params.index("-c")+1])
  if("-v" in params):
    verbose = True
  
  if(testMethod == "opf"):
    if ("-if" in params):
      interfaces = params[params.index("-if")+1]
    else:
      print("Give interface to use detect with OpenFlow protocol with -if")
      exit()
    
    if ("," in interfaces):
      ifaces=interfaces.split(";")
    else:
      ifaces=[interfaces]
    for i in ifaces:
      packets = sniff(iface=i, timeout=10)
      check=0
      for pkt in packets:
        if check==1:
          break
        try:
          if (str(pkt[TCP].version) in opf_version):
            print("SDN detected on " + i )
            print(opf_version[str(pkt[TCP].version)])
            check=1
            try:
              print("Controller information:")
              print("        IP: " + str(pkt[IP].src))
              print("        MAC: " + str(pkt[Ether].src))
              print("        Port: " + str(pkt[TCP].sport))
            except:
              exit()
        except:
            continue
    print("SDN not detected")
    exit()
  #print(testMethod + " " + dstIP + " " + str(interval) + " " + str(count) + " " + str(verbose))

  if(dstIP == ""):
    print("No target given, using default gateway")
    try:
      dstIP = netifaces.gateways()['default'][netifaces.AF_INET][0]
    except:
      print("Could not determine gateway address. Please specify a target using the -t option.")
      return
    print("Default gateway detected as " + dstIP)
  
  try:
    if(testForSDN(testMethod, dstIP, count, interval)):
      print("SDN detected!")
    else:
      print("SDN not detected")
  except PermissionError as e:
    print("Needs root!")
        
def testForSDN(testMethod, dstIP, count, interval):
  global verbose
  rtt = []
  sentMS = 0
  
  if(testMethod == ""):
    print("Give method to detect with -m <icmp/arp/opf>")
  elif(testMethod == "icmp"):
    print("Testing with ICMP...")
    icmp = (IP(dst=dstIP)/ICMP())
    for i in range(0,count):
      sentMS = int(round(time.time() * 1000))
      resp = sr1(icmp, verbose=0)
      rtt.append((int(round(time.time() * 1000))) - sentMS)
      time.sleep(interval)
      
  elif(testMethod == "arp"):
    print("Testing with ARP...")
    for i in range(0,count):
      sentMS = int(round(time.time() * 1000))
      resp = arping(dstIP, verbose=0)
      rtt.append((int(round(time.time() * 1000))) - sentMS)
      time.sleep(interval)
  
  initValue = rtt[0]
  rtt.pop(0)
  #Perform T-Test to check if first latency value is significantly different from others in our sample
  res = stats.ttest_1samp(rtt, initValue)
  if(verbose == True):
    print("Initial RTT: " + str(initValue))
    print("RTTs for other traffic: " + str(rtt))
    print("Calculated p-value for inital RTT is " + str(res[1]))
  if(res[1] < .05 and all(i < initValue for i in rtt)): #If the p-value is less that 5% we can say that initValue is significant
    return True
  else:
    return False


  


def main():
  if (len(sys.argv) > 1):
    if (sys.argv[1] == "-h"):
       usage()
    else:
       params = sys.argv
       filter(None, params)
       params.pop(0)
       run(params)
  else:
    params = sys.argv
    filter(None, params)
    params.pop(0)
    run(params)




if __name__ == '__main__':
  main()
