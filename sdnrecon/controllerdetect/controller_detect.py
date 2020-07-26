from scapy.all import *
import signal
import time
from scipy import stats
import http.client as httpc
import pandas as pd
import os


def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  print("Stopping...")
  exit(0)

def info():
  return "Attempts to fingerprint the network controller."

def usage():
  print("Option      Description")
  print("--------    -----------------------------------------------------------")
  print("  -i", "       Interface to use")
  print("  -l", "       Determine controller based off LLDP traffic")
  print("  -d", "       Dump the contents of the LLDP message")
  print("  -n", "       Do not detect controller based on LLDP content")
  print("  -t", "       Determine controller based northbound interface")
  print("  -p", "       Set ports to scan when -t is specified.")
  print("  -x", "       Define a proxy server to use when --target is specified.")
  print("  -v", "       Show verbose output")
  print("  -e", "       Export result to file .xlsx")


def lldpListen(interface, dumpLLDP, ignoreLLDPContent):
   sniff(iface=interface, prn=lldpListenerCallback(interface, dumpLLDP, ignoreLLDPContent), store=0, stop_filter=lldpStopFilter)

def lldpListenerCallback(interface, dumpLLDP, ignoreLLDPContent):
  def packetHandler(pkt):
    global lldpTimeTrack
    lldpContents = {"ONOS": "ONOS Discovery"}
    #LLDP: 0x88cc, BDDP: 0x8942
    if(pkt.type == 0x88cc):
      lldpTime = int(round(time.time()))
      if(len(lldpTimeTrack) > 0):
        if(lldpTime == lldpTimeTrack[-1]):
          return #This is a simple way to try to detect duplicate LLDP messages being picked up by the sniffer.
      lldpTimeTrack.append(lldpTime)
      if(ignoreLLDPContent == False):
        for c in lldpContents:
          if(lldpContents[c] in str(pkt)):
            sdnpwn.printSuccess("LLDP contents matches " + c)
            exit(0)
      if(dumpLLDP == True):
        print(pkt)
  return packetHandler

def lldpStopFilter(pkt):
  global lldpTimeTrack
  if(len(lldpTimeTrack) >= 6):
    return True
  else:
    return False

def run(params):
  global lldpTimeTrack

  lldpTimeTrack = []

  defaultGuiPorts = {"Floodlight & OpenDayLight": 8080, "OpenDayLight (DLUX Standalone)": 9000, "OpenDayLight (DLUX w/t Karaf) & ONOS": 8181}
  defaultGuiURLs = {"Floodlight": "/ui/index.html", "OpenDayLight (DLUX)": "/dlux/index.html", "OpenDayLight (Hydrogen)": "/index.html", "ONOS": "/onos/ui/login.html"}
  guiIdentifiers = {}
  ofdpIntervals = {"Floodlight": 15, "OpenDayLight (Lithium & Helium)": 5, "OpenDayLight (Hydrogen)": 300, "Pox?": 5, "Ryu?": 1, "Beacon": 15, "ONOS": 3}

  iface = None
  verbose = False
  dumpLLDP = False
  export = False
  

  signal.signal(signal.SIGINT, signal_handler) #Assign the signal handler

  if ("-d" in params):
    dumpLLDP = True
  if ("-n" in params):
    ignoreLLDPContent = True
  else:
    ignoreLLDPContent = False

  if ("-e" in params):
    export = True
  if ("-v" in params):
    verbose = True


  if("-l" in params):
    
    row_m1 = {'Mean time between frames': [], 'Version': [], 'Other': []}
    time,version,other= [],[],[]
    if ("-i" in params):
      try:
        iface = params[params.index("-i")+1]
      except:
        usage()
        exit()

    if(iface is None):
      print("Please specify an interface with -i option")
      return
    print("Collecting 6 LLDP frames. This may take a few minutes...")
    lldpListen(iface, dumpLLDP, ignoreLLDPContent)
    print("Got all LLDP frames. Getting mean time between frames...")
    timeBetweenMessages = []
    timeBetweenMessages.append((lldpTimeTrack[1] - lldpTimeTrack[0]))
    timeBetweenMessages.append((lldpTimeTrack[3] - lldpTimeTrack[2]))
    timeBetweenMessages.append((lldpTimeTrack[5] - lldpTimeTrack[4]))

    meanTimeBetweenMessages = 0
    for i in timeBetweenMessages:
      meanTimeBetweenMessages += i
    meanTimeBetweenMessages = round((meanTimeBetweenMessages/len(timeBetweenMessages)))

    print("Mean time between frames is: " + str(meanTimeBetweenMessages))
    

    matches = 0
    for k in ofdpIntervals:
      if((meanTimeBetweenMessages < (ofdpIntervals[k] + (ofdpIntervals[k]/100*5))) and (meanTimeBetweenMessages > (ofdpIntervals[k] - (ofdpIntervals[k]/100*5)))):
        print("Mean time matches " + k)
        time.append(str(meanTimeBetweenMessages))
        version.append(k)
        other.append("  ")
        matches+=1
    if(matches == 0):
      print("Could not determine controller from LLDP times.")
      time.append("  ")
      version.append("  ")
      other.append("Could not determine controller from LLDP times.")
    if(export==True):
      row_m1['Mean time between frames'] = time
      row_m1['Version'] = version
      row_m1['Other'] = other
      #print(row_m1)
      path = os.getcwd()[0:(int(os.getcwd().find("sdnrecon")))]
      filename=path + "sdnrecon/report/controller_detect/report_baseon_lldp.xlsx"
      df = pd.DataFrame(row_m1)
      df.to_excel(filename, index = False, header=True)
      print("[##] Result saved to " + "/sdnrecon/report/controller_detect/report_baseon_lldp.xlsx")

  elif("-t" in params):
    #Test using a URL
    row_m2 = {'Gui URL': [], 'Status': [], 'Version': [], 'Other': []}
    gui,status,version,other=[],[],[],[]
    try:
      target = params[params.index("-t")+1]
    except:
      usage()
      exit()

    
    if ("-p" in params):
      ports = []
      try:
        ports_input = params[params.index("-p")+1]
      except:
        usage()
        exit()
      if ("," in ports_input):
        p = ports_input.split(",")
        for x in p:
          ports.append(int(x))
      elif ("-" in ports_input):
        p = ports_input.split("-")
        for x in p:
          ports.append(int(x))
      else:
          ports.append(int(ports_input))
    else:
      ports = []
      for p in defaultGuiPorts:
        ports.append(defaultGuiPorts[p])
    print("Enumerating ports...")

    list_target = []	
    if ("," in target):
      list_target = target.split(",")
    else:
      list_target.append(target)

    for t in list_target:	
      print("Testing visibility of northbound interface on host " + str(t))
      for p in ports:
        try:
          conn = httpc.HTTPConnection(t, int(p), timeout=10)
          if( "-x" in params):
            try:
              conn.setTunnel(params[params.index("-x")+1])
            except:
              usage()
              exit()
          req = conn.request("GET", "/")
          print("Made HTTP connection to " + str(t) + " on port " + str(p))
          for c in defaultGuiPorts:
            if(defaultGuiPorts[c] == p):
              print("Port used by " + str(c) + " for GUI interface")
          print("Testing GUI URLs for port " + str(p))
          for u in defaultGuiURLs:
            try:
              conn = httpc.HTTPConnection(t, int(p))
              conn.request("GET", defaultGuiURLs[u])
              res = conn.getresponse()
              reqStatus = res.status
              gui.append("http://"+ str(t) + ":"+str(p)+ defaultGuiURLs[u])
              status.append(str(reqStatus))
              if(reqStatus >= 200 and reqStatus < 400):
                print("Got " + str(reqStatus) + " for " + defaultGuiURLs[u])
                print("URL associated with " + u + " GUI interface")
                version.append(u)
                other.append("  ")
              else:
                version.append("  ")
                other.append("  ")
                if(verbose == True):
                  print("Got " + str(reqStatus) + " for URL " + str(u))
            except:
              if(verbose == True):
                gui.append("http://"+ str(t) + ":"+str(p)+ defaultGuiURLs[u])
                status.append("  ")
                version.append("  ")
                other.append("Error testing URL")
                #print("Error testing URL: " + str(e))
        except Exception as e:
          if(verbose == True):
            print("No connection to " + str(t) + " on port " + str(p))
            gui.append("http://"+str(t)+":"+str(p))
            status.append("  ")
            version.append("  ")
            other.append("No connection")
            #print(str(e))

    if(export==True):
      row_m2['Gui URL'] = gui
      row_m2['Status'] = status
      row_m2['Version'] = version
      row_m2['Other'] = other
      path = os.getcwd()[0:(int(os.getcwd().find("sdnrecon")))]
      filename= path + "sdnrecon/report/controller_detect/report_baseon_northbound.xlsx"
      df = pd.DataFrame(row_m2)
      df.to_excel(filename, index = False, header=True)
      print("[##] Result saved to " + "/sdnrecon/report/controller_detect/report_baseon_northbound.xlsx")
  else:
    print("No detection method given. Exiting.")
    print(info())
    print(usage())
    return
  

def main():
  params = sys.argv
  filter(None, params)
  params.pop(0)
  run(params)

if __name__ == '__main__':
  main()


