from scapy.all import *
import pygsheets


# name of spreadsheet
spreadsheet_name = "PoopCounter"

# Google Sheets business
# authentication for pygsheets
gc = pygsheets.authorize(service_file='client_secret.json')

# Open spreadsheet and then workseet
sh = gc.open(spreadsheet_name)
wks = sh.sheet1

# Dash Button Business
print "started scanning for ARP"
timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
def arp_display(pkt):
  if pkt.haslayer(ARP):
    if pkt[ARP].op == 1: #who-has (request)
      # if pkt[ARP].psrc == '0.0.0.0': # ARP Probe
      if pkt[ARP].hwsrc == '74:c2:46:91:f6:18':
        # print "ARP Probe from: " + pkt[ARP].hwsrc
        print "Pushed Gatorade, it's got electrolytes at: " + timestamp
        # Update a cell with value
        wks.update_cell('A1', "Hi Lindsey")
        wks.update_cell('B1', timestamp)


print sniff(prn=arp_display, filter="arp", store=0, count=0)
