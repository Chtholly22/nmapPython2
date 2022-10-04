#!/usr/bin/python3

import nmap
import xml.etree.cElementTree as ET
import pyfiglet 
  
#BANNER

result = pyfiglet.figlet_format("Caza Putas 3K") 
print(result) 
print("_" * 70)
ip=input("[+] IP Objetivo ==> ")
export =input("[+] Nombre para el xml? ")
print("_" * 70)


nm = nmap.PortScanner()
puertos_abiertos="-p "
results = nm.scan(hosts=ip,arguments="-sT -n -Pn -T4")
count=0

#imprime resultados

print("\nHost : %s" % ip)
print("State : %s" % nm[ip].state())
for proto in nm[ip].all_protocols():
	print("Protocol : %s" % proto)
	print()
	lport = nm[ip][proto].keys()
	sorted(lport)
	for port in lport:
		print ("port : %s\tstate : %s" % (port, nm[ip][proto][port]["state"]))
		if count==0:
			puertos_abiertos=puertos_abiertos+str(port)
			count=1
		else:
			puertos_abiertos=puertos_abiertos+","+str(port)

print("\nPuertos abiertos Localizados: "+ puertos_abiertos +" "+str(ip))

result = nm.get_nmap_last_output()

fo = open(export, "wb")
fo.write(result)
fo.close()

