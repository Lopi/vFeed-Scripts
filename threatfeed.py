#!/usr/bin/env python
from lib.core.methods import *
from lib.core.update import Update
import os
import glob
import json
import numpy as np

# Edit tech to represent your org's technology
# It's important to be as specific as possible
# For example, Cisco Adaptive Security Appliance
tech = ['Wordpress', 'Cisco Adaptive Security Appliance', 'Oracle MySQL']
org_new_vulns = []
nessus_scans = []
nmap_scans = []
index_to_del = []
json_data = []

print "Updating the vFeed database from your scripts"
Update().update()

os.popen('python ./vfeedcli.py --stats get_latest|grep -oE "[A-Z]{3}-[0-9]{4}-[0-9]{3,10}" > new_cves.txt')

cves = [line.rstrip('\n') for line in open('new_cves.txt')]

for cve in cves:
	info = CveInfo(cve).get_cve()
	if info is not "[]":
		ExportJson(cve).json_dump()

exports = glob.glob("export/*.json")

for e in exports:
	with open(e) as json_file:
	    json_data.append(json.load(json_file))

for t in tech:
	for data in json_data:
		for stuff in data['Information']['CVE']:
			if t in stuff['summary']:
				org_new_vulns.append(data)

for t in tech:
	for index, vuln in enumerate(org_new_vulns):
		for things in vuln['Scanners']['Nessus']:
			if t in things['name']:
				nessus_scans.append(vuln)

for t in tech:
	for index, vuln in enumerate(org_new_vulns):
		for things in vuln['Scanners']['Nmap']:
			if t in things['name']:
				nmap_scans.append(vuln)

unique_nessus_scans=list(np.unique(np.array(nessus_scans)))
unique_nmap_scans=list(np.unique(np.array(nmap_scans)))

with open('vulns.txt', 'w') as out:
	json.dump(org_new_vulns, out, sort_keys=True, indent=4)

with open('nessus_scans.txt', 'w') as out:
	json.dump(unique_nessus_scans, out, sort_keys=True, indent=4)

with open('nmap_scans.txt', 'w') as out:
	json.dump(unique_nmap_scans, out, sort_keys=True, indent=4)
