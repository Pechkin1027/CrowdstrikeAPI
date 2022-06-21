#Basic Python libraries to import
import os
import sys
import json
import csv
import sys

#Logging configuration, suppresses some requests library logging
import logging
logging.basicConfig(filename=__file__.strip('.py') + '.log', level=logging.DEBUG, format='%(asctime)s %(message)s')
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.info("INFO: Program starting")

#Custom  crowdstrike.py module, make sure it's located in the same folder as this script
import crowdstrike as cs
import servicenow

#Import credentials and instance-specific information from the config.py file, make sure it's in the same folder as this script
import config
CROWDSTRIKE_USERNAME = config.CROWDSTRIKE_USERNAME
CROWDSTRIKE_API_KEY = config.CROWDSTRIKE_API_KEY
CROWDSTRIKE_URL = config.CROWDSTRIKE_URL

SERVICENOW_USERNAME = config.SERVICENOW_USERNAME
SERVICENOW_PASSWORD = config.SERVICENOW_PASSWORD
SERVICENOW_URL = config.SERVICENOW_URL


def create_differences_csv(crowdstrike_devices, servicenow_devices):
	"""
	This is the brunt of the logic for the application.
	High level: Check and make a list of the differences between Crowdstrike and ServiceNow

	1. There is a list of Crowdstrike devices that is iterated through.
	2. First, Crowdstrike will look to see if there is a MAC match in ServiceNow.
	3. If there is a MAC match, a comparison of ServiceNow and Crowdstrike IPs and Hostnames will be made. If either 
	is different, they will be noted and written to a CSV.
	4. If a MAC match is found, and both ServiceNow and Crowdstrike IPs and Hostnames match, it will also be written to the CSV
	5. If a MAC match is not found between ServiceNow and Crowdstrike, a host name lookup will commence. 
	6. If there is a hostname match, then that will be written to the CSV.
	7. If there is no MAC or hostname match, that will be written to the CSV. 

	A few things to note
	1. I replaced the "-" with ":" in the Crowdstrike MAC addresses.
	2. Comparison are case-insensitive as noted by ".upper()"
	3. Eme asked that if there is a "-" in the host name and that is the only difference to make a  note of that
	You will see that I remove the dashes in some of the logic below to make those comparisons.

	TO DO:
	Check with Eme if he wants me to remove "-" in hostnames. I am already comparing them by value, not upper/lower case.
	"""

	#This section creates a new dictionary of Servicenow devices with the hostname as the key. 
	#I created this upon Eme's request to also do a comparison by hostname and thus provide a much faster lookup time
	#in exchange for minimal memory. 
	servicenow_hostnames = {}

	for servicenow_device in servicenow_devices:
		servicenow_hostnames.update({servicenow_devices[servicenow_device]["name"].upper():servicenow_devices[servicenow_device]}) 
	
	#Iterates through all the Crowdstrike devices and checks to see if there is a hostname or MAC match in ServiceNow
	with open("crowdstrike_servicenow_difference.csv", "w", newline='') as csvfile:

		csv_writer = csv.writer(csvfile, delimiter=",", quotechar="\"", quoting=csv.QUOTE_MINIMAL)
		csv_writer.writerow(["CROWDSTRIKE MAC", 
							"CROWDSTRIKE IP", 
							"CROWDSTRIKE HOSTNAME",
							"CROWDSTRIKE OS",
                            "Last Seen",
							"SERVICENOW MAC",
							"SERVICENOW IP", 
							"SERVICENOW HOSTNAME",
							"SERVICENOW GROUP", 
							"DESCRIPTION"])
		
		#Logic for finding the differences and writing them to CSV between servicenow and crowdstrike
		for cs_device in crowdstrike_devices:
			try:
				servicenow_device = servicenow_devices.get(cs_device["mac_address"].replace("-", ":").upper(), None)
				if servicenow_device:
					if (cs_device["local_ip"] ==  servicenow_device["ip_address"]) and \
					(cs_device["hostname"].upper().replace("-","") == servicenow_device["name"].upper().replace("-","")):
						if cs_device["hostname"].upper() == servicenow_device["name"].upper():
							csv_writer.writerow([cs_device["mac_address"], 
												cs_device["local_ip"], 
												cs_device["hostname"],
												cs_device["os_version"],
												cs_device["last_seen"],
												servicenow_device["mac_address"],
												servicenow_device["ip_address"],  
												servicenow_device["name"],
												servicenow_device["group_name"],
												"IP, Hostname, and MAC are the same"].strip('\n')) #
						else:
							csv_writer.writerow([cs_device["mac_address"], 
												cs_device["local_ip"], 
												cs_device["hostname"],
												cs_device["os_version"],
												cs_device["last_seen"],
												servicenow_device["mac_address"],
												servicenow_device["ip_address"],  
												servicenow_device["name"],
												servicenow_device["group_name"],
												"IP, Hostname, and MAC are the same. Hostnames match except for '-'"])	#				
					else:
						csv_writer.writerow([cs_device["mac_address"], 
											cs_device["local_ip"], 
											cs_device["hostname"],
											cs_device["os_version"],
											cs_device["last_seen"],
											servicenow_device["mac_address"],
											servicenow_device["ip_address"],  
											servicenow_device["name"],
											servicenow_device["group_name"],
											"MAC address match, IP address or Hostname does not match"]) #
				else:
					if cs_device["hostname"].upper().replace("-", "") in servicenow_hostnames.keys():
						if cs_device["hostname"].upper() in servicenow_hostnames.keys():
							csv_writer.writerow([cs_device["mac_address"], 
												cs_device["local_ip"], 
												cs_device["hostname"],
												cs_device["os_version"],
												cs_device["last_seen"],
												servicenow_hostnames[cs_device["hostname"]]["mac_address"],
												servicenow_hostnames[cs_device["hostname"]]["ip_address"],
												servicenow_hostnames[cs_device["hostname"]]["name"],
												servicenow_hostnames[cs_device["hostname"]]["group_name"],
												"MAC found in Crowdstrike but not in ServiceNow, matching hostnames"])
						else:
							csv_writer.writerow([cs_device["mac_address"], 
												cs_device["local_ip"], 
												cs_device["hostname"],
												cs_device["os_version"],
												cs_device["last_seen"],
												servicenow_hostnames[cs_device["hostname"]]["mac_address"],
												servicenow_hostnames[cs_device["hostname"]]["ip_address"],
												servicenow_hostnames[cs_device["hostname"]]["name"],
												servicenow_hostnames[cs_device["hostname"]]["group_name"],
												"MAC found in Crowdstrike but not in ServiceNow, matching hostnames except for '-'"])							
					else:
						csv_writer.writerow([cs_device["mac_address"], 
											cs_device["local_ip"], 
											cs_device["hostname"],
											cs_device["os_version"],
											cs_device["last_seen"],
											"",
											"",
											"",
											"",
											"Crowdstrike device does not have any MAC or Hostname matches in ServiceNow"]) #
			except Exception as e:
				logging.warning("ERROR: Unable to write Crowdstrike  device to CSV, skipping to next")
				#print (cs_device["local_ip"])
				continue
		
		return None


def create_pid_file():
	"""Creates PID lock file to make sure more than 1 instance of this program isn't running

	Returns the full path to the PID file
	"""

	pid_file = str('/tmp/' + os.path.basename(__file__).strip('.py') + '.pid')
	if os.path.isfile(pid_file):
	    logging.warning("ERROR: Program already running or %s unsuccessfully closed, closing this current instance" % pid_file)
	    sys.exit(1)
	else:
		try:
		    current_pid = str(os.getpid())
		    pid = open(pid_file, 'w+')
		    pid.write(current_pid)
		except Exception as error:
			logging.warning("ERROR: Unable write lock file at  %s, exiting" % str('/tmp/' + os.path.basename(__file__).strip('.py') + '.pid'))
			sys.exit(1)

	return pid_file


def remove_pid_file():
	"""
	Removes PID file to unlock program

	"""
	try:
		os.remove(str('/tmp/' + os.path.basename(__file__).strip('.py') + '.pid'))
	except Exception as error:
		logging.warning("ERROR: Unable to close %s file, please manually delete" % str('/tmp/' + os.path.basename(__file__).strip('.py') + '.pid'))
		sys.exit(1)


def main():

	#pid_file = create_pid_file()
	print("Starting")
	# cs = crowdstrike.Crowdstrike(CROWDSTRIKE_USERNAME, CROWDSTRIKE_API_KEY, CROWDSTRIKE_URL)
	
	print("Pulling Crowdstrike device information")

	cs_device_ids = cs.pull_device_ids()
	cs_device_details = cs.pull_device_details(cs_device_ids)

	print("Pulling Crowdstrike device information complete")

	print("Pulling ServiceNow device information")
	sn = servicenow.ServiceNow(SERVICENOW_USERNAME, SERVICENOW_PASSWORD, SERVICENOW_URL)
	
	sn_devices = sn.pull_all_device_information("cmdb_ci")

	print("Pulling ServiceNow device information Complete")

	print("Comparing ServiceNow and Crowdstrike device information, creating CSV crowdstrike_servicenow_difference.csv")
	create_differences_csv(cs_device_details, sn_devices)
			
	print("Program completed")
	#remove_pid_file()
	logging.info("INFO: %s run to completion" % __file__)


if __name__ == "__main__":
	main()
