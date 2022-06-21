import requests
from requests.auth import HTTPBasicAuth
import json
import logging
import config



class ServiceNow:

	group_mappings = {}

	def __init__(self, username, password, url):

		self.url = url
		self.username = username
		self.password = password

	def pull_all_device_information(self, table_name):
		"""
		table_name is the name of the table in which you want to pull the device information

		Returns a dictionary of all servicenow device information in the table, mac address is the key and the value is a json of
		all the device information.
		Dictionary will be like {<mac_address> : <json_of_all_device_information>}

		Eme asked for further functionality in pulling the group names too. This is done in the "_populate_group_mappings" function 
		and also by adding the "group_name" entry into each "device_info" entry. 

		"""

		self._populate_group_mappings()

		query = self.url + "/api/now/table/" + table_name
		header = {"Content-Type":"application/json","Accept":"application/json"}

		result = requests.get(query, params=header, auth=HTTPBasicAuth(self.username, self.password), proxies=proxies)

		device_list = {}

		#creating the dictionary of devices and adding the "group_name" to each one
		for device_info in json.loads(result.content)["result"]:
			
			device_group_name = self.pull_group_name(dict(device_info["support_group"]).get("value"))
			device_info.update({"group_name" : device_group_name})
			device_list.update({device_info["mac_address"].upper() : device_info})

		return device_list

	def _populate_group_mappings(self):
		"""
		The ServiceNow group names are mapped to another table and instead of querying the API to lookup the group name
		each time I need to fetch that value, I query the group table in ServiceNow and populate a class dictionary mapping the 
		'sys_id' of each group to it's name for all groups in that table. This way the program can lookup without calling the API.

		"""

		query = self.url + "/api/now/table/sys_user_group"
		header = {"Content-Type":"application/json","Accept":"application/json"}

		result = requests.get(query, auth=HTTPBasicAuth(self.username, self.password), proxies=proxies)
		for group_info in json.loads(result.content)["result"]:
			try:
				self.group_mappings.update({group_info["sys_id"] : group_info["name"]})
			except:
				logging.warning("ERROR: Unable to get group, skipping to next")

	def pull_group_name(self, group_id):
		"""
		Performs a lookup in the class dictionary "group_mappings" and returns the group name associated with teh group_id.
		If that group_id is not there it will be returned as "Not Available"
		"""
		if group_id:
			return self.group_mappings.get(group_id, "Not Available")
		else:
			return "Not Available"

def main():

	#Using the main() function primarily for debugging
	print('Being run as main')

	import config

	SERVICENOW_USERNAME = config.SERVICENOW_USERNAME
	SERVICENOW_PASSWORD = config.SERVICENOW_PASSWORD
	SERVICENOW_URL = config.SERVICENOW_URL

	sn = ServiceNow(SERVICENOW_USERNAME, SERVICENOW_PASSWORD, SERVICENOW_URL)
	f = open('sn_test_data', 'w+')
	f.write(json.dumps(sn.pull_all_device_information("cmdb_ci"), indent=4, sort_keys=True))
	f.close()
	test = json.loads(open("sn_test_data", "r+").read())
	# for thing in test["result"]:
	# 	print( thing["mac_address"])
	# 	print("/n")


if __name__ == "__main__":
	main()
