from falconpy import oauth2 as FalconAuth #supports oauth2 
from falconpy import hosts as FalconHosts #access host info
import config #access API information
import pprint
import json
import os
import csv
##import pandas as pd

proxies = {'http': 'http://XXXX.XXXX.columbia.edu:8080','https':'http://XXXX.XXXX.columbia.edu:8080'}

authorization = FalconAuth.OAuth2(creds={
        'client_id': config.CROWDSTRIKE_USERNAME,
        'client_secret': config.CROWDSTRIKE_API_KEY,
        'http': 'http://XXXX.XXXX.columbia.edu:8080','https':'http://XXXX.XXXX.columbia.edu:8080'
    },
        proxy=proxies
)

try:
    token = authorization.token()["body"]["access_token"]
except:
    token = False
FALCON = FalconHosts.Hosts(access_token=token, proxy=proxies)
def pull_device_ids():
    

    PARAMS = {
        'limit': 5000,
        'sort': ''
        # 'filter':"hostname:'HiRoryCSTest*'"

    }
    device_id_list = []
    while True:
        response = FALCON.QueryDevicesByFilterScroll(parameters=PARAMS, proxy=proxies)
##        pprint.pprint(response)
        devices = response.get('body').get('resources')
        for d in devices:
            device_id_list.append(d)
        if not devices:
            break
        PARAMS['offset']=response.get('body').get('meta').get('pagination').get('offset')
    return device_id_list
        
  
def pull_device_details(device_id_list):
    device_details = []
    length = len(device_id_list)
    i = 0 
    slice_size = 5000
    while i < length:
        j = min(length, i+slice_size)
        device_slice = device_id_list[i:j]
        response = FALCON.GetDeviceDetails(ids=device_slice, proxy=proxies)
        for d in response.get('body').get('resources'):
            device_details.append(d)
        i += slice_size
        # print(response.get("body"))
        # print(response)
    return device_details

def main():
    cs_set = []
    for dl in pull_device_ids():

        resource_list = pull_device_details(dl)

        for r in resource_list:
            # r = [r.get("hostname"),r.get("mac_address"), r.get("local_ip"), r.get("os_version"), r.get("hostname"), r.get("last_seen")]
            # cs_set.update([r["mac_address"], r["device_id"], r["hostname"], r["last_seen"]])
            cs_set.append(r)
    # print(len(cs_set), len(cs_set[-1].keys()))
    return cs_set
        # cs_set = sorted(cs_set)
        # print(cs_set)
        
            




            # f.write(str(r))
            # f.write("\n")
            # mac_set.append([r.get("mac_address"), r.get("local_ip"), r.get("os_version"), r.get("last_seen"), r.get("hostname")])
            # f.write(str(mac_set))         

# main()

def tests():
    device_list = pull_device_ids()
    device_details_list = pull_device_details(device_list)
    print(len(device_details_list))
    expected_keys = {"mac_address", "os_version", "last_seen", "hostname", "local_ip"}
    device_keys = set(device_details_list[0].keys())
    assert expected_keys.intersection(device_keys)==expected_keys 


if __name__ in ('__main__','__console__'):
    tests()
    authorization.revoke(token=token)
