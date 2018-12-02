import os
import os.path
import time
import csv
import json
import subprocess
import requests
import threading

ap_file = 'access_points.csv'
client_file = 'clients.csv'
airodump_file = 'airodump'
data_file = 'scandata.json'

def load_config():
    with open('config.json', 'r') as conf_file:
        return json.loads(conf_file.read())

def files_valid():
    try:
        time1 = os.stat(ap_file).st_mtime
        time2 = os.stat(client_file).st_mtime
        return time.time() - time1 < 300 and time.time() - time2 < 300
    except Exception:
        return False

def send_data(config, data):
    #print(data)
    res = requests.post(config['db_host'] + '/scans', data={
        'device_id': config['device_id'],
        'api_key': config['api_key'],
        'data': open("scandata.json", 'rb')
    })
    print(res)

def enable_mon():
    p = subprocess.Popen(['airmon-ng', 'check', 'kill'])
    p.wait()
    p = subprocess.Popen(['airmon-ng', 'start', 'wlan0'])
    p.wait()

def get_data():
    try:
        os.remove(airodump_file + '-01.csv')
    except Exception:
        pass
    FNULL = open(os.devnull, 'w')
    p = subprocess.Popen(["timeout", '10', 'airodump-ng', '-w', 'airodump', '--output-format', 'csv', 'wlan0mon'])
    time.sleep(12)


def process_data():
    with open(airodump_file + '-01.csv', 'r', encoding='utf8') as ad_file:
     
        ad_file_str = ad_file.read()
        file_split = ad_file_str.split('\n\n')
        ap_str = file_split[0]
        client_str = file_split[1]

        with open(ap_file, 'w', encoding='utf8') as f:
            f.write(ap_str.lstrip())
        with open(client_file, 'w', encoding='utf8') as f:
            f.write(client_str)
        
        ap_list = []
        with open(ap_file, 'r', encoding='utf8') as f:
            reader = csv.reader(f)
            headers = [s.strip() for s in next(reader)]
            for row in reader:
                record = {}
                for i, col in enumerate(row):
                    try:
                        record[headers[i]] = int(col.strip())
                    except ValueError:
                        record[headers[i]] = col.strip()
                        
                ap_list.append(record)

        clients_list = []
        with open(client_file, 'r', encoding='utf8') as f:
            reader = csv.reader(f)
            headers = [s.strip() for s in next(reader)]
            for row in reader:
                record = {}
                for i, col in enumerate(row):
                    try:
                        record[headers[i]] = int(col.strip())
                    except ValueError:
                        record[headers[i]] = col.strip()

                clients_list.append(record)
                
        print(json.dumps(ap_list))

    with open(data_file, 'w', encoding='utf-8') as f:
        f.write(json.dumps({'access_points': ap_list, 'clients': clients_list}))


conf = load_config()
print(files_valid())
if (files_valid()):
    with open(data_file, 'r', encoding='utf-8') as f:
        send_data(conf, json.load(f))

enable_mon()
get_data()
process_data()

