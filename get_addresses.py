import os
import os.path
import time
import csv
import json
import subprocess
import requests


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
    res = requests.post(config['db_host'] + '/scans', data={
        'device_id': config['device_id'],
        'api_key': config['api_key'],
        'data': data
    })

def enable_mon():
    p = subprocess.Popen(['airmon-ng', 'check', 'kill'])
    p.wait()
    p = subprocess.Popen(['airmon-ng', 'start', 'wlan0'])
    p.wait()

def get_data():
    p = subprocess.Popen(['timeout', '10', 'airodump-ng', '-w', airodump_file, '--output', 'csv', 'wlan0mon'])
    p.wait()

def process_data():
    with open(airodump_file + '-01.csv', 'r', encoding='utf8') as ad_file:
        ad_file_str = ad_file.read()
        [ap_str, client_str] = ad_file_str.split('\n\n')

        with open(ap_file, 'w', encoding='utf8') as f:
            f.write(ap_str.lstrip())
        with open(client_file, 'w', encoding='utf8') as f:
            f.write(client_str)

        with open(ap_file, 'r', encoding='utf8') as f:
            reader = csv.DictReader(ap_file)
            ap_list = list(reader)

        with open(client_file, 'r', encoding='utf8') as f:
            reader = csv.DictReader(ap_file)
            clients_list = list(reader)

        print(json.dumps(ap_list))

    with open(data_file, 'w', encoding='utf-8') as f:
        f.write(json.dumps({'access_points': ap_list, 'clients': clients_list}))

    conf = load_config()

    if (files_valid()):
        with open(data_file, 'r', encoding='utf-8') as f:
            send_data(conf, json.load(f))

    enable_mon()
    get_data()
    process_data()

