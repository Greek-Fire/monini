#!/bin/python2

import re
import requests
import sys
import urllib2
import urllib
from pymongo import MongoClient
from multiprocessing.dummy import Pool
from datetime import date
import json
from operator import itemgetter
import uuid


mongo_client = MongoClient('localhost', 27017) 
url = 'https://cloud.redhat.com/api/'
v = 'false'
timeout = 30

def get_json(url):
    # Performs a GET using the passed URL location
  try:
    r = requests.get(url, auth=(username, password),timeout=timeout, verify=True)
    r  = r.json()
  except ValueError:
    print  "Json was not returned. Not Good!"
    print r.text
    sys.exit()
  return r

#Fix for better error
def call_api(url):
  jsn = get_json(url)
  if jsn.get('error'):
      print "Error: " + jsn['error']['message']
  else:
      if jsn.get('results'):
          return jsn['results']
      elif 'results' not in jsn:
          return jsn
      else:
          print "No results found"
  return None

def grab_id(n):
  ids = n['id']
  return ids

def url_list(url): #, api_ep):
  url_list = []
  #x = call_api(url + api_ep)['data']
  x = call_api(url + "vulnerability/v1/vulnerabilities/cves/ids?data_format=json&show_all=false&page_size=300000")['data']
  for ids in x:
    y = url + "vulnerability/v1/cves/" + ids + "/affected_systems?page_size=200000&show_advisories=true" 
    url_list.append(y)
  return url_list

def rhsa_url_list(url):
  rhsa_url_list = []
  x = call_api(url + "patch/v1/advisories?limit=-1&sort=-applicable_systems&filter[advisory_type]=3")['data']
  #x = call_api(url + "vulnerability/v1/vulnerabilities/cves?data_format=json&show_all=false&page_size=200000")['data']
  y = map(grab_id, x)
  for ids in y:
    y = url + "patch/v1/advisories/" + ids + "/systems?limit=-1"
    rhsa_url_list.append(y)
  return rhsa_url_list


def cve_rhsa_to_host(url):
  # Add RHSA or CVE key
  x = get_json(url)['data']
  re_cve_rhsa = re.search('(?=CVE|RHSA)([^abc]+-\d\d\d\d.\d+)', url)
  for y in x:
    y = json.dumps(y['attributes'])
    r = str(re_cve_rhsa.group(1))
    a = json.dumps({c_r_id:r,'api_upload_date':d,'source':'insights'})
    b = json.loads(y)
    a = json.loads(a)
    if 'rule' in b and b['rule']:
      if 'cmdline_dict' in b['rule']['details']:
        del b['rule']['details']
        print 'true'
    b.update(a)
    cve_rhsa_list.append(b)
  print re_cve_rhsa.group(1)

def cve_gen_report(url):
  ll = url_list(url)
  pool = Pool(2)
  cve = pool.map(cve_rhsa_to_host, ll)
  pool.close()
  pool.join()
  return

def rhsa_gen_report(url):
  rhsa_u_list = rhsa_url_list(url)
  pool = Pool(2)
  cve = pool.map(cve_rhsa_to_host, rhsa_u_list)
  pool.close()
  pool.join()
  return

d = date.today().strftime("%d/%m/%Y")
u = str(uuid.uuid1())
print u
cve_rhsa_list = []

insighsts = 'insights_'
cve_rhsa = 'rhsa'
c_r_id = cve_rhsa + '_id'
ins_r_c = insighsts + cve_rhsa
if cve_rhsa == 'rhsa':
  rhsa_gen_report(url)
elif cve_rhsa =='cve':
  cve_gen_report(url)

mongo_client['temp'][u].insert_many( cve_rhsa_list )

filter={
 'api_upload_date': d 
}
project={
  '_id': 0
}
sort=list({
  'display_name': 1,
  c_r_id: 1
}.items())

t  = mongo_client['temp'][u].find(filter=filter,projection=project,sort=sort)
tt = mongo_client['vuln'][ins_r_c].find(filter=filter,projection=project,sort=sort)

t = list(t)
tt = list(tt)
ttt = len(tt)


if t != tt: 
  diff = []
  for x in t:
    if x not in tt:
      diff.append(x)
else:
  diff = []

if len(diff) == 0:
  #mongo_client.drop_database('temp')
  print 'not uploading' 
elif ttt == 0:
  mongo_client['vuln'][ins_r_c].insert( t )  
else:
  mongo_client['vuln'][ins_r_c].insert( diff ) 
  #mongo_client.drop_database('temp')
  print 'uploading'
