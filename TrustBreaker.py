#!/usr/bin/python3
# TrustBreaker
"""
Copyright (c) The George Washington University
Written by Craig Laprade (craig_laprade@gwu.edu)
Directed by Prof. Howie Huang (howie@gwu.edu)
https://www.seas.gwu.edu/~howie/
This file is subject to the terms and conditions defined in
file 'LICENSE.txt', which is part of this source code package.
"""

import argparse
import copy
import json
import logging
import multiprocessing
import os
import resource
import subprocess
import time
from collections import defaultdict
from concurrent.futures import TimeoutError

import numpy as np
import requests
import tldextract
import urllib3
from pebble import ProcessPool
from tqdm import tqdm


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GANDI_API_V5_KEY = False
DOMAIN_AVAILABILITY_CACHE = {}

RESOLVERS_PATH = 'resolvers.txt'
FINGERPRINTS_PATH = 'fingerprints.json'
AMASS_CONFIG_PATH = 'amass_config.ini'
OUTPUT_PATH = './'
parser = argparse.ArgumentParser()
parser.add_argument("domain", help="Target domain you wish to examine.")
parser.add_argument("--input_file", "-i", help="Read in list of known subdomains. No OSINT collection.")
parser.add_argument("--fingerprints_path", "-f", help="Full path to Subtake fingerprints file.  Default is ./fingerprints.json")
parser.add_argument("--resolvers_path", "-r", help="Full path to the resolvers file.  Default is ./resolvers.txt")
parser.add_argument("--amass_config_path", "-a", help="Full path to Amass config file.  Default is ./amass_config.ini")
parser.add_argument("--output_dir", "-o", help="Full path to write ouput. Default is ./")
parser.add_argument("--gandi_api_key", "-k", help="Gandi v5 API key. Domain availability checking will not work without this")

args = parser.parse_args()

if args.fingerprints_path:
    FINGERPRINTS_PATH = args.fingerprints_path

if args.resolvers_path:
    RESOLVERS_PATH = args.resolvers_path

if args.amass_config_path:
    AMASS_CONFIG_PATH = args.amass_config_path

if args.gandi_api_key:
    GANDI_API_V5_KEY = args.gandi_api_key


def exec_and_readlines(cmd, domains):
    # Takes a cmd and a list [of domains] and pipes the list to the cmd as catted out from a file
    # Source: https://0xpatrik.com/subdomain-enumeration-2019/
    # Author: Patrik Hudak

    domains_str = bytes('\n'.join(domains), 'utf-8')
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.PIPE)
    stdout, stderr = proc.communicate(input=domains_str)

    return [j.decode('utf-8').strip() for j in stdout.splitlines() if j != b'\n' and b'\\' not in j]

def get_amass(domain):
    # Takes a domain and extracts AMASS output as unsorted list
    # Author: TBA
    print("[-] Getting AMASS output for " + domain)
    logging.info(("[-] Getting AMASS output for " + domain))
    amass_cmd = [
        'amass',
        'enum',
        '-timeout', '360',
        '-d', domain,
        '-dir',OUTPUT_PATH,
        '-config', "amass_config.ini",
        '-passive',
        '-o', OUTPUT_PATH+domain+'_amass.txt'
    ]
    proc = subprocess.Popen(amass_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    stdout = proc.communicate()[0]

    return stdout.decode('utf-8').strip()

def get_massdns(domains, query_type):
    # Takes an array of domains and a query type and returns a list of JSON objects with the resulting queries
    # Source: https://0xpatrik.com/subdomain-enumeration-2019/
    # Author: Patrik Hudak
    print("[-] Getting " + query_type + " records via MASSDNS for domains like " + domains[0])
    logging.info(("[-] Getting " + query_type + " records via MASSDNS for domains like " + domains[0]))
    massdns_cmd = [
        'massdns',
        '-s', '1000',
        '-t', query_type,
        '-o', 'J',
        '-r', RESOLVERS_PATH,
        '--flush'
    ]

    processed = []
    for line in exec_and_readlines(massdns_cmd, domains):
        if not line:
            continue
        processed.append(json.loads(line.strip()))

    return processed

def get_subtake(domains):
    # Takes a list of domains and return subtake output
    # Author: TBA
    print("[-] Getting SUBTAKE output for " + domains[0])
    logging.info(("[-] Getting SUBTAKE output for " + domains[0]))

    # subtake does not take stdin, so we flush the domains to disk and read them back
    # works well as a temp store for manual exploitation
    data = open(OUTPUT_PATH+ '/'+'subtake.tmp', "w")
    for domain in domains:
        data.write("%s\n" % domain)
    data.close()
    subtake_cmd = [
        'subtake',
        '-f', OUTPUT_PATH+'subtake.tmp',
        '-c', FINGERPRINTS_PATH,
        '-a',
        '-t', '200',
        '-o', OUTPUT_PATH+'subtake.txt'
    ]
    resource.setrlimit(resource.RLIMIT_NOFILE, (999999, 999999))
    proc = subprocess.Popen(subtake_cmd, stdout=subprocess.PIPE)
    stdout = proc.communicate()[0]
    return stdout.decode('utf-8').strip()


def validate_NS(domain_record):
    # Takes a domain record in JSON and returns whether or not the NS records are registerable
    # Author: TBA

    hostname = domain_record['name']
    nameserver =  str(domain_record['data'])
    dig_cmd = [
        'dig',
        hostname, '@' + str(nameserver)
    ]
    proc = subprocess.Popen(dig_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout,stderr = proc.communicate()

    if (('NXDOMAIN' in stdout.decode('utf-8')) or ('SERVFAIL' in stdout.decode('utf-8')) or ('REFUSED' in stdout.decode('utf-8'))) and (not 'CNAME' in stdout.decode('utf-8')):
        #print(stdout.decode('utf-8'))
        print('[!] ' + hostname + ' Not Found at ' + nameserver)
        logging.info('[!] ' + hostname + ' Not Found at ' + nameserver)




def check_registerability(domains):
    # Takes a list of domains and determines if any of them a registerable
    # Author: TBA

    for domain in domains:
        if domain['status'] == 'NOERROR' and 'authorities' not in domain['data'] and 'answers' in domain['data']:

            for result in domain['data']['answers']:
                ext = tldextract.extract(result['data'])

                if len(ext.registered_domain) > 2:

                    if is_domain_available(ext.registered_domain):

                        print("[!] %s is pointed to by %s as a %s and %s is available for registration" % (
                        ext.registered_domain, result['name'], result['type'], ext.registered_domain))
                        logging.info("[!] %s is pointed to by %s as a %s and %s is available for registration" % (
                        ext.registered_domain, result['name'], result['type'], ext.registered_domain))




def _auto_retry(registar_function):
    # Author: Matthew Bryant
    # Source: https://github.com/mandatoryprogrammer/TrustTrees/blob/620b212c4048225aef15d702f29e31a14d6191df/trusttrees/utils.py
    def wrapper_of_registar_function(input_domain):

        for _ in range(10):
            status = registar_function(input_domain)
            if status != 'pending':
                break
            time.sleep(1)

        return status.startswith('available')

    return wrapper_of_registar_function


@_auto_retry
def _can_register_with_gandi_api_v5(input_domain):
    # Author: Matthew Bryant
    # Source: https://github.com/mandatoryprogrammer/TrustTrees/blob/620b212c4048225aef15d702f29e31a14d6191df/trusttrees/utils.py
    try:
        response = requests.get(
            url='https://api.gandi.net/v5/domain/check',
            params={
                'name': input_domain,
            },
            headers={
                'Authorization': f'Apikey {GANDI_API_V5_KEY}',
            },
            verify=False,
        )

        assert response.status_code == 200

    except Exception:
        try:
            print("Failed 1st attempt to check availability of %s" % input_domain)
            logging.info("Failed 1st attempt to check availability of %s" % input_domain)
            time.sleep(5)

            response = requests.get(
            url='https://api.gandi.net/v5/domain/check',
            params={
                'name': input_domain,
            },
            headers={
                'Authorization': f'Apikey {GANDI_API_V5_KEY}',
            },
            verify=False,
            )
            assert response.status_code == 200

        except Exception:
            print("Failed 2nd attempt to check availability of %s. Moving on" % input_domain)
            logging.info("Failed 2nd attempt to check availability of %s. Moving on" % input_domain)
            return 'not_available'

    if 'products' not in response.json():
        return 'not_available'

    assert len(response.json()['products']) == 1
    status = response.json()['products'][0]['status']

    return status




def is_domain_available(input_domain):
    # Author: Matthew Bryant
    # Source: https://github.com/mandatoryprogrammer/TrustTrees/blob/620b212c4048225aef15d702f29e31a14d6191df/trusttrees/utils.py

    if input_domain.endswith('.'):
        input_domain = input_domain[:-1]

    if input_domain in DOMAIN_AVAILABILITY_CACHE:
        return DOMAIN_AVAILABILITY_CACHE[input_domain]

    _can_register_function = _can_register_with_gandi_api_v5

    domain_available = _can_register_function(input_domain)
    DOMAIN_AVAILABILITY_CACHE[input_domain] = domain_available

    return domain_available

def azurefd_check(domain_record):
    # Takes a NDJSON domain record from MassDNS and determines if the record is a vulnerable Azure Front Door
    # Author: TBA

    if 'azurefd.net' in domain_record['data']:
        try:
            main_get = requests.get(
                url='https://'+domain_record['name'],
                verify=False,
                allow_redirects=True,
                timeout=10
            )
            cname_get = requests.get(
                url='https://'+domain_record['data'],
                verify=False,
                allow_redirects = True,
                timeout=10
            )
            if "InvalidUri" in cname_get.text and "restore" in main_get.text:
                print('[!] ' + domain_record['name'] + ' vulnerable Azuerfd record of ' + domain_record['data'])
                logging.info('[!] ' + domain_record['name'] + ' vulnerable Azuerfd record of ' + domain_record['data'])
        except Exception:
            pass

def beanstalk_check(domain_record):
    # Takes a NDJSON domain record from MassDNS and determines if the record is a vulnerable AWS Beanstalk
    # Author: TBA

    if "elasticbeanstalk" in domain_record['data']:

        hostname = domain_record['data']
        subtake_cmd = [
            'dig',
            hostname
        ]
        proc = subprocess.Popen(subtake_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout,stderr = proc.communicate()

        if (('NXDOMAIN' in stdout.decode('utf-8'))):

            print('[!] ' + domain_record['name'] + "is an invalid elasticbeanstalk for " + hostname )
            logging.info('[!] ' + domain_record['name'] + "is an invalid elasticbeanstalk for " + hostname )

        if stderr:
            print(stderr)


def chunks(L, n):
    # Takes a list and yields chunks of size n
    # Author: Ned Batchelder
    # Source: https://stackoverflow.com/questions/312443/how-do-you-split-a-list-into-evenly-sized-chunks
    if n == 0:
        return L
    for i in range(0, len(L), n):
        yield L[i:i+n]



if __name__ == '__main__':

    domain = args.domain
    known_sub_domains = []
    OUTPUT_PATH = OUTPUT_PATH + domain + '/'
    os.makedirs(OUTPUT_PATH)
    logging.basicConfig(filename=OUTPUT_PATH+'TrustBreaker_output.txt', level=logging.INFO, format='%(asctime)s %(message)s')
    logging.info("*******************************Starting*******************************")
    # First we all known subdomains from OSINT via AMASS
    if args.input_file:
        with open(args.input_file) as f:
            known_sub_domains = f.readlines()

    else:
        known_sub_domains = get_amass(domain).splitlines()

    known_sub_domains.insert(0, domain)

    # We check if any of the known subdomains are vulnerable to "normal" subdomain takeovers
    subtake_res = get_subtake(known_sub_domains)
    if subtake_res:
        print(subtake_res)
        logging.info(subtake_res)

    All_NS = []
    All_CNAME = []
    All_Fail = defaultdict(list)

    # For all known subdomains we gather their A, NS and CNAME records
    ############################# A Processes #################################
    mass_res_A = get_massdns(known_sub_domains, 'A')
    with open(OUTPUT_PATH+'A_Orig.txt', 'w') as filehandle:
        for listitem in mass_res_A:
            filehandle.write('%s\n' % listitem)
    for res in mass_res_A:
        if (res['status'] == 'NXDOMAIN' or res['status'] == 'SERVFAIL' or res['status'] == 'REFUSED'):
            #todo Add dig +trace and extract.  If we have Azure/DO/AWS we can go to town
            All_Fail[res['status']].append(res['name'])
    for each in All_Fail['SERVFAIL']:
        print('[!] '+ each + " SERVFAILed.")
        logging.info('[!] '+ each + " SERVFAILed.")
    for each in All_Fail['REFUSED']:
        print('[!] '+ each + " REFUSEDed.")
        logging.info('[!] '+ each + " REFUSEDed.")
    Orig_Fail = copy.deepcopy(All_Fail)

    ############################# NS Processes #################################
    mass_res_NS = get_massdns(known_sub_domains, 'NS')
    with open(OUTPUT_PATH+'NS_Orig.txt', 'w') as filehandle:
        for listitem in mass_res_NS:
            filehandle.write('%s\n' % listitem)

    if GANDI_API_V5_KEY:
        print('[-] Checking for domains that can be registered [NS]')
        logging.info('[-] Checking for domains that can be registered [NS]')
        check_registerability(mass_res_NS)

    for res in mass_res_NS:
        if 'answers' in res['data']:
            for result in res['data']['answers']:
                if 'SOA' not in str(result) and 'CNAME' not in str(result):
                    All_NS.append(result)
    Uniq_NS_string = list(np.unique(np.array(All_NS).astype(str)))
    Uniq_NS = [json.loads(n.replace("'", '"')) for n in Uniq_NS_string]
    print( '[-] Attempting to find vulnerable NS records for ' + domain)
    logging.info('[-] Attempting to find vulnerable NS records for ' + domain)

    with ProcessPool(max_workers=multiprocessing.cpu_count()*4) as pool:
        future = pool.map(validate_NS, tqdm(Uniq_NS), timeout=30)
        iterator = future.result()
        while True:
            try:
                result = next(iterator)
            except StopIteration:
                break
            except TimeoutError:
                print("Timeout NS Availability Check")

    ############################# CNAME Processes #################################
    mass_res_CNAME = get_massdns(known_sub_domains, 'CNAME')
    with open(OUTPUT_PATH+'CNAME_Orig.txt', 'w') as filehandle:
        for listitem in mass_res_CNAME:
            filehandle.write('%s\n' % listitem)
    if GANDI_API_V5_KEY:
        print('[-] Checking for domains that can be registered [CNAME]')
        logging.info('[-] Checking for domains that can be registered [CNAME]')
        check_registerability(mass_res_CNAME)
    for res in mass_res_CNAME:
        if res['status'] == 'NOERROR' and 'answers' in res['data']:
            for result in res['data']['answers']:
                if 'SOA' not in str(result) and 'CNAME' in str(result):
                    All_CNAME.append(result)
    Uniq_CNAME_string = list(np.unique(np.array(All_CNAME).astype(str)))
    Uniq_CNAME = [json.loads(n.replace("'", '"')) for n in Uniq_CNAME_string]
    with ProcessPool(max_workers=multiprocessing.cpu_count()*4) as pool:
        future = pool.map(azurefd_check, tqdm(Uniq_CNAME), timeout=30)
        iterator = future.result()
        while True:
            try:
                result = next(iterator)
            except StopIteration:
                break
            except TimeoutError:
                print("Timeout Azurefd")
    with ProcessPool(max_workers=multiprocessing.cpu_count()*4) as pool:
        future = pool.map(beanstalk_check, tqdm(Uniq_CNAME), timeout=30)
        iterator = future.result()
        while True:
            try:
                result = next(iterator)
            except StopIteration:
                break
            except TimeoutError:
                print("Timeout Beanstalk")

    ############################# MX Processes #################################
    mass_res_MX = get_massdns(known_sub_domains, 'MX')
    with open(OUTPUT_PATH+'MX_Orig.txt', 'w') as filehandle:
        for listitem in mass_res_MX:
            filehandle.write('%s\n' % listitem)
    if GANDI_API_V5_KEY:
        print('[-] Checking for domains that can be registered [MX]')
        logging.info('[-] Checking for domains that can be registered [MX]')
        check_registerability(mass_res_MX)


    print("[-] Complete")
    logging.info("[-] Complete")
