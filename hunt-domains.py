#!/usr/bin/env python

from __future__ import print_function

import argparse
import concurrent.futures
import re
import sys
import time
import warnings

from colorama import init
from termcolor import colored

import hnrd.utils

try:
    from sets import Set as set
except ModuleNotFoundError:
    pass

init()

warnings.filterwarnings("ignore")


def get_dns_record_results():
    global IPs
    try:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(DOMAINS)) as executor:
            future_to_domain = {
                    executor.submit(
                            hnrd.utils.dns_records, domain
                        ): domain for domain in DOMAINS
                }
            for future in concurrent.futures.as_completed(future_to_domain):
                dom = future_to_domain[future]
                print(r"  \_", colored(dom, 'cyan'))
                try:
                    DNSAdata = future.result()
                    for k, v in DNSAdata.items():
                        print(r"    \_", k, colored(','.join(v), 'yellow'))
                        for ip in v:
                            aa = re.match(
                                r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)
                            if aa:
                                IPs.append(ip)
                except Exception as exc:
                    print(('%r generated an exception: %s' % (dom, exc)))
    except ValueError:
        pass
    return IPs


def get_ip2cidr():
    w = len(IPs)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=w) as executor:
            future_to_ip2asn = {
                executor.submit(hnrd.utils.ip2cidr, ip): ip for ip in IPs}
            for future in concurrent.futures.as_completed(future_to_ip2asn):
                ipaddress = future_to_ip2asn[future]
                print(r"  \_", colored(ipaddress, 'cyan'))
                try:
                    data = future.result()
                    for k, v in data.items():
                        print(r"    \_", k, colored(v, 'yellow'))
                except Exception as exc:
                    print(('%r generated an exception: %s' % (ipaddress, exc)))
    except ValueError:
        pass


def get_whois_results():
    global NAMES
    w = len(DOMAINS)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=w) as executor:
            future_to_whois_domain = {
                executor.submit(
                        hnrd.utils.whois_domain, domain
                    ): domain for domain in DOMAINS
            }

            for future in concurrent.futures.as_completed(
                    future_to_whois_domain):
                dwhois = future_to_whois_domain[future]
                try:
                    whois_data = future.result()
                    if whois_data:
                        for k, v in whois_data.items():
                            if 'creation_date' in k:
                                cd = whois_data.get('creation_date')
                            if 'updated_date' in k:
                                ud = whois_data.get('updated_date')
                            if 'expiration_date' in k:
                                ed = whois_data.get('expiration_date')
                            if 'creation_date_diff' in k:
                                cdd = whois_data.get('creation_date_diff')
                            if 'name' in k:
                                name = whois_data.get('name')
                            if 'emails' in k:
                                email = whois_data.get('emails')
                            if 'registrar' in k:
                                reg = whois_data.get('registrar')
                        print(
                            r"  \_",
                            colored(dwhois, 'cyan'),
                            "\n" + r"    \_ Created Date",
                            colored(cd, 'yellow'),
                            "\n" + r"    \_ Updated Date",
                            colored(ud, 'yellow'),
                            "\n" + r"    \_ Expiration Date",
                            colored(ed, 'yellow'),
                            "\n" + r"    \_ DateDiff",
                            colored(cdd, 'yellow'),
                            "\n" + r"    \_ Name",
                            colored(name, 'yellow'),
                            "\n" + r"    \_ Email",
                            colored(email, 'yellow'),
                            "\n" + r"    \_ Registrar",
                            colored(reg, 'yellow'))

                        if isinstance(name, list):
                            for n in name:
                                NAMES.append(n)
                        else:
                            NAMES.append(name)

                except Exception as exc:
                    print(('%r generated an exception: %s' % (dwhois, exc)))
    except ValueError:
        pass
    return NAMES


def get_email_domain_bigdata():
    CreatedDomains = []
    w = len(NAMES)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=w) as executor:
            future_to_rev_whois_domain = {
                executor.submit(
                    hnrd.utils.email_domain_bigdata, name):
                        name for name in set(NAMES)}

            for future in concurrent.futures.as_completed(
                    future_to_rev_whois_domain):
                namedomaininfo = future_to_rev_whois_domain[future]
                try:
                    rev_whois_data = future.result()
                    print(r"  \_", colored(namedomaininfo, 'cyan'))
                    CreatedDomains[:] = []
                    if rev_whois_data is not None:
                        for row in rev_whois_data.findAll("tr"):
                            if row:
                                cells = row.findAll("td")
                                if len(cells) == 3:
                                    CreatedDomains.append(
                                        colored(cells[0].find(text=True)))

                        print(
                            r"    \_",
                            colored(str(len(CreatedDomains)-1) +
                                    " domain(s) have been created in the past",
                                    'yellow')
                            )
                    else:
                        print(
                            r"    \_",
                            colored(str(len(CreatedDomains)) +
                                    " domain(s) have been created in the past",
                                    'yellow')
                        )
                except Exception as exc:
                    print("{} generated an exception: {}".format(
                            namedomaininfo, exc))

    except ValueError:
        pass


def get_crt():
    w = len(NAMES)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=w) as executor:
            future_to_crt = {
                executor.submit(hnrd.utils.crt, domain):
                    domain for domain in DOMAINS}
            for future in concurrent.futures.as_completed(future_to_crt):
                d = future_to_crt[future]
                print(r"  \_", colored(d, 'cyan'))
                try:
                    crtdata = future.result()
                    if len(crtdata) > 0:
                        for crtd in crtdata:
                            for k, v in crtd.items():
                                print(r"    \_", k, colored(v, 'yellow'))
                    else:
                        print(r"    \_", colored("No CERT found", 'red'))
                except Exception as exc:
                    print(r"    \_", colored(exc, 'red'))
    except ValueError:
        pass


def get_vt_domain_report():
    w = len(DOMAINS)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=w) as executor:
            future_to_vt = {
                executor.submit(
                    hnrd.utils.vt_domain_report, domain):
                        domain for domain in DOMAINS}

            for future in concurrent.futures.as_completed(future_to_vt):
                d = future_to_vt[future]
                print(r"  \_", colored(d, 'cyan'))
                try:
                    vtdata = future.result()
                    if vtdata['response_code'] == 1:
                        if 'detected_urls' in vtdata:
                            if len(vtdata['detected_urls']) > 0:
                                print(
                                    r"    \_",
                                    colored("Detected URLs", 'red'))
                                for det_urls in vtdata['detected_urls']:
                                    print(
                                        r"      \_",
                                        colored(det_urls['url'], 'yellow'),
                                        colored(
                                            det_urls['positives'], 'yellow'),
                                        r"/",
                                        colored(
                                            det_urls['total'], 'yellow'),
                                        colored(
                                            det_urls['scan_date'], 'yellow'))
                        if 'detected_downloaded_samples' in vtdata:
                            if len(vtdata['detected_downloaded_samples']) > 0:
                                print(r"    \_", colored(
                                    "Detected Download Samples", 'red'))
                                for det_donw_samples in vtdata[
                                        'detected_downloaded_samples']:
                                    print(
                                        r"      \_",
                                        colored(
                                            det_donw_samples['date'],
                                            'yellow'),
                                        colored(
                                            det_donw_samples['positives'],
                                            'yellow'),
                                        r"/",
                                        colored(
                                                det_donw_samples['total'],
                                                'yellow'
                                            ),
                                        colored(
                                                det_donw_samples['sha256'],
                                                'yellow')
                                            )
                        if 'detected_communicating_samples' in vtdata:
                            if len(
                                    vtdata['detected_communicating_samples']
                                    ) > 0:
                                print(
                                    r"    \_",
                                    colored(
                                        "Detected Communication Samples",
                                        'red'
                                    )
                                )
                                for det_comm_samples in vtdata[
                                        'detected_communicating_samples']:
                                    print(
                                        r"      \_",
                                        colored(
                                            det_comm_samples['date'],
                                            'yellow'),
                                        colored(
                                            det_comm_samples['positives'],
                                            'yellow'),
                                        r"/",
                                        colored(
                                            det_comm_samples['total'],
                                            'yellow'),
                                        colored(
                                            det_comm_samples['sha256'],
                                            'yellow')
                                    )
                        if 'categories' in vtdata:
                            if len(vtdata['categories']) > 0:
                                print(r"    \_", colored("categories", 'red'))
                                for ctg in vtdata['categories']:
                                    print(r"      \_", colored(ctg, 'yellow'))
                        if 'subdomains' in vtdata:
                            if len(vtdata['subdomains']) > 0:
                                print(r"    \_", colored("Subdomains", 'red'))
                                for vt_domain in vtdata['subdomains']:
                                    print(r"      \_", colored(
                                        vt_domain, 'yellow'))
                        if 'resolutions' in vtdata:
                            if len(vtdata['resolutions']) > 0:
                                print(r"    \_", colored(
                                    "Resolutions (PDNS)", 'red'))
                                for vt_resolution in vtdata['resolutions']:
                                    print(
                                        r"      \_",
                                        colored(
                                            vt_resolution['last_resolved'],
                                            'yellow'),
                                        colored(
                                            vt_resolution['ip_address'],
                                            'yellow'))
                    else:
                        print(
                            r"    \_",
                            colored(vtdata['verbose_msg'], 'yellow')
                        )
                except Exception as exc:
                    print(r"    \_", colored(exc, 'red'))
    except ValueError:
        pass


def get_quad9_results():
    w = len(DOMAINS)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=w) as executor:
            future_to_quad9 = {
                executor.submit(
                    hnrd.utils.quad9, domain): domain for domain in DOMAINS}
            for future in concurrent.futures.as_completed(future_to_quad9):
                quad9_domain = future_to_quad9[future]
                print(r"  \_", colored(quad9_domain, 'cyan'))
                try:
                    QUAD9NXDOMAIN = future.result()
                    if QUAD9NXDOMAIN is not None:
                        print(r"    \_", colored(QUAD9NXDOMAIN, 'red'))
                    else:
                        print(r"    \_", colored("Not Blocked", 'yellow'))
                except Exception as exc:
                    print(
                        ('%r generated an exception: %s' % (quad9_domain, exc))
                    )
    except ValueError:
        pass


if __name__ == '__main__':
    DOMAINS = []
    IPs = []
    NAMES = []
    parser = argparse.ArgumentParser(
        prog="hnrd.py",
        description='hunting newly registered domains')
    parser.add_argument(
        "-f",
        action="store",
        dest='date',
        help="date [format: year-month-date]",
        required=True)
    parser.add_argument(
        "-s",
        action="store",
        dest='search',
        help="search a keyword",
        required=True)
    parser.add_argument(
        "-v",
        action="version",
        version="%(prog)s v1.0")
    args = parser.parse_args()

    regexd = re.compile(r'[\d]{4}-[\d]{2}-[\d]{2}$')
    matchObj = re.match(regexd, args.date)
    if matchObj:
        hnrd.utils.donwnload_nrd(args.date)
    else:
        print("Not a correct input (example: 2010-10-10)")
        sys.exit()

    try:
        f = open(args.date + '.txt', 'r')
    except Exception:
        print(
            "No such file or directory {}.zip found."
            " Trying domain-names.txt.".format(args.date)
        )

        try:
            f = open('domain-names.txt', 'r')
        except Exception:
            print("No such file or directory domain-names.txt found")
            sys.exit()

    bitsquatting_search = hnrd.utils.bitsquatting(args.search)
    hyphenation_search = hnrd.utils.hyphenation(args.search)
    subdomain_search = hnrd.utils.subdomain(args.search)
    search_all = bitsquatting_search+hyphenation_search+subdomain_search
    search_all.append(args.search)

    for row in f:
        for argssearch in search_all:
            match = re.search(r"^"+argssearch, row)
            if match:
                DOMAINS.append(row.strip('\r\n'))

    start = time.time()

    print("[*]-Retrieving DNS Record(s) Information")
    get_dns_record_results()

    print("[*]-Retrieving IP2ASN Information")
    get_ip2cidr()

    print("[*]-Retrieving WHOIS Information")
    get_whois_results()

    print(
        "[*]-Retrieving Reverse WHOIS (by Name) Information "
        + "[Source https://domainbigdata.com]")
    get_email_domain_bigdata()

    print("[*]-Retrieving Certficates [Source https://crt.sh]")
    get_crt()

    print("[*]-Retrieving VirusTotal Information")
    get_vt_domain_report()

    print("[*]-Check domains against QUAD9 service")
    get_quad9_results()

    print("[*]-Calculate Shannon Entropy Information")
    for domain in DOMAINS:
        if hnrd.utils.shannon_entropy(domain) > 4:
            print(
                r"  \_",
                colored(domain, 'cyan'),
                colored(
                    hnrd.utils.shannon_entropy(domain), 'red')
            )
        elif (hnrd.utils.shannon_entropy(domain) > 3.5
                and hnrd.utils.shannon_entropy(domain) < 4):
            print(
                r"  \_",
                colored(domain, 'cyan'),
                colored(hnrd.utils.shannon_entropy(domain), 'yellow')
            )
        else:
            print(
                r"  \_",
                colored(domain, 'cyan'),
                hnrd.utils.shannon_entropy(domain))

    print("[*]-Calculate Levenshtein Ratio")
    for domain in DOMAINS:

        r = hnrd.utils.levenshtein_ratio(domain, args.search)
        if r["ratio"] > 0.8:
            print(
                r"  \_",
                colored(r["LevWord1"], 'cyan'),
                "vs",
                colored(r["LevWord2"], 'cyan'),
                colored(r["ratio"], 'red'))
        if (r["ratio"] < 0.8 and r["ratio"] > 0.4):
            print(
                r"  \_",
                colored(r["LevWord1"], 'cyan'),
                "vs",
                colored(r["LevWord2"], 'cyan'),
                colored(r["ratio"], 'yellow'))
        if r["ratio"] < 0.4:
            print(
                r"  \_",
                colored(r["LevWord1"], 'cyan'),
                "vs", colored(r["LevWord2"], 'cyan'),
                colored(r["ratio"], 'green'))

    print((time.time() - start))
