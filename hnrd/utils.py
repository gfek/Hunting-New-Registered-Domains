import base64
import dns.resolver
import json
import Levenshtein
import os
import os.path
import requests
import sys
import tldextract
import whois
import zipfile

from bs4 import BeautifulSoup


def dns_records(domain):

    RES = {}
    MX = []
    NS = []
    A = []
    AAAA = []
    SOA = []

    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1

    rrtypes = ['A', 'MX', 'NS', 'AAAA', 'SOA']
    for r in rrtypes:
        try:
            Aanswer = resolver.query(domain, r)
            for answer in Aanswer:
                if r == 'A':
                    A.append(answer.address)
                    RES.update({r: A})
                if r == 'MX':
                    MX.append(answer.exchange.to_text()[:-1])
                    RES.update({r: MX})
                if r == 'NS':
                    NS.append(answer.target.to_text()[:-1])
                    RES.update({r: NS})
                if r == 'AAAA':
                    AAAA.append(answer.address)
                    RES.update({r: AAAA})
                if r == 'SOA':
                    SOA.append(answer.mname.to_text()[:-1])
                    RES.update({r: SOA})
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except dns.name.EmptyLabel:
            pass
        except dns.resolver.NoNameservers:
            pass
        except dns.resolver.Timeout:
            pass
        except dns.exception.DNSException:
            pass
    return RES


def diff_dates(date1, date2):
    return abs((date2-date1).days)


def whois_domain(domain_name):
    import time
    import datetime
    RES = {}
    emails = "-"

    try:
        w_res = whois.whois(domain_name)

        if (isinstance(w_res.creation_date, list)
                or isinstance(w_res.updated_date, list)
                or isinstance(w_res.expiration_date, list)):
            creation_date = w_res.creation_date[0]
            updated_date = w_res.updated_date[0]
            expiration_date = w_res.expiration_date[0]
        else:
            creation_date = w_res.creation_date
            updated_date = w_res.updated_date
            expiration_date = w_res.expiration_date

        if isinstance(w_res.emails, list):
            emails = ", ".join(w_res.emails)
        current_date = datetime.datetime.now()

        RES.update({
            "creation_date": creation_date,
            "creation_date_diff": diff_dates(current_date, creation_date),
            "emails": emails,
            "name": w_res.name,
            "registrar": w_res.registrar,
            "updated_date": updated_date,
            "expiration_date": expiration_date
        })

        time.sleep(2)
    except TypeError:
        pass
    except whois.parser.PywhoisError:
        print("No match for domain: {}.".format(domain_name))
    except AttributeError:
        pass

    return RES


def ip2cidr(ip):
    from ipwhois.net import Net
    from ipwhois.asn import IPASN

    net = Net(ip)
    obj = IPASN(net)
    results = obj.lookup()
    return results


def email_domain_bigdata(name):
    url = "http://domainbigdata.com/name/{}".format(name)
    session = requests.Session()
    session.headers['User-Agent'] = r'Mozilla/5.0 ' \
        + '(Macintosh; Intel Mac OS X 10.10; rv:42.0) ' \
        + 'Gecko/20100101 Firefox/42.0'
    email_query = session.get(url)
    email_soup = BeautifulSoup(email_query.text, "html5lib")
    emailbigdata = email_soup.find("table", {"class": "t1"})
    return emailbigdata


def crt(domain):
    parameters = {'q': '%.{}'.format(domain), 'output': 'json'}
    headers = {
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0)'
        + ' Gecko/20100101 Firefox/52.0',
        'Accept': 'application/json'}
    response = requests.get(
        "https://crt.sh/?", params=parameters, headers=headers)
    assert(response.status_code == "200"), "Too many connections."
    content = response.content.decode('utf-8')
    data = json.loads("{}".format(content.replace('}{', '},{')))

    return data


def vt_domain_report(domain):
    parameters = {
        'domain': domain, 'apikey': 'f76bdbc3755b5bafd4a18436bebf6a47d0aae6'
        + 'd2b4284f118077aa0dbdbd76a4'}
    headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10;'
               + ' rv:52.0) Gecko/20100101 Firefox/52.0'}
    response = requests.get(
        'https://www.virustotal.com/vtapi/v2/domain/report',
        params=parameters,
        headers=headers)
    response_dict = response.json()
    return response_dict


def quad9(domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['9.9.9.9']
    resolver.timeout = 1
    resolver.lifetime = 1

    try:
        resolver.query(domain, 'A')
    except dns.resolver.NXDOMAIN:
        return "Blocked"
    except dns.resolver.NoAnswer:
        pass
    except dns.name.EmptyLabel:
        pass
    except dns.resolver.NoNameservers:
        pass
    except dns.resolver.Timeout:
        pass
    except dns.exception.DNSException:
        pass


def shannon_entropy(domain):
    import math

    stList = list(domain)
    alphabet = list(set(domain))  # list of symbols in the string
    freqList = []

    for symbol in alphabet:
        ctr = 0
        for sym in stList:
            if sym == symbol:
                ctr += 1
        freqList.append(float(ctr) / len(stList))

    # Shannon entropy
    ent = 0.0
    for freq in freqList:
        ent = ent + freq * math.log(freq, 2)
    ent = -ent
    return ent


def bitsquatting(search_word):
    out = []
    masks = [1, 2, 4, 8, 16, 32, 64, 128]

    for i in range(0, len(search_word)):
        c = search_word[i]
        for j in range(0, len(masks)):
            b = chr(ord(c) ^ masks[j])
            o = ord(b)
            if (o >= 48 and o <= 57) or (o >= 97 and o <= 122) or o == 45:
                out.append(search_word[:i] + b + search_word[i+1:])
    return out


def hyphenation(search_word):
    out = []
    for i in range(1, len(search_word)):
        out.append(search_word[:i] + '-' + search_word[i:])
    return out


def subdomain(search_word):
    out = []
    for i in range(1, len(search_word)):
        if (search_word[i] not in ['-', '.']
                and search_word[i-1] not in ['-', '.']):
            out.append(search_word[:i] + '.' + search_word[i:])
    return out


def donwnload_nrd(d):
    if not os.path.isfile(d+".zip"):
        b64 = base64.b64encode((d+".zip").encode('ascii'))
        nrd_zip = 'https://whoisds.com'\
            + '/whois-database/newly-registered-domains/{}/nrd'.format(
                b64.decode('ascii'))
        try:
            resp = requests.get(nrd_zip, stream=True)

            print("Downloading File {} - Size {}...".format(
                d+'.zip', resp.headers['Content-length']))

            if resp.headers['Content-length']:
                with open(d+".zip", 'wb') as f:
                    for data in resp.iter_content(chunk_size=1024):
                        f.write(data)
                try:
                    zip = zipfile.ZipFile(d+".zip")
                    zip.extractall()
                except Exception:
                    print("File is not a zip file.")
                    sys.exit()
        except Exception:
            print("File {}.zip does not exist on the remore server.".format(d))
            sys.exit()


def levenshtein_ratio(domain, search_args):
    ext_domain = tldextract.extract(domain)
    LevWord1 = ext_domain.domain
    LevWord2 = search_args
    RES = {
        "domain": domain,
        "LevWord1": ext_domain.domain,
        "LevWord2": search_args,
        "ratio": Levenshtein.ratio(LevWord1, LevWord2)
    }

    return RES
