from __future__ import print_function

import concurrent.futures
import dns.resolver
import whois
import time
import zipfile
import os, os.path
import re
import argparse
import sys
import requests
import re
from colorama import init
from termcolor import colored
from bs4 import BeautifulSoup
import warnings
import json
import Levenshtein
import tldextract
import base64


try:
	from sets import Set as set
except ModuleNotFoundError:
	pass

init()

warnings.filterwarnings("ignore")

def DNS_Records(domain):

	RES={}
	MX=[]
	NS=[]
	A=[]
	AAAA=[]
	SOA=[]
	CNAME=[]

	resolver = dns.resolver.Resolver()
	resolver.timeout = 1
	resolver.lifetime = 1

	rrtypes=['A','MX','NS','AAAA','SOA']
	for r in rrtypes:
		try:
			Aanswer=resolver.query(domain,r)
			for answer in Aanswer:
				if r=='A':
					A.append(answer.address)
					RES.update({r:A})
				if r=='MX':
					MX.append(answer.exchange.to_text()[:-1])
					RES.update({r:MX})
				if r=='NS':
					NS.append(answer.target.to_text()[:-1])
					RES.update({r:NS})
				if r=='AAAA':
					AAAA.append(answer.address)
					RES.update({r:AAAA})
				if r=='SOA':
					SOA.append(answer.mname.to_text()[:-1])
					RES.update({r:SOA})
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

def get_DNS_record_results():
	global IPs
	try:
		with concurrent.futures.ThreadPoolExecutor(max_workers=len(DOMAINS)) as executor:
			future_to_domain={executor.submit(DNS_Records, domain):domain for domain in DOMAINS}
			for future in concurrent.futures.as_completed(future_to_domain):
				dom=future_to_domain[future]
				print("  \_", colored(dom,'cyan'))
				try:
					DNSAdata = future.result()
					for k,v in DNSAdata.items():
						print("    \_", k,colored(','.join(v), 'yellow'))
						for ip in v:
							aa=re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ip)
							if aa:
								IPs.append(ip)
				except Exception as exc:
					print(('%r generated an exception: %s' % (dom, exc)))
	except ValueError:
		pass
	return IPs

def diff_dates(date1, date2):
	return abs((date2-date1).days)

def whois_domain(domain_name):
	import time
	import datetime
	RES={}

	try:
		w_res=whois.whois(domain_name)
		name=w_res.name
		creation_date=w_res.creation_date
		emails=w_res.emails
		registrar=w_res.registrar
		updated_date=w_res.updated_date
		expiration_date=w_res.expiration_date

		if isinstance(creation_date, datetime.datetime) or isinstance(expiration_date, datetime.datetime) or  isinstance(updated_date, datetime.datetime):
			current_date=datetime.datetime.now()
			res=diff_dates(current_date,creation_date)
			RES.update({"creation_date":creation_date, \
				"creation_date_diff":res,\
				"emails":emails,\
				"name":name,\
				"registrar":registrar,\
				"updated_date":updated_date,\
				"expiration_date":expiration_date})

		elif isinstance(creation_date, list) or isinstance(expiration_date, list) or  isinstance(updated_date, list):
			creation_date=w_res.creation_date[0]
			updated_date=w_res.updated_date[0]
			expiration_date=w_res.expiration_date[0]
			current_date=datetime.datetime.now()
			res=diff_dates(current_date,creation_date)

			RES.update({"creation_date":creation_date, \
				"creation_date_diff":res,\
				"emails":emails,\
				"name":name,\
				"registrar":registrar,\
				"updated_date":updated_date,\
				"expiration_date":expiration_date})

		time.sleep(2)
	except TypeError:
		pass
	except whois.parser.PywhoisError:
		print(colored("No match for domain: {}.".format(domain_name),'red'))
	except AttributeError:
		pass
	return RES

def IP2CIDR(ip):
	from ipwhois.net import Net
	from ipwhois.asn import IPASN

	net = Net(ip)
	obj = IPASN(net)
	results = obj.lookup()
	return results

def get_IP2CIDR():
	try:
		with concurrent.futures.ThreadPoolExecutor(max_workers=len(IPs)) as executor:
			future_to_ip2asn={executor.submit(IP2CIDR, ip):ip for ip in IPs}
			for future in concurrent.futures.as_completed(future_to_ip2asn):
				ipaddress=future_to_ip2asn[future]
				print("  \_",colored(ipaddress, 'cyan'))
				try:
					data = future.result()
					for k,v in data.items():
						print("    \_", k, colored(v, 'yellow'))
				except Exception as exc:
					print(('%r generated an exception: %s' % (ipaddress, exc)))
	except ValueError:
		pass

def get_WHOIS_results():
	global NAMES
	try:
		with concurrent.futures.ThreadPoolExecutor(max_workers=len(DOMAINS)) as executor:
			future_to_whois_domain={executor.submit(whois_domain, domain):domain for domain in DOMAINS}
			for future in concurrent.futures.as_completed(future_to_whois_domain):
				dwhois=future_to_whois_domain[future]
				try:
					whois_data = future.result()
					if whois_data:
						for k,v in whois_data.items():
							if 'creation_date' in k:
								cd=whois_data.get('creation_date')
							if 'updated_date' in k:
								ud=whois_data.get('updated_date')
							if 'expiration_date' in k:
								ed=whois_data.get('expiration_date')
							if 'creation_date_diff' in k:
								cdd=whois_data.get('creation_date_diff')
							if 'name' in k:
								name=whois_data.get('name')
							if 'emails' in k:
								email=whois_data.get('emails')
							if 'registrar' in k:
								reg=whois_data.get('registrar')

						if isinstance(email,list):
							print("  \_", colored(dwhois,'cyan'), \
							"\n    \_ Created Date", colored(cd, 'yellow'), \
							"\n    \_ Updated Date", colored(ud, 'yellow'), \
							"\n    \_ Expiration Date", colored(ed, 'yellow'), \
							"\n    \_ DateDiff", colored(cdd, 'yellow'), \
							"\n    \_ Name",colored(name, 'yellow'),\
							"\n    \_ Email", colored(','.join(email), 'yellow'), \
							"\n    \_ Registrar", colored(reg, 'yellow'))

							if isinstance(name,list):
								for n in name:
									NAMES.append(n)
							else:
								NAMES.append(name)
						else:
								print("  \_ ", colored(dwhois,'cyan'), \
								"\n    \_ Created Date", colored(cd, 'yellow'), \
								"\n    \_ Updated Date", colored(ud, 'yellow'), \
								"\n    \_ Expiration Date", colored(ed, 'yellow'), \
								"\n    \_ DateDiff", colored(cdd, 'yellow'), \
								"\n    \_ Name",colored(name, 'yellow'),\
								"\n    \_ Email", colored(email, 'yellow'),	\
								"\n    \_ Registrar", colored(reg, 'yellow'))

				except Exception as exc:
					print(('%r generated an exception: %s' % (dwhois, exc)))
	except ValueError:
		pass
	return NAMES

def EmailDomainBigData(name):
	url = "http://domainbigdata.com/name/{}".format(name)
	session = requests.Session()
	session.headers['User-Agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:42.0) Gecko/20100101 Firefox/42.0'
	email_query = session.get(url)
	email_soup = BeautifulSoup(email_query.text,"html5lib")
	emailbigdata = email_soup.find("table",{"class":"t1"})
	return emailbigdata

def get_EmailDomainBigData():
	CreatedDomains=[]
	try:
		with concurrent.futures.ThreadPoolExecutor(max_workers=len(NAMES)) as executor:
			future_to_rev_whois_domain={executor.submit(EmailDomainBigData, name): name for name in set(NAMES)}
			for future in concurrent.futures.as_completed(future_to_rev_whois_domain):
				namedomaininfo=future_to_rev_whois_domain[future]
				try:
					rev_whois_data = future.result()
					print("  \_", colored(namedomaininfo,'cyan'))
					CreatedDomains[:] = []
					if rev_whois_data is not None:
						for row in rev_whois_data.findAll("tr"):
							if row:
								cells = row.findAll("td")
								if len(cells) == 3:
									CreatedDomains.append(colored(cells[0].find(text=True)))

						print("    \_", colored(str(len(CreatedDomains)-1) + " domain(s) have been created in the past",'yellow'))
					else:
						print("    \_", colored(str(len(CreatedDomains)) + " domain(s) have been created in the past",'yellow'))
				except Exception as exc:
					print(('%r generated an exception: %s' % (namedomaininfo, exc)))
	except ValueError:
		pass

def crt(domain):
	parameters = {'q': '%.{}'.format(domain), 'output':'json'}
	headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0','content-type': 'application/json'}
	response = requests.get("https://crt.sh/?",params=parameters, headers=headers)
	content=response.content.decode('utf-8')
	data = json.loads("[{}]".format(content.replace('}{', '},{')))
	return data

def getcrt():
	try:
		with concurrent.futures.ThreadPoolExecutor(max_workers=len(NAMES)) as executor:
			future_to_crt={executor.submit(crt, domain):domain for domain in DOMAINS}
			for future in concurrent.futures.as_completed(future_to_crt):
				d=future_to_crt[future]
				print("  \_", colored(d,'cyan'))
				try:
					crtdata=future.result()
					if len(crtdata)>0:
						for crtd in crtdata:
							for k,v in crtd.items():
								print("    \_",k,colored(v,'yellow'))
					else:
						print("    \_", colored("No CERT found",'red'))
				except Exception as exc:
					print("    \_",colored(exc,'red'))
	except ValueError:
		pass

def VTDomainReport(domain):
		parameters = {'domain': domain, 'apikey': 'f76bdbc3755b5bafd4a18436bebf6a47d0aae6d2b4284f118077aa0dbdbd76a4'}
		headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0'}
		response = requests.get('https://www.virustotal.com/vtapi/v2/domain/report', params=parameters,headers=headers)
		response_dict = response.json()
		return response_dict

def getVTDomainReport():
	try:
		with concurrent.futures.ThreadPoolExecutor(max_workers=len(DOMAINS)) as executor:
			future_to_vt={executor.submit(VTDomainReport, domain):domain for domain in DOMAINS}
			for future in concurrent.futures.as_completed(future_to_vt):
				d=future_to_vt[future]
				print("  \_",colored(d,'cyan'))
				try:
					vtdata = future.result()
					if vtdata['response_code']==1:
						if 'detected_urls' in vtdata:
							if len(vtdata['detected_urls'])>0:
								print("    \_",colored("Detected URLs",'red'))
								for det_urls in vtdata['detected_urls']:
									print("      \_", colored(det_urls['url'],'yellow'),\
									colored(det_urls['positives'],'yellow'), \
									"/", \
									colored(det_urls['total'],'yellow'),\
									colored(det_urls['scan_date'],'yellow'))
						if 'detected_downloaded_samples' in vtdata:
							if len(vtdata['detected_downloaded_samples'])>0:
								print("    \_",colored("Detected Download Samples",'red'))
								for det_donw_samples in vtdata['detected_downloaded_samples']:
									print("      \_", colored(det_donw_samples['date'],'yellow'),\
									colored(det_donw_samples['positives'],'yellow'), \
									"/", \
									colored(det_donw_samples['total'],'yellow'),\
									colored(det_donw_samples['sha256'],'yellow'))
						if 'detected_communicating_samples' in vtdata:
							if len(vtdata['detected_communicating_samples'])>0:
								print("    \_",colored("Detected Communication Samples",'red'))
								for det_comm_samples in vtdata['detected_communicating_samples']:
									print("      \_", colored(det_comm_samples['date'],'yellow'),\
									colored(det_comm_samples['positives'],'yellow'), \
									"/", \
									colored(det_comm_samples['total'],'yellow'),\
									colored(det_comm_samples['sha256'],'yellow'))
						if 'categories' in vtdata:
							if len(vtdata['categories'])>0:
								print("    \_",colored("categories",'red'))
								for ctg in vtdata['categories']:
									print("      \_", colored(ctg,'yellow'))
						if 'subdomains' in vtdata:
							if len(vtdata['subdomains'])>0:
								print("    \_",colored("Subdomains",'red'))
								for vt_domain in vtdata['subdomains']:
									print("      \_", colored(vt_domain,'yellow'))
						if 'resolutions' in vtdata:
							if len(vtdata['resolutions'])>0:
								print("    \_",colored("Resolutions (PDNS)",'red'))
								for vt_resolution in vtdata['resolutions']:
									print("      \_", colored(vt_resolution['last_resolved'],'yellow'),\
									colored(vt_resolution['ip_address'],'yellow'))
					else:
						print("    \_", colored(vtdata['verbose_msg'],'yellow'))
				except Exception as exc:
					print("    \_", colored(exc,'red'))
	except ValueError:
		pass

def quad9(domain):
	resolver = dns.resolver.Resolver()
	resolver.nameservers = ['9.9.9.9']
	resolver.timeout = 1
	resolver.lifetime = 1

	try:
		Aanswers = resolver.query(domain, 'A')
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

def get_quad9_results():
	try:
		with concurrent.futures.ThreadPoolExecutor(max_workers=len(DOMAINS)) as executor:
			future_to_quad9={executor.submit(quad9, domain):domain for domain in DOMAINS}
			for future in concurrent.futures.as_completed(future_to_quad9):
				quad9_domain=future_to_quad9[future]
				print("  \_", colored(quad9_domain,'cyan'))
				try:
					QUAD9NXDOMAIN = future.result()
					if QUAD9NXDOMAIN is not None:
						print("    \_", colored(QUAD9NXDOMAIN,'red'))
					else:
						print("    \_", colored("Not Blocked",'yellow'))
				except Exception as exc:
					print(('%r generated an exception: %s' % (quad9_domain, exc)))
	except ValueError:
		pass

def shannon_entropy(domain):
	import math


	stList = list(domain)
	alphabet = list(set(domain)) # list of symbols in the string
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

def donwnload_nrd(d):
	if not os.path.isfile(d+".zip"):
		b64 = base64.b64encode((d+".zip").encode('ascii'))
		nrd_zip = 'https://whoisds.com//whois-database/newly-registered-domains/{}/nrd'.format(b64.decode('ascii'))
		try:
			resp = requests.get(nrd_zip,stream=True)

			print("Downloading File {} - Size {}...".format(d+'.zip',resp.headers['Content-length']))
			if resp.headers['Content-length']:
				with open(d+".zip", 'wb') as f:
					for data in resp.iter_content(chunk_size=1024):
						f.write(data)
				try:
					zip = zipfile.ZipFile(d+".zip")
					zip.extractall()
				except:
					print("File is not a zip file.")
					sys.exit()
		except:
			print("File {}.zip does not exist on the remore server.".format(d))
			sys.exit()

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
	out=[]
	for i in range(1, len(search_word)):
		out.append(search_word[:i] + '-' + search_word[i:])
	return out

def subdomain(search_word):
	out=[]
	for i in range(1, len(search_word)):
		if search_word[i] not in ['-', '.'] and search_word[i-1] not in ['-', '.']:
			out.append(search_word[:i] + '.' + search_word[i:])
	return out

if __name__ == '__main__':
	DOMAINS=[]
	IPs=[]
	NAMES=[]
	parser = argparse.ArgumentParser(prog="hnrd.py",description='hunting newly registered domains')
	parser.add_argument("-f", action="store", dest='date', help="date [format: year-month-date]",required=True)
	parser.add_argument("-s", action="store", dest='search',help="search a keyword",required=True)
	parser.add_argument("-v", action="version",version="%(prog)s v1.0")
	args = parser.parse_args()

	regexd=re.compile('[\d]{4}-[\d]{2}-[\d]{2}$')
	matchObj=re.match(regexd,args.date)
	if matchObj:
		donwnload_nrd(args.date)
	else:
		print("Not a correct input (example: 2010-10-10)")
		sys.exit()

	try:
		f = open(args.date + '.txt','r')
	except:
		print("No such file or directory {}.zip found. Trying domain-names.txt.".format(args.date))

		try:
			f = open('domain-names.txt','r')
		except:
			print("No such file or directory domain-names.txt found")
			sys.exit()

	bitsquatting_search=bitsquatting(args.search)
	hyphenation_search=hyphenation(args.search)
	subdomain_search=subdomain(args.search)
	search_all=bitsquatting_search+hyphenation_search+subdomain_search
	search_all.append(args.search)

	for row in f:
		for argssearch in search_all:
			match = re.search(r"^"+argssearch,row)
			if match:
				DOMAINS.append(row.strip('\r\n'))

	start = time.time()

	print("[*]-Retrieving DNS Record(s) Information")
	get_DNS_record_results()

	print("[*]-Retrieving IP2ASN Information")
	get_IP2CIDR()

	print("[*]-Retrieving WHOIS Information")
	get_WHOIS_results()

	print("[*]-Retrieving Reverse WHOIS (by Name) Information [Source https://domainbigdata.com]")
	get_EmailDomainBigData()

	print("[*]-Retrieving Certficates [Source https://crt.sh]")
	getcrt()

	print("[*]-Retrieving VirusTotal Information")
	getVTDomainReport()

	print("[*]-Check domains against QUAD9 service")
	get_quad9_results()

	print("[*]-Calculate Shannon Entropy Information")
	for domain in DOMAINS:
		if shannon_entropy(domain) > 4:
			print("  \_", colored(domain,'cyan'), colored(shannon_entropy(domain), 'red'))
		elif shannon_entropy(domain) > 3.5 and shannon_entropy(domain) < 4:
			print("  \_", colored(domain,'cyan'), colored(shannon_entropy(domain), 'yellow'))
		else:
			print("  \_",colored(domain,'cyan'), shannon_entropy(domain))

	print("[*]-Calculate Levenshtein Ratio")
	for domain in DOMAINS:
		ext_domain=tldextract.extract(domain)
		LevWord1=ext_domain.domain
		LevWord2=args.search
		if Levenshtein.ratio(LevWord1, LevWord2) > 0.8:
			print("  \_", colored(LevWord1, 'cyan'), "vs",colored(LevWord2,'cyan'), colored(Levenshtein.ratio(LevWord1, LevWord2),'red'))
		if Levenshtein.ratio(LevWord1, LevWord2) < 0.8 and Levenshtein.ratio(LevWord1, LevWord2) > 0.4:
			print("  \_", colored(LevWord1, 'cyan'), "vs",colored(LevWord2,'cyan'), colored(Levenshtein.ratio(LevWord1, LevWord2),'yellow'))
		if Levenshtein.ratio(LevWord1, LevWord2) < 0.4:
			print("  \_", colored(LevWord1, 'cyan'), "vs", colored(LevWord2,'cyan'), colored(Levenshtein.ratio(LevWord1, LevWord2),'green'))

	print((time.time() - start))
