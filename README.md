# Hunting-Newly-Registered-Domains
Hunting Newly Registered Domains

The `hnrd.py` is a python utility for finding and analysing potential phishing domains used in phishing campaigns targeting your customers. This utility is written in python 2.7 and is based on the analysis of the features below by consuming a free daily list provided by the [Whoisds](https://whoisds.com/newly-registered-domains) site. 

## Features

* Download a free list from [Whoisds](https://whoisds.com/newly-registered-domains)
* Bitsquatting, hyphenation & domain permutation is used for the transformation of the given keyword
* Generated words are searched/matched againsts the list
* Retrieve DNS Record(s) Information
* Retrieve IP2ASN Information
* Retrieve WHOIS Information
* [Retrieve Reverse WHOIS (by Name) Information](https://domainbigdata.com)
* [Retrieve Certficates](https://crt.sh)
* Retirieve VirusTotal Information
* Check domains against [QUAD9](https://quad9.net) service 
* Calculate Shannon Entropy Information
* Calculate Levenshtein Ratio Distance

## Requirements

* futures
* dnspython
* python-whois
* ipwhois
* colorama
* requests
* beautifulsoup4
* html5lib
* termcolor
* python-Levenshtein
* tldextract

## Help

```
usage: hnrd.py [-h] -f DATE -s SEARCH [-v]

hunting newly registered domains

optional arguments:
  -h, --help  show this help message and exit
  -f DATE     date [format: year-month-date]
  -s SEARCH   search a keyword
  -v          show program's version number and exit
```

### Example

`python hnrd.py -f 2018-03-30 -s paypal`

```
[*]-Retrieving DNS Record(s) Information
  \_ paypal-required-action.com
    \_ A 162.219.251.133
    \_ SOA ns19.hosterbox.com
    \_ NS ns19.hosterbox.com,ns20.hosterbox.com
    \_ MX paypal-required-action.com
  \_ paypal-resolvedbillingstatement.com
    \_ A 74.220.199.6
[*]-Retrieving IP2ASN Information
  \_ 162.219.251.133
    \_ asn_registry arin
    \_ asn_country_code US
    \_ asn_date 2013-08-21
    \_ asn_cidr 162.219.251.0/24
    \_ asn 33494
    \_ asn_description IHNET - IHNetworks, LLC, US
  \_ 74.220.199.6
    \_ asn_registry arin
    \_ asn_country_code US
    \_ asn_date 2007-01-09
    \_ asn_cidr 74.220.192.0/19
    \_ asn 46606
    \_ asn_description UNIFIEDLAYER-AS-1 - Unified Layer, US
[*]-Retrieving WHOIS Information
  \_ paypal-required-action.com
    \_ Created Date 2018-03-29 19:11:32
    \_ Updated Date [datetime.datetime(2018, 3, 29, 19, 11, 32), datetime.datetime(2018, 3, 29, 19, 11, 41)]
    \_ Expiration Date [datetime.datetime(2019, 3, 29, 19, 11, 32), datetime.datetime(2019, 3, 29, 20, 11, 32)]
    \_ DateDiff 3
    \_ Name mario pichardo
    \_ Email domain-abuse@psi-usa.info,pichardomario44@gmail.com
    \_ Registrar PSI-USA, Inc. dba Domain Robot
  \_ paypal-resolvedbillingstatement.com
    \_ Created Date 2018-03-29 23:45:13
    \_ Updated Date 2018-03-29 23:45:14
    \_ Expiration Date 2019-03-29 23:45:13
    \_ DateDiff 2
    \_ Name DOMAIN PRIVACY SERVICE FBO REGISTRANT
    \_ Email abuse@bluehost.com,WHOIS@BLUEHOST.COM
    \_ Registrar FastDomain Inc.
[*]-Retrieving Reverse WHOIS (by Name) Information [Source https://domainbigdata.com]
  \_ mario pichardo
    \_ 3 domain(s) have been created in the past
  \_ DOMAIN PRIVACY SERVICE FBO REGISTRANT
    \_ 200 domain(s) have been created in the past
[*]-Retrieving Certficates [Source https://crt.sh]
  \_ paypal-resolvedbillingstatement.com
    \_ No CERT found
  \_ paypal-required-action.com
    \_ not_after 2018-06-28T23:59:59
    \_ min_entry_timestamp 2018-03-30T07:07:18.128
    \_ min_cert_id 370495406
    \_ issuer_ca_id 12922
    \_ name_value mail.paypal-required-action.com
    \_ issuer_name C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    \_ not_before 2018-03-30T00:00:00
    \_ not_after 2018-06-28T23:59:59
    \_ min_entry_timestamp 2018-03-30T07:07:18.128
    \_ min_cert_id 370495406
    \_ issuer_ca_id 12922
    \_ name_value www.paypal-required-action.com
    \_ issuer_name C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    \_ not_before 2018-03-30T00:00:00
[*]-Retrieving VirusTotal Information
  \_ paypal-required-action.com
    \_ Detected URLs
      \_ http://paypal-required-action.com/signin/?country.x=&amp;locale.x=en_EN 10 / 68 2018-03-30 13:04:22
      \_ http://paypal-required-action.com/signin/?country.x=&locale.x=it_IT 10 / 67 2018-03-30 12:39:00
      \_ http://paypal-required-action.com/signin/?country.x=&amp;locale.x=it_IT 10 / 67 2018-03-30 12:37:59
      \_ http://paypal-required-action.com/signin 9 / 67 2018-03-30 12:22:42
      \_ http://paypal-required-action.com/signin/ 8 / 68 2018-03-30 10:30:01
      \_ https://paypal-required-action.com/ 1 / 67 2018-03-30 08:03:02
    \_ Detected Download Samples
      \_ 2018-03-30 13:12:15 2 / 59 84d698d294b28a3ea1413c162e23f28e42a7a6c49669004e67dcf01867b5e7f4
      \_ 2018-03-30 12:46:13 2 / 59 91b9a986026cc24bd46a3a9c868606b47164554f87c8f03e2f9725bfc29b52fb
      \_ 2018-03-30 12:45:19 2 / 59 3aab8ffed0e0aec6f2551170c72f8fb4bb4a82891efdb16df14b25fd96dee52e
    \_ categories
      \_ dynamic content
    \_ Subdomains
      \_ www.paypal-required-action.com
      \_ mail.paypal-required-action.com
    \_ Resolutions (PDNS)
      \_ 2018-03-30 00:00:00 162.219.251.133
  \_ paypal-resolvedbillingstatement.com
    \_ Domain not found
[*]-Check domains against QUAD9 service
  \_ paypal-required-action.com
    \_ Blocked
  \_ paypal-resolvedbillingstatement.com
    \_ Not Blocled
[*]-Calculate Shannon Entropy Information
  \_ paypal-required-action.com 3.97909789113
  \_ paypal-resolvedbillingstatement.com 4.05757515968
[*]-Calculate Levenshtein Ratio
  \_ paypal-required-action vs paypal 0.428571428571
  \_ paypal-resolvedbillingstatement vs paypal 0.324324324324
```
## Similar projects

* [**dnstiwst**](https://github.com/elceef/dnstwist)
* [**phishing catcher**](https://github.com/x0rz/phishing_catcher)

