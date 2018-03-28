# Hunting-Newly-Registered-Domains
Hunting Newly Registered Domains

The `hnrd.py` is a python utility for finding and analysing potential phishing domains used in phishing campaigns targeting your customers. This utility is written in python 2.7 and is based on the analysis of the features below by consuming a free daily list provided by the [Whoisds](https://whoisds.com/newly-registered-domains) site. 

## Features

* Download a free list from [Whoisds](https://whoisds.com/newly-registered-domains)
* Bitsquatting, hyphenation & domain permutation is used for the transformation of the given keyword
* Generated words are searched/matched againsts the list
* Retrieve `A` DNS Record(s) Information
* Retrieve IP2ASN Information
* Retrieve WHOIS Information
* [Retrieve Reverse WHOIS (by Name) Information](https://domainbigdata.com)
* [Retrieve Certficates](https://crt.sh)
* Retirieve VirusTotal Information
* Calculate Shannon Entropy Information

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

## Help

```
usage: hnrd.py [-h] -f DATE -s SEARCH [-v]

hunting newly registered domain

optional arguments:
  -h, --help  show this help message and exit
  -f DATE     date [format: year-month-date]
  -s SEARCH   search a keyword
  -v          show program's version number and exit
```

### Example

`python hnrd.py -f 2018-03-27 -s twitter`

```
[*]-Retrieving A DNS Record(s) Information
  \_ twitter-2020.com 173.208.193.186
  \_ twitter-2030.com 173.208.193.186
  \_ twitterverifiedwelcome.com None
  \_ tuwitter.info 133.130.112.25
  \_ twitter-url.com None
  \_ twitterenglish.com None
[*]-Retrieving IP2ASN Information
  \_ 173.208.193.186
    \_ asn_registry arin
    \_ asn_country_code US
    \_ asn_date 2009-12-17
    \_ asn_cidr 173.208.128.0/17
    \_ asn 32097
    \_ asn_description WII-KC - WholeSale Internet, Inc., US
  \_ 133.130.112.25
    \_ asn_registry apnic
    \_ asn_country_code JP
    \_ asn_date 1997-03-01
    \_ asn_cidr 133.130.64.0/18
    \_ asn 7506
    \_ asn_description INTERQ GMO Internet,Inc, JP
[*]-Retrieving WHOIS Information
  \_ tuwitter.info
    \_ Created Date 2018-03-27 07:50:18
    \_ Updated Date 2018-03-27 08:58:49
    \_ Expiration Date 2019-03-27 07:50:18
    \_ DateDiff 2
    \_ Name Whois Privacy Protection Service by onamae.com
    \_ Email abuse@gmo.jp,proxy@whoisprotectservice.com
    \_ Registrar GMO Internet, Inc. d/b/a Onamae.com
  \_ twitterenglish.com
    \_ Created Date 2018-03-27 03:23:21
    \_ Updated Date [datetime.datetime(2018, 3, 27, 3, 23, 21), datetime.datetime(2018, 3, 27, 3, 54, 19)]
    \_ Expiration Date 2019-03-27 03:23:21
    \_ DateDiff 2
    \_ Name Domain Admin
    \_ Email abuse@matbao.com,contact@privacyprotect.org
    \_ Registrar MAT BAO CORPORATION
  \_ twitter-2030.com
    \_ Created Date 2018-03-26 17:31:21
    \_ Updated Date 2018-03-26 17:33:53
    \_ Expiration Date 2019-03-26 17:31:21
    \_ DateDiff 3
    \_ Name Mohammed alhila
    \_ Email abuse@name.com,m.iig@hotmail.com
    \_ Registrar Name.com, Inc.
  \_ twitterverifiedwelcome.com
    \_ Created Date 2018-03-26 08:12:06
    \_ Updated Date 2018-03-26 08:12:07
    \_ Expiration Date 2019-03-26 08:12:06
    \_ DateDiff 3
    \_ Name PROXY PROTECTION LLC
    \_ Email W3Q46A8A36WY9XC@PROXY.DREAMHOST.COM,domain-abuse@dreamhost.com
    \_ Registrar DREAMHOST
  \_ twitter-2020.com
    \_ Created Date 2018-03-26 17:31:22
    \_ Updated Date 2018-03-26 17:34:09
    \_ Expiration Date 2019-03-26 17:31:22
    \_ DateDiff 3
    \_ Name Mohammed alhila
    \_ Email abuse@name.com,m.iig@hotmail.com
    \_ Registrar Name.com, Inc.
  \_ twitter-url.com
    \_ Created Date 2018-03-26 07:06:52
    \_ Updated Date 2018-03-26 07:21:04
    \_ Expiration Date 2019-03-26 07:06:52
    \_ DateDiff 3
    \_ Name Ye Jian Hua
    \_ Email DomainAbuse@service.aliyun.com,yuidejjjo@126.com
    \_ Registrar HiChina Zhicheng Technology Ltd.
[*]-Retrieving Reverse WHOIS (by Name) Information [Source https://domainbigdata.com]
  \_ Ye Jian Hua
    \_ 136 domain(s) have been created in the past
  \_ Mohammed alhila
    \_ 110 domain(s) have been created in the past
  \_ Mohammed alhila
    \_ 110 domain(s) have been created in the past
  \_ Whois Privacy Protection Service by onamae.com
    \_ 200 domain(s) have been created in the past
  \_ Domain Admin
    \_ 200 domain(s) have been created in the past
  \_ PROXY PROTECTION LLC
    \_ 200 domain(s) have been created in the past
[*]-Retrieving Certficates [Source https://crt.sh]
  \_ tuwitter.info
    \_ No CERT found
  \_ twitterenglish.com
    \_ No CERT found
  \_ twitter-url.com
    \_ No CERT found
  \_ twitter-2030.com
    \_ not_after 2018-06-24T23:59:59
    \_ min_entry_timestamp 2018-03-26T21:55:18.393
    \_ min_cert_id 367016831
    \_ issuer_ca_id 12922
    \_ name_value mail.twitter-2030.com
    \_ issuer_name C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    \_ not_before 2018-03-26T00:00:00
    \_ not_after 2018-06-24T23:59:59
    \_ min_entry_timestamp 2018-03-26T21:55:18.393
    \_ min_cert_id 367016831
    \_ issuer_ca_id 12922
    \_ name_value www.twitter-2030.com
    \_ issuer_name C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    \_ not_before 2018-03-26T00:00:00
  \_ twitterverifiedwelcome.com
    \_ not_after 2018-06-24T07:16:33
    \_ min_entry_timestamp 2018-03-26T08:16:33.376
    \_ min_cert_id 366445375
    \_ issuer_ca_id 16418
    \_ name_value www.twitterverifiedwelcome.com
    \_ issuer_name C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3
    \_ not_before 2018-03-26T07:16:33
  \_ twitter-2020.com
    \_ not_after 2018-06-24T23:59:59
    \_ min_entry_timestamp 2018-03-26T22:17:31.294
    \_ min_cert_id 367040205
    \_ issuer_ca_id 12922
    \_ name_value mail.twitter-2020.com
    \_ issuer_name C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    \_ not_before 2018-03-26T00:00:00
    \_ not_after 2018-06-24T23:59:59
    \_ min_entry_timestamp 2018-03-26T22:17:31.294
    \_ min_cert_id 367040205
    \_ issuer_ca_id 12922
    \_ name_value www.twitter-2020.com
    \_ issuer_name C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    \_ not_before 2018-03-26T00:00:00
[*]-Retrieving VirusTotal Information
  \_ twitter-2030.com
    \_ Domain not found
  \_ twitterverifiedwelcome.com
    \_ Domain not found
  \_ twitter-2020.com
    \_ Domain not found
  \_ twitterenglish.com
    \_ categories
      \_ uncategorized
    \_ Resolutions (PDNS)
      \_ 2016-01-15 00:00:00 125.253.125.67
      \_ 2015-03-06 00:00:00 64.31.42.235
  \_ twitter-url.com
    \_ Resolutions (PDNS)
      \_ 2017-09-01 00:00:00 192.185.241.208
  \_ tuwitter.info
    \_ Domain not found
[*]-Calculate Shannon Entropy Information
  \_ tuwitter.info 3.18083298721
  \_ twitter-2020.com 3.45281953111
  \_ twitter-2030.com 3.57781953111
  \_ twitter-url.com 3.45656476213
  \_ twitterenglish.com 3.68354236243
  \_ twitterverifiedwelcome.com 3.5035391228
```

## Similar projects

* **dnstiwst:** `https://github.com/elceef/dnstwist`
* **phishing catcher:** `https://github.com/x0rz/phishing_catcher` 

