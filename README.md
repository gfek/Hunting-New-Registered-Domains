# Hunting-New-Registered-Domains
Hunting New Registered Domains

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

`python hnrd.py -f 2018-03-26 -s apple`

```
[*]-Retrieving A DNS Record(s) Information
  \_ appleid-term-updates.com 128.199.151.90
  \_ applaydoratemb.date 195.225.173.217,195.225.173.22
  \_ appleid-apple-locked.support 138.201.34.210
  \_ appleid-apple-locked.net 78.46.58.194
  \_ applefix.online 45.113.122.73
  \_ apple-u.store 89.111.176.241
  \_ aspple.net 185.116.237.132
  \_ appleid-ifneiphone.com None
  \_ appliedgraphicscompany.info 50.63.202.60
  \_ applexus.co.uk 80.231.135.155
  \_ applepot.com 52.0.217.44
  \_ appleproducts.store 199.188.200.123
  \_ appleweb88.com 59.125.33.6
  \_ appleidcs.com 108.187.96.217
  \_ appleidcase.tech None
  \_ appleidcares.com None
  \_ appleidcase.store None
  \_ appnext.ltd None
  \_ apple-supportaccount-verified.com None
  \_ applevalleypetsitting.com 50.22.154.126
  \_ appleids-locked-issue.com 162.214.1.183
  \_ applecase.tech None
  \_ appleserve.store None
  \_ appleserve.tech None
  \_ appleno.party None
  \_ appletherapycenter.com None
  \_ applezee.com None
  \_ appleteraphycenter.com None
  \_ appleidcaser.com None
  \_ apple-supportaccount-verifiedindentity.com None
[*]-Retrieving IP2ASN Information
  \_ 128.199.151.90
    \_ asn_registry ripencc
    \_ asn_country_code GB
    \_ asn_date 1999-04-12
    \_ asn_cidr 128.199.128.0/18
    \_ asn 14061
    \_ asn_description DIGITALOCEAN-ASN - DigitalOcean, LLC, US
  \_ 45.113.122.73
    \_ asn_registry apnic
    \_ asn_country_code IN
    \_ asn_date 2015-03-20
    \_ asn_cidr 45.113.122.0/24
    \_ asn 394695
    \_ asn_description PUBLIC-DOMAIN-REGISTRY - PDR, US
  \_ 89.111.176.241
    \_ asn_registry ripencc
    \_ asn_country_code RU
    \_ asn_date 2006-04-26
    \_ asn_cidr 89.111.176.0/20
    \_ asn 41126
    \_ asn_description CENTROHOST-AS, RU
  \_ 78.46.58.194
    \_ asn_registry ripencc
    \_ asn_country_code DE
    \_ asn_date 2007-04-16
    \_ asn_cidr 78.46.0.0/15
    \_ asn 24940
    \_ asn_description HETZNER-AS, DE
  \_ 185.116.237.132
    \_ asn_registry ripencc
    \_ asn_country_code GB
    \_ asn_date 2015-09-10
    \_ asn_cidr 185.116.237.0/24
    \_ asn 9178
    \_ asn_description DEVCAPSULE, GB
  \_ 195.225.173.217
    \_ asn_registry ripencc
    \_ asn_country_code UA
    \_ asn_date 2004-03-04
    \_ asn_cidr 195.225.172.0/22
    \_ asn 31158
    \_ asn_description ASGARD-AS RadioEthernet provider, UA
  \_ 195.225.173.22
    \_ asn_registry ripencc
    \_ asn_country_code UA
    \_ asn_date 2004-03-04
    \_ asn_cidr 195.225.172.0/22
    \_ asn 31158
    \_ asn_description ASGARD-AS RadioEthernet provider, UA
  \_ 138.201.34.210
    \_ asn_registry ripencc
    \_ asn_country_code DE
    \_ asn_date 1990-05-23
    \_ asn_cidr 138.201.0.0/16
    \_ asn 24940
    \_ asn_description HETZNER-AS, DE
  \_ 50.63.202.60
    \_ asn_registry arin
    \_ asn_country_code US
    \_ asn_date 2011-02-02
    \_ asn_cidr 50.63.202.0/24
    \_ asn 26496
    \_ asn_description AS-26496-GO-DADDY-COM-LLC - GoDaddy.com, LLC, US
  \_ 80.231.135.155
    \_ asn_registry ripencc
    \_ asn_country_code EU
    \_ asn_date 2002-03-20
    \_ asn_cidr 80.231.0.0/16
    \_ asn 6453
    \_ asn_description AS6453 - TATA COMMUNICATIONS (AMERICA) INC, US
  \_ 199.188.200.123
    \_ asn_registry arin
    \_ asn_country_code US
    \_ asn_date 2011-08-03
    \_ asn_cidr 199.188.200.0/24
    \_ asn 22612
    \_ asn_description NAMECHEAP-NET - Namecheap, Inc., US
  \_ 59.125.33.6
    \_ asn_registry apnic
    \_ asn_country_code TW
    \_ asn_date 2005-10-18
    \_ asn_cidr 59.125.0.0/17
    \_ asn 3462
    \_ asn_description HINET Data Communication Business Group, TW
  \_ 52.0.217.44
    \_ asn_registry arin
    \_ asn_country_code US
    \_ asn_date 1991-12-19
    \_ asn_cidr 52.0.0.0/16
    \_ asn 16509
    \_ asn_description AMAZON-02 - Amazon.com, Inc., US
  \_ 50.22.154.126
    \_ asn_registry arin
    \_ asn_country_code US
    \_ asn_date 2010-11-01
    \_ asn_cidr 50.22.128.0/18
    \_ asn 36351
    \_ asn_description SOFTLAYER - SoftLayer Technologies Inc., US
  \_ 162.214.1.183
    \_ asn_registry arin
    \_ asn_country_code US
    \_ asn_date 2013-05-22
    \_ asn_cidr 162.214.0.0/15
    \_ asn 46606
    \_ asn_description UNIFIEDLAYER-AS-1 - Unified Layer, US
  \_ 108.187.96.217
    \_ asn_registry arin
    \_ asn_country_code US
    \_ asn_date 2013-08-16
    \_ asn_cidr 108.187.0.0/16
    \_ asn 15003 395954
    \_ asn_description None
[*]-Retrieving WHOIS Information
Socket Error: [Errno 8] nodename nor servname provided, or not known
Socket Error: [Errno 8] nodename nor servname provided, or not known
Socket Error: [Errno 8] nodename nor servname provided, or not known
Socket Error: Socket Error: [Errno 8] nodename nor servname provided, or not known
Socket Error: [Errno 8] nodename nor servname provided, or not known
[Errno 8] nodename nor servname provided, or not known
  \_  applexus.co.uk
    \_ Created Date 2018-03-23 00:00:00
    \_ DateDiff 5
    \_ Name None
    \_ Email None
Socket Error: [Errno 54] Connection reset by peer
  \_ appliedgraphicscompany.info
    \_ Created Date 2018-03-25 22:42:47
    \_ DateDiff 3
    \_ Name [u'Matt Vassallo', u'******** ******** (see Notes section below on how to view unmasked data)']
    \_ Email abuse@godaddy.com,mmascitto@therhinestoneworld.com
  \_ appleid-term-updates.com
    \_ Created Date 2018-03-25 10:38:01
    \_ DateDiff 3
    \_ Name INES DA SILVA MOREIRA
    \_ Email support@domainbox.com,ambigusajah@outlook.com
  \_ appleno.party
    \_ Created Date 2018-03-25 20:08:27
    \_ DateDiff 3
    \_ Name Bill
    \_ Email abuse@alpnames.com,morensbill@gmail.com
  \_ appleid-apple-locked.support
    \_ Created Date 2018-03-25 04:20:48
    \_ DateDiff 3
    \_ Name Contact Privacy Inc. Customer 1242437870
    \_ Email registrar-abuse@google.com,qefjejofn9tc@contactprivacy.email
  \_  applaydoratemb.date
    \_ Created Date 2018-03-25 09:44:58
    \_ DateDiff 3
    \_ Name Network Division
    \_ Email enhmedtelecom@gmail.com
  \_ applezee.com
    \_ Created Date 2018-03-25 05:09:30
    \_ DateDiff 3
    \_ Name Liu Ke
    \_ Email DomainAbuse@service.aliyun.com,enufengji@126.com
  \_ appleidcs.com
    \_ Created Date 2018-03-26 03:34:43
    \_ DateDiff 2
    \_ Name Qin Hai Bin
    \_ Email DomainAbuse@service.aliyun.com,lihai1809@gmail.com
  \_ aspple.net
    \_ Created Date 2018-03-25 13:28:33
    \_ DateDiff 3
    \_ Name Contact Privacy Inc. Customer 0151061039
    \_ Email aspple.net@contactprivacy.com,domainabuse@tucows.com
  \_ applevalleypetsitting.com
    \_ Created Date 2018-03-26 03:35:03
    \_ DateDiff 2
    \_ Name Jade E Smith
    \_ Email abuse@domainit.com,Jadesmith5011@gmail.com,hostmaster@domainit.com
  \_ applepot.com
    \_ Created Date 2018-03-25 05:14:28
    \_ DateDiff 3
    \_ Name Super Privacy Service c/o Dynadot
    \_ Email abuse@dynadot.com,privacy@dynadot.com
  \_ appleteraphycenter.com
    \_ Created Date 2018-03-25 20:52:07
    \_ DateDiff 3
    \_ Name ozge conway
    \_ Email ozge2512@hotmail.com,abuse@ihs.com.tr
Socket Error: [Errno 54] Connection reset by peer
  \_ appleid-ifneiphone.com
    \_ Created Date 2018-03-25 05:11:40
    \_ DateDiff 3
    \_ Name Zhou WenJie
    \_ Email tld@cndns.com,domain@cndns.com,1377360164@qq.com
  \_ apple-supportaccount-verified.com
    \_ Created Date 2018-03-25 14:22:46
    \_ DateDiff 3
    \_ Name Contact Privacy Inc. Customer 1242438805
    \_ Email registrar-abuse@google.com,chsqrgmjhnk0@contactprivacy.email
  \_ apple-supportaccount-verifiedindentity.com
    \_ Created Date 2018-03-25 14:22:46
    \_ DateDiff 3
    \_ Name Contact Privacy Inc. Customer 1242438804
    \_ Email registrar-abuse@google.com,mgn6ola1wwwd@contactprivacy.email
  \_ appleid-apple-locked.net
    \_ Created Date 2018-03-25 04:20:46
    \_ DateDiff 3
    \_ Name Contact Privacy Inc. Customer 1242437868
    \_ Email registrar-abuse@google.com,vlxo5ncaweg1@contactprivacy.email
  \_ appleweb88.com
    \_ Created Date 2018-03-26 02:58:05
    \_ DateDiff 2
    \_ Name ZIYI CHEN
    \_ Email SEO@APPSEO.COM.TW,abuse@enom.com
  \_ appleserve.tech
    \_ Created Date 2018-03-25 13:36:04
    \_ DateDiff 3
    \_ Name shurong dong
    \_ Email 1194645576@qq.com,domain@sudu.cn
Socket Error: [Errno 54] Connection reset by peer
  \_ appleidcares.com
    \_ Created Date 2018-03-25 13:28:58
    \_ DateDiff 3
    \_ Name shurong dong
    \_ Email abuse@35.cn,domain@sudu.cn,1194645576@qq.com
  \_ appleidcaser.com
    \_ Created Date 2018-03-25 13:29:01
    \_ DateDiff 3
    \_ Name shurong dong
    \_ Email abuse@35.cn,domain@sudu.cn,1194645576@qq.com
  \_ appleids-locked-issue.com
    \_ Created Date 2018-03-25 17:29:16
    \_ DateDiff 3
    \_ Name ADRIAN STOKES
    \_ Email abuse@melbourneit.com.au,wakibatala@ugimail.net
  \_ appletherapycenter.com
    \_ Created Date 2018-03-25 21:21:27
    \_ DateDiff 3
    \_ Name ozge conway
    \_ Email ozge2512@hotmail.com,abuse@ihs.com.tr
  \_ applecase.tech
    \_ Created Date 2018-03-25 13:40:12
    \_ DateDiff 3
    \_ Name shurong dong
    \_ Email 1194645576@qq.com,domain@sudu.cn
  \_ appleidcase.tech
    \_ Created Date 2018-03-25 13:44:05
    \_ DateDiff 3
    \_ Name shurong dong
    \_ Email 1194645576@qq.com,domain@sudu.cn
[*]-Retrieving Reverse WHOIS (by Name) Information [Source https://domainbigdata.com]
  \_ ******** ******** (see Notes section below on how to view unmasked data)
    \_ 0 domain(s) have been created in the past
  \_ Contact Privacy Inc. Customer 1242437868
    \_ 0 domain(s) have been created in the past
  \_ Contact Privacy Inc. Customer 1242437870
    \_ 0 domain(s) have been created in the past
  \_ Contact Privacy Inc. Customer 1242438805
    \_ 0 domain(s) have been created in the past
  \_ Contact Privacy Inc. Customer 0151061039
    \_ 0 domain(s) have been created in the past
  \_ Contact Privacy Inc. Customer 1242438804
    \_ 0 domain(s) have been created in the past
  \_ shurong dong
    \_ 10 domain(s) have been created in the past
  \_ shurong dong
    \_ 10 domain(s) have been created in the past
  \_ shurong dong
    \_ 10 domain(s) have been created in the past
  \_ Jade E Smith
    \_ 0 domain(s) have been created in the past
  \_ shurong dong
    \_ 10 domain(s) have been created in the past
  \_ shurong dong
    \_ 10 domain(s) have been created in the past
  \_ INES DA SILVA MOREIRA
    \_ 8 domain(s) have been created in the past
  \_ Matt Vassallo
    \_ 23 domain(s) have been created in the past
  \_ ZIYI CHEN
    \_ 14 domain(s) have been created in the past
  \_ ozge conway
    \_ 41 domain(s) have been created in the past
  \_ ADRIAN STOKES
    \_ 25 domain(s) have been created in the past
  \_ ozge conway
    \_ 41 domain(s) have been created in the past
  \_ Zhou WenJie
    \_ 109 domain(s) have been created in the past
  \_ Qin Hai Bin
    \_ 115 domain(s) have been created in the past
  \_ Bill
    \_ 200 domain(s) have been created in the past
  \_ Liu Ke
    \_ 200 domain(s) have been created in the past
  \_ Super Privacy Service c/o Dynadot
    \_ 200 domain(s) have been created in the past
[*]-Retrieving Certficates [Source https://crt.sh]
  \_ apple-u.store
    \_ No CERT found
  \_ apple-supportaccount-verifiedindentity.com
    \_ No CERT found
  \_ applaydoratemb.date
    \_ No CERT found
  \_ applecase.tech
    \_ No CERT found
  \_ applefix.online
    \_ No CERT found
  \_ apple-supportaccount-verified.com
    \_ No CERT found
  \_ appleidcase.store
    \_ No CERT found
  \_ appleid-term-updates.com
    \_ No CERT found
  \_ appleid-ifneiphone.com
    \_ No CERT found
  \_ appleidcase.tech
    \_ No CERT found
  \_ appleserve.store
    \_ No CERT found
  \_ appleno.party
    \_ No CERT found
  \_ appleteraphycenter.com
    \_ No CERT found
  \_ applepot.com
    \_ No CERT found
  \_ appleidcs.com
    \_ No CERT found
  \_ appleproducts.store
    \_ No CERT found
  \_ appleidcares.com
    \_ No CERT found
  \_ appletherapycenter.com
    \_ No CERT found
  \_ appleserve.tech
    \_ No CERT found
  \_ appleidcaser.com
    \_ No CERT found
  \_ applevalleypetsitting.com
    \_ No CERT found
  \_ appnext.ltd
    \_ No CERT found
  \_ appliedgraphicscompany.info
    \_ No CERT found
  \_ appleid-apple-locked.support
    \_ not_after 2018-06-24T23:59:59
    \_ min_entry_timestamp 2018-03-26T18:56:56.04
    \_ min_cert_id 366879760
    \_ issuer_ca_id 12922
    \_ name_value www.appleid-apple-locked.support
    \_ issuer_name C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    \_ not_before 2018-03-26T00:00:00
  \_ applexus.co.uk
    \_ No CERT found
  \_ appleids-locked-issue.com
    \_ not_after 2018-06-23T16:34:33
    \_ min_entry_timestamp 2018-03-25T17:34:33.209
    \_ min_cert_id 365763333
    \_ issuer_ca_id 16418
    \_ name_value account.appleids-locked-issue.com
    \_ issuer_name C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3
    \_ not_before 2018-03-25T16:34:33
  \_ appleid-apple-locked.net
    \_ not_after 2018-06-23T23:59:59
    \_ min_entry_timestamp 2018-03-27T00:39:20.844
    \_ min_cert_id 367207776
    \_ issuer_ca_id 12922
    \_ name_value www.appleid-apple-locked.net
    \_ issuer_name C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    \_ not_before 2018-03-25T00:00:00
    \_ not_after 2018-06-24T23:59:59
    \_ min_entry_timestamp 2018-03-26T15:18:33.314
    \_ min_cert_id 366723935
    \_ issuer_ca_id 12922
    \_ name_value www.appleid-apple-locked.net
    \_ issuer_name C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    \_ not_before 2018-03-26T00:00:00
    \_ not_after 2018-06-23T23:59:59
    \_ min_entry_timestamp 2018-03-25T11:12:38.434
    \_ min_cert_id 365523494
    \_ issuer_ca_id 12922
    \_ name_value www.appleid-apple-locked.net
    \_ issuer_name C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    \_ not_before 2018-03-25T00:00:00
    \_ not_after 2018-06-23T23:59:59
    \_ min_entry_timestamp 2018-03-25T04:32:20.842
    \_ min_cert_id 365285273
    \_ issuer_ca_id 12922
    \_ name_value www.appleid-apple-locked.net
    \_ issuer_name C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    \_ not_before 2018-03-25T00:00:00
  \_ aspple.net
    \_ not_after 2018-06-23T13:27:32
    \_ min_entry_timestamp 2018-03-25T14:27:32.302
    \_ min_cert_id 365634306
    \_ issuer_ca_id 16418
    \_ name_value www.aspple.net
    \_ issuer_name C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3
    \_ not_before 2018-03-25T13:27:32
  \_ appleweb88.com
    \_ not_after 2018-06-25T23:59:59
    \_ min_entry_timestamp 2018-03-27T17:56:19.856
    \_ min_cert_id 367892100
    \_ issuer_ca_id 12922
    \_ name_value cpanel.appleweb88.com
    \_ issuer_name C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    \_ not_before 2018-03-27T00:00:00
    \_ not_after 2018-06-25T23:59:59
    \_ min_entry_timestamp 2018-03-27T17:56:19.856
    \_ min_cert_id 367892100
    \_ issuer_ca_id 12922
    \_ name_value mail.appleweb88.com
    \_ issuer_name C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    \_ not_before 2018-03-27T00:00:00
    \_ not_after 2018-06-25T23:59:59
    \_ min_entry_timestamp 2018-03-27T17:56:19.856
    \_ min_cert_id 367892100
    \_ issuer_ca_id 12922
    \_ name_value webdisk.appleweb88.com
    \_ issuer_name C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    \_ not_before 2018-03-27T00:00:00
    \_ not_after 2018-06-25T23:59:59
    \_ min_entry_timestamp 2018-03-27T17:56:19.856
    \_ min_cert_id 367892100
    \_ issuer_ca_id 12922
    \_ name_value webmail.appleweb88.com
    \_ issuer_name C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    \_ not_before 2018-03-27T00:00:00
    \_ not_after 2018-06-25T23:59:59
    \_ min_entry_timestamp 2018-03-27T17:56:19.856
    \_ min_cert_id 367892100
    \_ issuer_ca_id 12922
    \_ name_value www.appleweb88.com
    \_ issuer_name C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    \_ not_before 2018-03-27T00:00:00
  \_ applezee.com
    \_ not_after 2013-03-13T23:59:59
    \_ min_entry_timestamp 2013-05-21T11:21:04.427
    \_ min_cert_id 1990824
    \_ issuer_ca_id 2
    \_ name_value www.applezee.com
    \_ issuer_name C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=PositiveSSL CA 2
    \_ not_before 2012-03-13T00:00:00
[*]-Retrieving VirusTotal Information
  \_ appleid-term-updates.com
    \_ Domain not found
  \_ appleno.party
    \_ Subdomains
      \_ bem86ea6b152f9.appleno.party
  \_ appleid-apple-locked.net
    \_ categories
      \_ uncategorized
    \_ Resolutions (PDNS)
      \_ 2018-03-26 00:00:00 78.46.58.194
  \_ appleidcares.com
    \_ Resolutions (PDNS)
      \_ 2015-07-19 00:00:00 123.1.189.96
  \_ applepot.com
    \_ categories
      \_ parked
      \_ uncategorized
    \_ Resolutions (PDNS)
      \_ 2016-07-11 00:00:00 72.52.4.91
  \_ applevalleypetsitting.com
    \_ Domain not found
  \_ appleid-ifneiphone.com
    \_ Domain not found
  \_ appleids-locked-issue.com
    \_ Detected URLs
      \_ http://appleids-locked-issue.com/ 1 / 67 2018-03-26 08:45:53
    \_ categories
      \_ uncategorized
    \_ Resolutions (PDNS)
      \_ 2018-03-26 00:00:00 162.214.1.183
  \_ appletherapycenter.com
    \_ Domain not found
  \_ applaydoratemb.date
    \_ Domain not found
  \_ appleid-apple-locked.support
    \_ Detected URLs
      \_ https://appleid-apple-locked.support/ 5 / 67 2018-03-27 19:37:25
      \_ https://appleid-apple-locked.support/_ 2 / 67 2018-03-27 15:24:06
    \_ categories
      \_ newly registered websites
    \_ Resolutions (PDNS)
      \_ 2018-03-27 00:00:00 138.201.34.210
  \_ appleidcs.com
  \_ appleproducts.store
    \_ Domain not found
  \_ apple-u.store
    \_ Domain not found
  \_ applezee.com
    \_ Detected URLs
      \_ https://applezee.com/ 1 / 66 2018-01-10 04:30:53
    \_ categories
      \_ business
      \_ uncategorized
    \_ Subdomains
      \_ mail.applezee.com
    \_ Resolutions (PDNS)
      \_ 2016-07-04 00:00:00 192.64.52.88
      \_ 2018-01-10 00:00:00 69.64.147.28
  \_ appleweb88.com
    \_ Domain not found
  \_ appliedgraphicscompany.info
    \_ Domain not found
  \_ appleserve.tech
    \_ Domain not found
  \_ applefix.online
    \_ Detected URLs
      \_ http://applefix.online/ 1 / 68 2016-11-21 15:17:01
    \_ categories
      \_ uncategorized
    \_ Subdomains
      \_ id.applefix.online
      \_ www.applefix.online
    \_ Resolutions (PDNS)
      \_ 2016-11-20 00:00:00 31.31.204.161
      \_ 2018-03-25 00:00:00 45.113.122.73
  \_ applexus.co.uk
    \_ Domain not found
  \_ appleidcase.store
    \_ Domain not found
  \_ apple-supportaccount-verified.com
    \_ Domain not found
  \_ appleidcase.tech
    \_ Domain not found
  \_ appleteraphycenter.com
    \_ Domain not found
  \_ applecase.tech
    \_ Domain not found
  \_ appleserve.store
    \_ Domain not found
  \_ aspple.net
    \_ Domain not found
  \_ appleidcaser.com
    \_ Domain not found
  \_ appnext.ltd
    \_ Domain not found
  \_ apple-supportaccount-verifiedindentity.com
    \_ Domain not found
[*]-Calculate Shannon Entropy Information
  \_ applaydoratemb.date 3.40582225029
  \_ apple-supportaccount-verified.com 4.0060710131
  \_ apple-supportaccount-verifiedindentity.com 4.0526826012
  \_ apple-u.store 3.39274741045
  \_ applecase.tech 3.0391486719
  \_ applefix.online 3.24022392894
  \_ appleid-apple-locked.net 3.47017552146
  \_ appleid-apple-locked.support 3.62808527889
  \_ appleid-ifneiphone.com 3.62921968652
  \_ appleid-term-updates.com 3.77205520887
  \_ appleidcares.com 3.5
  \_ appleidcase.store 3.45482239995
  \_ appleidcase.tech 3.32781953111
  \_ appleidcaser.com 3.5
  \_ appleidcs.com 3.39274741045
  \_ appleids-locked-issue.com 3.7034651896
  \_ appleno.party 3.18083298721
  \_ applepot.com 3.02205520887
  \_ appleproducts.store 3.47135448701
  \_ appleserve.store 3.125
  \_ appleserve.tech 3.24022392894
  \_ appleteraphycenter.com 3.51602764127
  \_ appletherapycenter.com 3.51602764127
  \_ applevalleypetsitting.com 3.72307418943
  \_ appleweb88.com 3.37878349349
  \_ applexus.co.uk 3.37878349349
  \_ applezee.com 3.02205520887
  \_ appliedgraphicscompany.info 3.8841550946
  \_ appnext.ltd 3.095795255
  \_ aspple.net 2.92192809489

```

## Similar projects

* **dnstiwst:** `https://github.com/elceef/dnstwist`
* **phishing catcher:** `https://github.com/x0rz/phishing_catcher` 

