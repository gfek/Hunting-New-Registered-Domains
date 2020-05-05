from setuptools import setup

setup(name='hnrd-tools',
      version='1.0',
      description="A python utility for finding and analysing potential "
                  + "phishing domains used in campaigns.",
      url='https://github.com/gfek/Hunting-New-Registered-Domains',
      author='George Fekkas',
      author_email='',
      license='Apache',
      packages=['hnrd'],
      scripts=['hunt-domains.py'],
      install_requires=[
        'beautifulsoup4==4.6.0',
        'bs4==0.0.1',
        'certifi==2018.1.18',
        'chardet==3.0.4',
        'colorama==0.3.9',
        'dnspython==1.15.0',
        'future==0.16.0',
        'futures>=3.1.1',
        'html5lib==1.0.1',
        'idna==2.6',
        'ipaddr==2.2.0',
        'ipwhois==1.0.0',
        'python-Levenshtein==0.12.0',
        'python-whois==0.6.9',
        'requests==2.18.4',
        'requests-file==1.4.3',
        'six==1.11.0',
        'termcolor==1.1.0',
        'tldextract==2.2.0',
        'urllib3==1.22',
        'webencodings==0.5.1',
      ],
      zip_safe=False)
