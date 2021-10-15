#! /bin/sh

# Add in paramater the regex that needs to be matched, and insert the script in a crontab.
# For example, to check every day all domains newly registered with the tld .info, write in the crontab (remember to make the script executable):
# 0 0 * * *     /path/to/script/cron.sh ".*\.info$"
now="$(date +'%Y-%m-%d')"
yesterday="$(date -d "$now -1 day" +'%Y-%m-%d')"

python hnrd.py -f $yesterday -r $1
mv domain-names.txt "$yesterday"_domain-names.txt