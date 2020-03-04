# 2020.02.29 CAA Rechecking Bug scanner
This script will scan a list of hostnames (one per line) and check if their SSL-certificates is going to be revoked due to the [2020-02-29-caa-rechecking-bug](https://community.letsencrypt.org/t/2020-02-29-caa-rechecking-bug/114591)


## How to use

* Check out this repo.
* Download https://d4twhgtvn0ff5.cloudfront.net/caa-rechecking-incident-affected-serials.txt.gz into the repo path.
* Run ```gunzip caa-rechecking-incident-affected-serials.txt.gz```
* Create a list of hostnames/domains you want to check.
* Run ```./check.py <hostnameListFile>```
