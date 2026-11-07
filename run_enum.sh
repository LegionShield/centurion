#!/bin/bash
# Scarica wordlist e lancia enum su tesla.com
cd /media/sf_centurion

# Scarica una wordlist se non esiste
if [ ! -f wordlist.txt ]; then
    curl -L https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -o wordlist.txt 2>/dev/null
    echo "[+] Wordlist scaricata: $(wc -l < wordlist.txt) entries"
fi

sudo ./centurion enum -d tesla.com -f wordlist.txt -b 10m --timeout 5 --retry 2 -o tesla_results.txt
