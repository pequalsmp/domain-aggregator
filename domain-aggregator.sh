#!/bin/sh

# Hot to run:
# domain-aggregator -o </tmp/output.file> -t </tmp>

# Description:
# Fetch and concatenate/clean a list of potentially unwanted domains

# Notes:
# Blacklist sources: Google, Github

alias curl='curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36" -L -s'

# fetch and clean "adblock" rules, some rules
# will be dropped as they are dependant on elements
# or URL parts.
# - <!!><domain><^>
fetch_adblock_rules() {
    while test $# -gt 0
    do
        CONTENTS=$(
            # fetch the contents
            curl "$1" |\
            # remove all comments
            grep -v "!" |\
            # remove all exceptions
            grep -v "@@" |\
            # remove url arg
            grep -v "?" |\
            # remove wildcard selectors
            grep -v "*" |\
            # match only the beginning of an address
            grep "||"
        )

        # save the contents to a temporary file
        echo "$CONTENTS" > "$TEMP_DIR/$(($(date +%s%N)/1000000)).temporary"

        shift
    done
}

# fetch and clean domain lists with "#" comments, i.e.
# - <domain> #<comment>
# - #<comment>
fetch_domains_comments() {
    while test $# -gt 0
    do
        CONTENTS=$(
            # fetch the contents
            curl "$1" |\
            # remove line comments and preserve the domains
            sed -e 's/#.*$//' -e '/^$/d' |\
            # remove all comments
            grep -v "#"
        )

        # save the contents to a temporary file
        echo "$CONTENTS" > "$TEMP_DIR/$(($(date +%s%N)/1000000)).temporary"

        shift
    done
}

# fetch and clean domain lists with a "hosts" file format
# - <ip><tab|space><domain>
fetch_hosts() {
    while test $# -gt 0
    do
        CONTENTS=$(
            # fetch the contents
            curl "$1" |\
            # remove all comments
            grep -v "#" |\
            # remove all ip addresses in format:
            # - 127.0.0.1<TAB>
            sed -e 's/127.0.0.1\x09//g' |\
            # remove all ip addresses in format:
            # - 0.0.0.0<SPACE>
            sed -e 's/0.0.0.0\x20//g'
            # remove localhost entries
            #grep -v "localhost" |\
            # remove localhost.localdomain entries
            #grep -v "localhost.localdomain" |\
            # remove broadcasthost entries
            #grep -v "broadcasthost"
        )

        # save the contents to a temporary file
        echo "$CONTENTS" > "$TEMP_DIR/$(($(date +%s%N)/1000000)).temporary"

        shift
    done
}

# clean up/format the domain list for final version
domain_cleanup() {
    cat $TEMP_DIR/*.temporary |\
    # remove ips
    grep -v "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" |\
    # remove the start match and separator symbols
    sed -e 's/||//g' -e 's/\^//g' |\
    # remove "dirty" urls
    sed -e 's/\///g' |\
    # remove space/tab from at the EoL
    sed 's/[[:blank:]]*$//' |\
    # remove empty lines
    sed '/^$/d' |\
    # convert <CRLF> to <LF>
    sed 's/\x0d//' |\
    # sort (and remove duplicates) entries
    sort -u |\
    # remove all white-listed domains
    grep -Fvxf $WHITELIST

    # remove the temporary files
    rm -rf $TEMP_DIR/*.temporary
}

# helper - warn if something is not installed
cmd_exists() {
    while test $# -gt 0
    do
        if ! command -v "$1" >/dev/null 2>&1; then
            return 1
        fi
        shift
    done
}

if ! cmd_exists "cat" "curl" "date" "grep" "sed" "sort"; then
    echo 'Missing dependency, please make sure: cat, curl, date, grep, sed and sort are installed and functional.'
    exit 1
fi

while getopts ":o:t:w:" opt; do
  case $opt in
    o) OUT_FILE="$OPTARG"
    ;;
    t) TEMP_DIR="$OPTARG"
    ;;
    w) WHITELIST="$OPTARG"
    ;;
    \?) echo "Invalid option -$OPTARG" >&2
    ;;
  esac
done

if [ -z "$OUT_FILE" ]; then
    echo 'Invalid output file path.'
    exit 1
fi

if [ -z "$TEMP_DIR" ]; then
    TEMP_DIR="/tmp"
fi

if [ -z "$WHITELIST" ]; then
    WHITELIST="/dev/null"
fi

echo "[*] update adguard domain list..."

fetch_adblock_rules "https://adguard.com/en/filter-rules.html?id=15"

echo "[*] update abuse.ch ransomware list..."

fetch_domains_comments "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt"

echo "[*] update disconnect ad list..."

fetch_domains_comments "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt" "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt"

echo "[*] update eladkarako ad-hosts..."

fetch_domains_comments "https://raw.githubusercontent.com/eladkarako/hosts.eladkarako.com/master/_raw__hosts.txt"

echo "[*] update hosts-file lists..."

fetch_hosts "https://hosts-file.net/ad_servers.txt" "https://hosts-file.net/emd.txt" "https://hosts-file.net/exp.txt" "https://hosts-file.net/fsa.txt" "https://hosts-file.net/mmt.txt" "https://hosts-file.net/pha.txt" "https://hosts-file.net/psh.txt" "https://hosts-file.net/pup.txt"

echo "[*] update malwaredomains lists..."

fetch_domains_comments "https://malwaredomains.usu.edu/justdomains"

echo "[*] update sb's hosts..."

fetch_hosts "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts" "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Dead/hosts" "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts" "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts" "https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts" "https://raw.githubusercontent.com/marktron/fakenews/master/fakenews"

echo "[*] update quidsup tracking list..."

fetch_domains_comments "https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt"

echo "[*] update pgl's ad servers..."

fetch_domains_comments "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml"

domain_cleanup > $OUT_FILE