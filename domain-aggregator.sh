#!/bin/sh

# Hot to run:
# domain-aggregator -o </tmp/output.file> -t </tmp> -b </tmp/blacklist> -w </tmp/whitelist>

# Description:
# Fetch and concatenate/clean a list of potentially unwanted domains

# add user-agent as some websites refuse connection if the UA is cURL
alias curl='curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36" -L -s'
# force grep to work with text in order to avoid some files being treated as binaries
alias grep='grep --text'

# fetch abuse.ch ransomware tracker feed
# and extract hosts
fetch_abuse_ch_feed() {
    while test $# -gt 0
    do
        CONTENTS=$(
            # fetch the contents
            curl "$1" |\
            # remove all comments
            grep -v "#" |\
            # get the 4th column - host
            awk -F "\"*,\"*" '{print $4}'
        )

        # save the contents to a temporary file
        echo "$CONTENTS" > "$TEMP_DIR/$(($(date +%s%N)/1000000)).temporary"

        shift
    done
}

# fetch and clean "ad_block" rules, some rules
# will be dropped as they are dependant on elements
# or URL parts.
# - <!!><domain><^>
fetch_ad_block_rules() {
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
        )

        # save the contents to a temporary file
        echo "$CONTENTS" > "$TEMP_DIR/$(($(date +%s%N)/1000000)).temporary"

        shift
    done
}

# fetch and extract domains from a list with urls
# <http|https://>
# note: URL lists are more prone to false-positives
fetch_url_hosts(){
    while test $# -gt 0
    do
        CONTENTS=$(
            # fetch the contents
            curl "$1" |\
            # get the entry between the 2nd and 3rd slash
            # http|https://<domain>/
            awk -F/ '{print $3}'
        )

        # save the contents to a temporary file
        echo "$CONTENTS" > "$TEMP_DIR/$(($(date +%s%N)/1000000)).temporary"

        shift
    done
}

# clean up/format the domain list for final version
sanitize_domain_list() {
    cat $TEMP_DIR/*.temporary |\
    # remove ips
    grep -v "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" |\
    # remove invalid domain names
    grep "\." |\
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
}

# remove the left-over temporary files
remove_temporary_files() {
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

while getopts ":b:o:t:w:" opt; do
  case $opt in
    b) BLACKLIST="$OPTARG"
    ;;
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

if [ "$BLACKLIST" ]; then
    cp "$BLACKLIST" "$TEMP_DIR/blacklist.temporary"
fi

if [ -z "$WHITELIST" ]; then
    WHITELIST="/dev/null"
fi

echo "[*] updating adguard domain list..."
fetch_ad_block_rules "https://adguard.com/en/filter-rules.html?id=15"

echo "[*] updating abuse.ch lists..."
fetch_domains_comments "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt" "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist" "https://feodotracker.abuse.ch/blocklist/?download=domainblocklist"

echo "[*] updating abuse.ch ransomware feed lists..."
fetch_abuse_ch_feed "https://ransomwaretracker.abuse.ch/feeds/csv/"

echo "[*] updating disconnect lists..."
fetch_domains_comments "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt" "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt" "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt" "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt"

# CAUTION: false-positives
#echo "[*] updating eladkarako ad-hosts..."
#fetch_domains_comments "https://raw.githubusercontent.com/eladkarako/hosts.eladkarako.com/master/_raw__hosts.txt"

# info: https://hosts-file.net/?s=classifications
echo "[*] updating hosts-file lists..."
fetch_hosts "https://hosts-file.net/ad_servers.txt" "https://hosts-file.net/emd.txt" "https://hosts-file.net/exp.txt" "https://hosts-file.net/fsa.txt" "https://hosts-file.net/grm.txt" "https://hosts-file.net/hjk.txt" "https://hosts-file.net/mmt.txt" "https://hosts-file.net/pha.txt" "https://hosts-file.net/psh.txt" "https://hosts-file.net/pup.txt"

echo "[*] updating malwaredomains lists..."
fetch_domains_comments "https://malwaredomains.usu.edu/justdomains"

echo "[*] updating networksec list..."
fetch_domains_comments "http://www.networksec.org/grabbho/block.txt"

# info: https://isc.sans.edu/suspicious_domains.html
echo "[*] updating sans list..."
fetch_domains_comments "https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt"

echo "[*] updating sb's hosts..."
fetch_hosts "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts" "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Dead/hosts" "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts" "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts" "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/SpotifyAds/hosts" "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts" "https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts"

echo "[*] updating quidsup tracking list..."
fetch_domains_comments "https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt"

echo "[*] updating pgl's ad servers..."
fetch_domains_comments "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml"

echo "[*] updating WindowsSpyBlocker's 7 telemetry list..."
fetch_hosts "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/win7/spy.txt"

echo "[*] updating WindowsSpyBlocker's 8.1 telemetry list..."
fetch_hosts "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/win81/spy.txt"

echo "[*] updating WindowsSpyBlocker's 10 telemetry list..."
fetch_hosts "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/win10/spy.txt"

sanitize_domain_list > $OUT_FILE

remove_temporary_files
