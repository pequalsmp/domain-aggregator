#!/bin/sh

# force sorting to be byte-wise
export LC_ALL="C"

# add user-agent as some websites refuse connection if the UA is cURL
# follow redirects
# don't print out anything (silent)
# use compression (when available/possible)
# don't use keepalive (there's not reason for it, as we're closing the connection as soon as we download the file)
# retry 5 times with 30s delay inbetween
alias curl='curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36" -L -s --compressed --no-keepalive --retry 5 --retry-delay 30'
# force grep to work with text in order to avoid some files being treated as binaries
alias grep='grep --text'

# description / options for this script
HELP_TXT="$(basename "$0") [-h] [-o /<path>] [-t /<path>] [-b /<path>] [-w /<path>]

fetch and concatenate/clean a list of potentially unwanted domains

options:
    -h  show this help text
    -o  path for the output file
    -t  path to a directory, to be used as storage for temporary files
        default: /tmp
    -b  path to a list of domains to block
    -w  path to a list of domains to whitelist"

# fetch abuse.ch ransomware tracker feed
# and extract hosts
fetch_abuse_ch_feed() {
    while test $# -gt 0
    do
        TARGET=$(readlink -m "$TEMP_DIR/sources/$(echo "$1" | md5sum - | cut -c 1-32)")
        
        curl -o $TARGET -z $TARGET -k "$1"

        CONTENTS=$(
            # fetch the contents
            cat "$TARGET" |\
            # remove all comments
            sed '/^#/ d' |\
            # get the 4th column - host
            awk -F '"*,"*' '{print $4}'
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
        TARGET=$(readlink -m "$TEMP_DIR/sources/$(echo "$1" | md5sum - | cut -c 1-32)")
        
        curl -o $TARGET -z $TARGET -k "$1"

        CONTENTS=$(
            # fetch the contents
            cat "$TARGET" |\
            # remove all comments
            grep -v '!' |\
            # remove all exceptions
            grep -v '@@' |\
            # remove url arg
            grep -v '?' |\
            # remove wildcard selectors
            grep -v '*' |\
            # match only the beginning of an address
            grep '||'
        )

        # save the contents to a temporary file
        echo "$CONTENTS" > "$TEMP_DIR/$(($(date +%s%N)/1000000)).temporary"

        shift
    done
}

# fetch csv list
# - c2-dommasterlist.txt
fetch_bambenek_c2() {
    while test $# -gt 0
    do
        TARGET=$(readlink -m "$TEMP_DIR/sources/$(echo "$1" | md5sum - | cut -c 1-32)")
        
        curl -o $TARGET -z $TARGET -k "$1"

        CONTENTS=$(
            # fetch the contents
            cat "$TARGET" |\
            # grab the domains only
            awk -F ',' '{print $1}' |\
            # remove all comments
            sed '/^#/ d'
        )

        # save the contents to a temporary file
        echo "$CONTENTS" > "$TEMP_DIR/$(($(date +%s%N)/1000000)).temporary"

        shift
    done
}

# fetch gzipped DGA feed
# - dga_feed.gz
fetch_bambenek_dga() {
    while test $# -gt 0
    do
        TARGET=$(readlink -m "$TEMP_DIR/sources/$(echo "$1" | md5sum - | cut -c 1-32)")
        
        curl -o $TARGET -z $TARGET -k "$1"

        CONTENTS=$(
            # inflate
            gzip -c -d "$TARGET" |\
            # grab the domains only
            awk -F ',' '{print $1}' |\
            # remove all comments
            sed '/^#/ d'
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
        TARGET=$(readlink -m "$TEMP_DIR/sources/$(echo "$1" | md5sum - | cut -c 1-32)")
        
        curl -o $TARGET -z $TARGET -k "$1"

        CONTENTS=$(
            # fetch the contents
            cat "$TARGET" |\
            # remove line comments and preserve the domains
            sed -e 's/#.*$//' -e '/^$/d' |\
            # remove all comments
            grep -v '#'
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
        TARGET=$(readlink -m "$TEMP_DIR/sources/$(echo "$1" | md5sum - | cut -c 1-32)")
        
        curl -o $TARGET -z $TARGET -k "$1"

        CONTENTS=$(
            # fetch the contents
            cat "$TARGET" |\
            # remove all comments
            grep -v '#' |\
            # remove all ipv4 addresses in format:
            # - 127.0.0.1<TAB>
            sed -e 's/127.0.0.1\x09//g' |\
            # remove all ipv4 addresses in format:
            # - 0.0.0.0<SPACE>
            sed -e 's/0.0.0.0\x20//g' |\
            # remove all ipv6 addresses in format:
            # - ::<SPACE>
            sed -e 's/\:\:\x20//g'
        )

        # save the contents to a temporary file
        echo "$CONTENTS" > "$TEMP_DIR/$(($(date +%s%N)/1000000)).temporary"

        shift
    done
}

# fetch gzipped Phishtank feed
# - verified_online.csv.gz
fetch_phishtank_gz() {
    while test $# -gt 0
    do
        TARGET=$(readlink -m "$TEMP_DIR/sources/$(echo "$1" | md5sum - | cut -c 1-32)")

        curl -o $TARGET -z $TARGET -k "$1"
        
        CONTENTS=$(
            # inflate
            gzip -c -d $TARGET |\
            # grab the urls
            awk -F ',' '{print $2}' |\
            # grab the domain from an entry with/without url scheme
            awk -F '/' '{ if ($0~"(http|https)://") {print $3} else {print $1} }' |\
            # strip malformed urls
            sed -e 's/\?.*$//g'
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
        TARGET=$(readlink -m "$TEMP_DIR/sources/$(echo "$1" | md5sum - | cut -c 1-32)")
        
        curl -o $TARGET -z $TARGET -k "$1"

        CONTENTS=$(
            # fetch the contents
            cat "$TARGET" |\
            # remove all comments
            sed '/^#/ d' |\
            # grab the domain from an entry with/without url scheme
            awk -F '/' '{ if ($0~"(http|https)://") {print $3} else {print $1} }'
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
    grep -v '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$' |\
    # remove port left-overs
    awk -F ':' '{print $1}' |\
    # remove invalid domain names
    grep '\.' |\
    # remove the start match and separator symbols
    sed -e 's/||//g' -e 's/\^//g' |\
    # remove "dirty" urls
    sed -e 's/\///g' |\
    # remove malformed url args
    awk -F '?' '{print $1}' |\
    # remove space/tab from at the EoL
    sed 's/[[:blank:]]*$//' |\
    # remove empty lines
    sed '/^$/d' |\
    # convert <CRLF> to <LF>
    sed 's/\x0d//' |\
    # sort (and remove duplicates) entries
    sort -u |\
    # remove all white-listed domains
    grep -Evf $WHITELIST
}

# remove the left-over temporary files
clean_temporary_files() {
    # remove the temporary files
    rm -rf $TEMP_DIR/*.temporary
}

# helper - warn if something is missing
cmd_exists() {
    while test $# -gt 0
    do
        if ! command -v "$1" >/dev/null 2>&1; then
            return 1
        fi
        shift
    done
}

if ! cmd_exists "awk" "cat" "curl" "cut" "date" "grep" "gzip" "md5sum" "mkdir" "readlink" "sed" "sort" "rm"; then
    echo 'Missing dependency, please make sure: awk, cat, curl, cut, date, echo, grep, gzip, md5sum, mkdir, readlink, sed, sort and rm are installed and functional.'
    exit 1
fi

while getopts "ho:b:t:w:" opt; do
  case $opt in
    b)  BLOCKLIST="$OPTARG"
        ;;
    h)  echo "$HELP_TXT"
        exit 1
        ;;
    o)  OUT_FILE="$OPTARG"
        ;;
    t)  TEMP_DIR="$OPTARG"
        ;;
    w)  WHITELIST="$OPTARG"
        ;;
    \?) echo "Invalid option -$OPTARG" >&2
        exit 1
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

if [ "$BLOCKLIST" ]; then
    cp "$BLOCKLIST" "$TEMP_DIR/blocklist.temporary"
fi

if [ -z "$WHITELIST" ]; then
    WHITELIST="/dev/null"
fi

mkdir -p "$TEMP_DIR/sources"

echo "[*] updating adguard domain list..."
fetch_ad_block_rules \
    "https://adguard.com/en/filter-rules.html?id=15"

echo "[*] updating abuse.ch lists..."
fetch_domains_comments \
    "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt" \
    "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist"
fetch_url_hosts \
    "https://urlhaus.abuse.ch/downloads/text/"

echo "[*] updating abuse.ch ransomware feed..."
fetch_abuse_ch_feed \
    "https://ransomwaretracker.abuse.ch/feeds/csv/"

echo "[*] updating anudeepnd list..."
fetch_hosts \
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt"

echo "[*] updating bambenek c2 list..."
fetch_bambenek_c2 \
    "https://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt"

echo "[*] updating bambenek dga feed..."
fetch_bambenek_dga \
    "https://osint.bambenekconsulting.com/feeds/dga-feed.gz"

echo "[*] updating bbcan177 ms2 list..."
fetch_domains_comments \
    "https://gist.githubusercontent.com/BBcan177/4a8bf37c131be4803cb2/raw/"

echo "[*] updating coinblocker browser list..."
fetch_domains_comments \
    "https://zerodot1.gitlab.io/CoinBlockerLists/list.txt"

echo "[*] updating cybercrime lists..."
fetch_url_hosts \
    "https://cybercrime-tracker.net/all.php" \
    "https://cybercrime-tracker.net/ccamgate.php"

echo "[*] updating disconnect lists..."
fetch_domains_comments \
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt" \
    "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt" \
    "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt" \
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt"

echo "[*] updating firebog lists..."
fetch_domains_comments \
    "https://v.firebog.net/hosts/Airelle-trc.txt" \
    "https://v.firebog.net/hosts/BillStearns.txt" \
    "https://v.firebog.net/hosts/Easyprivacy.txt" \
    "https://v.firebog.net/hosts/Prigent-Ads.txt" \
    "https://v.firebog.net/hosts/Prigent-Malware.txt" \
    "https://v.firebog.net/hosts/Prigent-Phishing.txt" \
    "https://v.firebog.net/hosts/Shalla-mal.txt" \
    "https://v.firebog.net/hosts/static/w3kbl.txt"

# WARNING: the list contains parsing fragments
echo "[*] updating horus phishing list..."
fetch_domains_comments \
    "https://raw.githubusercontent.com/HorusTeknoloji/TR-PhishingList/master/url-lists.txt"

# info: https://hosts-file.net/?s=classifications
echo "[*] updating hosts-file lists..."
fetch_hosts \
    "https://hosts-file.net/ad_servers.txt" \
    "https://hosts-file.net/emd.txt" \
    "https://hosts-file.net/exp.txt" \
    "https://hosts-file.net/fsa.txt" \
    "https://hosts-file.net/grm.txt" \
    "https://hosts-file.net/hjk.txt" \
    "https://hosts-file.net/mmt.txt" \
    "https://hosts-file.net/pha.txt" \
    "https://hosts-file.net/psh.txt" \
    "https://hosts-file.net/pup.txt"

echo "[*] updating malwaredomains list..."
fetch_domains_comments \
    "https://malwaredomains.usu.edu/justdomains"

echo "[*] updating malwaredomains immortal list..."
fetch_domains_comments \
    "https://malwaredomains.usu.edu/immortal_domains.txt"

echo "[*] updating notracking feed..."
fetch_hosts \
    "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt"

# WARNING: can cause false-positives
echo "[*] updating openphish feed..."
fetch_url_hosts \
    "https://openphish.com/feed.txt"

# WARNING: will cause false-positives
echo "[*] updating phishtank feed..."
fetch_phishtank_gz \
    "https://data.phishtank.com/data/online-valid.csv.gz"

echo "[*] updating pgl ad servers..."
fetch_domains_comments \
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml"

echo "[*] updating perflyst android list..."
fetch_domains_comments \
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt"

echo "[*] updating phishing army list..."
fetch_domains_comments \
    "https://phishing.army/download/phishing_army_blocklist_extended.txt"

echo "[*] updating piwik referrer spam list..."
fetch_domains_comments \
    "https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt"

echo "[*] updating quidsup lists..."
fetch_domains_comments \
    "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt" \
    "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt"

# info: https://isc.sans.edu/suspicious_domains.html
echo "[*] updating sans feed..."
fetch_domains_comments \
    "https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt"

echo "[*] updating sb lists..."
fetch_hosts \
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts" \
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Dead/hosts" \
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts" \
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts" \
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/SpotifyAds/hosts" \
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts" \
    "https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts"

echo "[*] updating squidblacklist lists..."
fetch_domains_comments \
    "https://www.squidblacklist.org/downloads/dg-ads.acl" \
    "https://www.squidblacklist.org/downloads/dg-malicious.acl"

# WARNING: THIS IS BEING TRANSMITTED OVER HTTP
echo "[*] updating vxvault list..."
fetch_url_hosts \
    "http://vxvault.net/URL_List.php"

echo "[*] updating web-to-onion lists..."
fetch_domains_comments \
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/onion.txt" \
    "https://raw.githubusercontent.com/keithmccammon/tor2web-domains/master/tor2web-domains.txt" \
    "https://raw.githubusercontent.com/WalnutATiie/google_search/master/resourcefile/keywords_google.txt"

echo "[*] updating WindowsSpyBlocker list..."
fetch_hosts \
    "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt"

sanitize_domain_list > $OUT_FILE

clean_temporary_files
