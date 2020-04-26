#!/bin/sh

# force sorting to be byte-wise
export LC_ALL="C"

# cURL setup
#
# use compression
# - DISABLE if you encounter unsupported encoding algorithm
# follow redirects
# don't use keepalive 
# - there's not reason for it, we're closing the connection as soon
# - as we download the file
# try to guess the timestamp of the remote file
# retry 5 times with 30s delay inbetween
# don't print out anything (silent)
# add user-agent
# - some websites refuse the connection if the UA is cURL
alias curl='curl --compressed --location --no-keepalive --remote-time --retry 3 --retry-delay 30 --silent --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"'

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


# fetch and clean "ad_block" rules, some rules
# will be dropped as they are dependant on elements
# or URL parts.
# - <!!><domain><^>
fetch_ad_block_rules() {
    while test $# -gt 0
    do
        TARGET=$(readlink -m "$TEMP_DIR/sources/$(echo "$1" | md5sum - | cut -c 1-32)")

        echo " -- $TARGET - $1"

        curl -o "$TARGET" -z "$TARGET" -k "$1"

        CONTENTS=$(
            # remove all comments
            grep -v -F '!' < "$TARGET" |\
            # remove all exceptions
            grep -v -F '@@' |\
            # remove url arg
            grep -v -F '?' |\
            # remove wildcard selectors
            grep -v -F '*' |\
            # match only the beginning of an address
            grep '||'
        )

        # save the contents to a temporary file
        echo "$CONTENTS" > "$TEMP_DIR/$(($(date +%s%N)/1000000)).temporary"

        shift
    done
}

# fetch and get the domains
# - /feed
fetch_ayashige_feed() {
    while test $# -gt 0
    do
        TARGET=$(readlink -m "$TEMP_DIR/sources/$(echo "$1" | md5sum - | cut -c 1-32)")

        echo " -- $TARGET - $1"

        curl -o "$TARGET" -z "$TARGET" -k "$1"

        CONTENTS=$(
            # use jq to grab all domains
            jq -r '.[].domain' < "$TARGET"
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

        echo " -- $TARGET - $1"

        curl -o "$TARGET" -z "$TARGET" -k "$1"

        CONTENTS=$(
            # grab the domains only
            awk -F ',' '{print $1}' < "$TARGET" |\
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

        echo " -- $TARGET - $1"

        curl -o "$TARGET" -z "$TARGET" -k "$1"

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

        echo " -- $TARGET - $1"

        curl -o "$TARGET" -z "$TARGET" -k "$1"

        CONTENTS=$(
            # remove line comments and preserve the domains
            sed -e 's/#.*$//' -e '/^$/d' < "$TARGET" |\
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

        echo " -- $TARGET - $1"

        curl -o "$TARGET" -z "$TARGET" -k "$1"

        CONTENTS=$(
            # remove all comments
            grep -v '#' < "$TARGET" |\
            # remove all ipv4 addresses in format:
            # - 127.0.0.1<SPACE>
            sed -e 's/127.0.0.1\s//g' |\
            # remove all ipv4 addresses in format:
            # - 0.0.0.0<SPACE>
            sed -e 's/0.0.0.0\s//g' |\
            # remove all ipv6 addresses in format:
            # - ::<SPACE>
            sed -e 's/\:\:\s//g' |\
            # remove all ipv6 addresses in format:
            # - ::1<SPACE>
            sed -e 's/\:\:1\s//g'
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

        echo " -- $TARGET - $1"

        curl -o "$TARGET" -z "$TARGET" -k "$1"
        
        CONTENTS=$(
            # inflate
            gzip -c -d "$TARGET" |\
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

        echo " -- $TARGET - $1"

        curl -o "$TARGET" -z "$TARGET" -k "$1"

        CONTENTS=$(
            # remove all comments
            sed '/^#/ d' < "$TARGET"  |\
            # grab the domain from an entry with/without url scheme
            awk -F '/' '{ if ($0~"(http|https)://") {print $3} else {print $1} }'
        )

        # save the contents to a temporary file
        echo "$CONTENTS" > "$TEMP_DIR/$(($(date +%s%N)/1000000)).temporary"

        shift
    done
}

python_idna_encoder() {
    python3 -c "
import sys;

for line in sys.stdin:
    try:
        print(line.strip().encode('idna').decode('ascii'))
    except:
        pass
"
}

# clean up/format the domain list for final version
sanitize_domain_list() {
    cat "$TEMP_DIR"/*.temporary |\
    # lowercase everything
    awk '{print tolower($0)}' |\
    # remove malformed url args
    awk -F '?' '{print $1}' |\
    # remove "dirty" urls
    awk -F '/' '{print $1}' |\
    # remove port left-overs
    awk -F ':' '{print $1}' |\
    # remove the start match and separator symbols
    sed -e 's/||//g' -e 's/\^//g' |\
    # remove single/double quotes (artifacts from parsing)
    sed -e "s/'/ /g" -e 's/\"//g' |\
    # remove ips
    grep -v '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$' |\
    # remove invalid domain names
    grep '\.' |\
    # filter out sanitize domains according to IDNA RFC
    python_idna_encoder |\
    # sort (and remove duplicates) entries
    sort -u |\
    # remove all white-listed domains
    grep -Evf "$WHITELIST"
}

# remove the left-over temporary files
clean_temporary_files() {
    # remove the temporary files
    rm -rf "$TEMP_DIR"/*.temporary
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

if ! cmd_exists "awk" "cat" "curl" "cut" "date" "grep" "gzip" "jq" "md5sum" "mkdir" "python3" "readlink" "sed" "sort" "rm"; then
    echo 'Missing dependency! Please make sure: awk, coreutils, curl, grep, gzip, jq, python3 and sed are installed and functional.'
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

echo "[*] updating adaway mobile list..."
fetch_hosts \
    "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt"

echo "[*] updating adguard domain list..."
fetch_ad_block_rules \
    "https://adguard.com/en/filter-rules.html?id=15"

echo "[*] updating abuse.ch urlhaus list..."
fetch_url_hosts \
    "https://urlhaus.abuse.ch/downloads/text/"

echo "[*] updating anudeepnd list..."
fetch_hosts \
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt" \
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt"

echo "[*] updating ayashige feed..."
fetch_ayashige_feed \
    "https://ayashige.herokuapp.com/feed"

echo "[*] updating bambenek c2 list..."
fetch_bambenek_c2 \
    "https://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt"

echo "[*] updating bambenek dga feed..."
fetch_bambenek_dga \
    "https://osint.bambenekconsulting.com/feeds/dga-feed.gz"

echo "[*] updating bbcan177 ms2 list..."
fetch_domains_comments \
    "https://gist.githubusercontent.com/BBcan177/4a8bf37c131be4803cb2/raw/"

echo "[*] updating blackjack8 iosad list..."
fetch_domains_comments \
    "https://raw.githubusercontent.com/BlackJack8/iOSAdblockList/master/Hosts.txt"

echo "[*] updating botvrij ioc lists..."
fetch_domains_comments \
    "https://www.botvrij.eu/data/ioclist.domain" \
    "https://www.botvrij.eu/data/ioclist.hostname"

echo "[*] updating cert-pa infosec list..."
fetch_domains_comments \
    "https://infosec.cert-pa.it/analyze/listdomains.txt"

echo "[*] updating coinblocker browser list..."
fetch_domains_comments \
    "https://zerodot1.gitlab.io/CoinBlockerLists/list.txt"

echo "[*] updating crazy-max windows list..."
fetch_hosts \
    "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt"

echo "[*] updating cybercrime-tracker lists..."
fetch_url_hosts \
    "https://cybercrime-tracker.net/all.php" \
    "https://cybercrime-tracker.net/ccamgate.php"

echo "[*] updating datamaster-2501 list..."
fetch_hosts \
    "https://raw.githubusercontent.com/DataMaster-2501/DataMaster-Android-AdBlock-Hosts/master/hosts"

echo "[*] updating energized regional list..."
fetch_domains_comments \
    "https://block.energized.pro/extensions/regional/formats/domains.txt"

echo "[*] updating fademind lists..."
fetch_hosts \
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts" \
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Dead/hosts" \
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts" \
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts" \
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/StreamingAds/hosts" \
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts"

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

echo "[*] updating jakejarvis ios list..."
fetch_ad_block_rules \
    "https://raw.githubusercontent.com/jakejarvis/ios-trackers/master/adguard.txt"

# WARN: this list may contain false-positives
echo "[*] updating lightswitch05 lists..."
fetch_hosts \
    "https://raw.githubusercontent.com/lightswitch05/hosts/master/ads-and-tracking-extended.txt" \
    "https://raw.githubusercontent.com/lightswitch05/hosts/master/tracking-aggressive-extended.txt"

echo "[*] updating malwaredomains list..."
fetch_domains_comments \
    "https://malwaredomains.usu.edu/justdomains"

echo "[*] updating malwaredomains immortal list..."
fetch_domains_comments \
    "https://malwaredomains.usu.edu/immortal_domains.txt"

echo "[*] updating mitchellkrogza list..."
fetch_hosts \
    "https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts"

echo "[*] updating mitchellkrogza phishing.database..."
fetch_domains_comments \
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt" \
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-NEW-today.txt"

echo "[*] updating notracking feed..."
fetch_hosts \
    "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt"

# WARN: the list might contain false-positives
echo "[*] updating openphish feed..."
fetch_url_hosts \
    "https://openphish.com/feed.txt"

echo "[*] updating phishing army list..."
fetch_domains_comments \
    "https://phishing.army/download/phishing_army_blocklist_extended.txt"

# WARN: the list contains false-positives
echo "[*] updating phishtank feed..."
fetch_phishtank_gz \
    "https://data.phishtank.com/data/online-valid.csv.gz"

echo "[*] updating pirat28 ihatetraker list..."
fetch_domains_comments \
    "https://raw.githubusercontent.com/pirat28/IHateTracker/master/iHateTracker.txt"

echo "[*] updating pgl ad servers..."
fetch_domains_comments \
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml"

echo "[*] updating perflyst lists..."
fetch_domains_comments \
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt" \
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt" \
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt"

echo "[*] updating piwik referrer spam list..."
fetch_domains_comments \
    "https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt"

echo "[*] updating quidsup lists..."
fetch_domains_comments \
    "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt" \
    "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt"

# INFO: https://isc.sans.edu/suspicious_domains.html
echo "[*] updating sans feed..."
fetch_domains_comments \
    "https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt"

echo "[*] updating squidblacklist lists..."
fetch_domains_comments \
    "https://www.squidblacklist.org/downloads/dg-ads.acl" \
    "https://www.squidblacklist.org/downloads/dg-malicious.acl"

echo "[*] updating stamparm lists..."
fetch_domains_comments \
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/anonymous_web_proxy.txt" \
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/badwpad.txt" \
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/computrace.txt" \
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/domain.txt" \
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/dynamic_domain.txt" \
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/onion.txt" \
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/pua.txt"

# WARN: this list is being transmitted over http
echo "[*] updating vxvault list..."
fetch_url_hosts \
    "http://vxvault.net/URL_List.php"

echo "[*] updating various web-to-onion lists..."
fetch_domains_comments \
    "https://raw.githubusercontent.com/keithmccammon/tor2web-domains/master/tor2web-domains.txt" \
    "https://raw.githubusercontent.com/WalnutATiie/google_search/master/resourcefile/keywords_google.txt"

# WARN: this list blocks license/activation domains for popular software
echo "[*] updating vokins yhosts list..."
fetch_hosts \
    "https://raw.githubusercontent.com/vokins/yhosts/master/hosts"

echo "[*] updating yhonay antipopads list..."
fetch_hosts \
    "https://raw.githubusercontent.com/Yhonay/antipopads/master/hosts"

sanitize_domain_list > "$OUT_FILE"

clean_temporary_files
