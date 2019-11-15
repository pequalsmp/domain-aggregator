Intro
-

This is a simple shell script, utilizing a subset of `coreutils`, `awk`, `curl`, `gzip`, `jq`, `python3` and `sed` to aggregate domain blocklists from various sources.

Why Shell
-

The tools used here are readily available and simple to use. The main objective of this project is to have a portable script, working with what's (most probably), already available.

Setup
-

Copy `domain-aggregator.sh`, make sure its executable (`chmod +x domain-aggregator.sh`) and set the args, according to your needs.

_Optional_: drop a script (in `/etc/cron.daily`), executing `domain-aggregator.sh`, in order to automate updates

Usage
-

```
domain-aggregator.sh [-h] [-o /<path>] [-t /<path>] [-b /<path>] [-w /<path>]

fetch and concatenate/clean a list of potentially unwanted domains

options:
    -h  show this help text
    -o  path for the output file
    -t  path to a directory, to be used as storage for temporary files
        default: /tmp
    -b  path to a list of domains to block
    -w  path to a list of domains to whitelist
```

How to add new sources
-

Follow the existing setup.

For example `fetch_domains_comments` will fetch generic list and remove comments. While `fetch_hosts` will attempt to fetch and sanitize a commonly-used format - `hosts`.

Keep in mind there's additional processing done in `sanitize_domain_list`

How to remove sources
-

Simply comment the lines related to that list.

For example to disable `adguard`, you can turn:

```sh
echo "[*] update adguard domain list..."

fetch_adblock_rules "<url>"
```

into

```sh
#echo "[*] update adguard domain list..."

#fetch_adblock_rules "<url>"
```

Recommendations
-

- Check your sources. Sources may put unverified domains in their lists, resulting in false-positives (even for popular websites like Dropbox, Instagram, etc.).
- Use a RAM-disk (`tmpfs`) to store `temporary` files when using flash storage.
- Make sure your filtering application can handle large lists. The default setup generates a blocklists with more than a million domains.
- Its a good idea to white-list all the domains associated with fetching blocklists, as some of the sources may block websites hosting other sources.