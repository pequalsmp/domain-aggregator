Intro
-

This is a simple shell script, utilizing coreutils to aggregate domain blacklists from various sources.

Why Shell
-

The tools used here are readily available, simple to use and they actually get the job done. The main objective was to have a portable script, working with what's already present.

Usage
-

Copy `domain-aggregator.sh`, make sure its executable (`chmod +x`) and set the parameters, according to your needs.

```sh
./domain-aggregator.sh -b /tmp/blacklist -o /tmp/list -t /tmp/ -w /tmp/whitelist
```

- `- b`
    
    Path to the blacklist file

    _Note: You can use this to add domains to the list without having to host / rewrite lists._
- `- o`
    
    Path to the output file

- `- t`
    
    To reduce memory usage, we're writing the files directly to disk, so this is the path to the folder, where `.temporary` files are stored during list generation.
- `- w`
    
    Path to the whitelist file
    
    _Note: You can use this file to remove domains from the output file. Sometimes (often) lists contain false-positives._

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

- Check your sources, a lot of sources put random domains and do not verify the content resulting in a lot of false-positives
- Use a RAM-disk (`tmpfs`) to `temporary` files, when using flash storage
- Make sure your filtering application can handle large lists. The default setup generates a blacklist with more than a million domains.
- Its a good idea to white-list all the domains associated with fetching blacklists as some sources may blacklist other sources.