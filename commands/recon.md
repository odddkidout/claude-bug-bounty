---
description: Run full recon pipeline on a target — ASN/IP range discovery, subdomain enum, DNS deep dive, WAF detection, live host discovery, URL crawl, Wayback diff, GraphQL extraction, deep JS analysis (hidden endpoints/params/secrets/source maps), directory fuzzing, screenshots, subdomain takeover, cloud asset discovery, GitHub dorking, Shodan/Censys, tech-aware nuclei scan. Outputs to recon/<target>/ directory. Usage: /recon target.com
---

# /recon

Run the full recon pipeline on a target and produce a prioritized attack surface.

## What This Does

1. **Phase 0.5** — ASN / IP range discovery (bgpview.io + RIPE stat)
2. **Phase 1**   — Subdomain enumeration (Chaos API + subfinder + crt.sh + Wayback)
3. **Phase 1.5** — DNS deep dive (MX, TXT, SPF, DMARC, AXFR, wildcard detection)
4. **Phase 2**   — HTTP probing (httpx: status, title, tech, content-length)
5. **Phase 2.5** — WAF detection (wafw00f or header fingerprinting)
6. **Phase 3**   — Port scanning (nmap top 1000)
7. **Phase 4**   — URL collection (gau + Wayback)
8. **Phase 4.5** — Wayback endpoint diff (new vs 12-month-old snapshot)
9. **Phase 4.6** — GraphQL schema extraction + mutation list
10. **Phase 5**  — **Deep JS analysis** (discovery, source maps, hidden endpoints, hidden params, 30+ secret patterns, trufflehog, live API probing)
11. **Phase 6**  — Directory fuzzing (ffuf)
12. **Phase 6.5** — Config file exposure check
13. **Phase 6.6** — Screenshot automation (gowitness)
14. **Phase 7**  — Parameter discovery
15. **Phase 7.5** — Subdomain takeover scanning (subjack + nuclei + CNAME check)
16. **Phase 7.6** — Cloud asset discovery (S3 + Firebase permutation probing)
17. **Phase 7.7** — GitHub dorking (gh CLI + exposed .git)
18. **Phase 7.8** — Shodan / Censys integration (optional, API-key gated)
19. **Phase 8**  — CI/CD workflow scan
20. **Phase 9**  — Tech-aware nuclei scan (base + exposures/ + misconfiguration/ + tech tags)

## Usage

```
/recon target.com
```

Or with specific focus:
```
/recon target.com --focus api
/recon target.com --focus auth
/recon target.com --fast     (skip historical URLs)
```

## Steps

### Step 1: ASN / IP Range Discovery

```bash
TARGET="$1"
mkdir -p recon/$TARGET

# Resolve IP → ASN → all owned CIDRs
TARGET_IP=$(dig +short $TARGET | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
curl -s "https://api.bgpview.io/ip/$TARGET_IP" | jq -r '.data.prefixes[].prefix'
# Enriched via RIPE stat: https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS<N>
```

### Step 2: Subdomain Enumeration

```bash
# Chaos API (ProjectDiscovery — most comprehensive)
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r '.[]' > recon/$TARGET/subdomains.txt

# subfinder + crt.sh
subfinder -d $TARGET -silent | anew recon/$TARGET/subdomains.txt
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | anew recon/$TARGET/subdomains.txt

echo "[+] Subdomains: $(wc -l < recon/$TARGET/subdomains.txt)"
```

### Step 3: DNS Deep Dive

```bash
# MX, TXT, SPF, DMARC
dig +noall +answer MX $TARGET
dig +noall +answer TXT $TARGET
dig +noall +answer TXT _dmarc.$TARGET

# Zone transfer attempt (AXFR)
for ns in $(dig +short NS $TARGET); do dig axfr $TARGET @$ns; done

# Wildcard detection
dig +short "nonexistent-$(date +%s).$TARGET"  # should return nothing
```

### Step 4: Live Host Discovery

```bash
cat recon/$TARGET/subdomains.txt \
  | httpx -silent -status-code -title -tech-detect \
  | tee recon/$TARGET/live-hosts.txt

echo "[+] Live hosts: $(wc -l < recon/$TARGET/live-hosts.txt)"
```

### Step 5: URL Crawl + Wayback Diff

```bash
# Active crawl
cat recon/$TARGET/live-hosts.txt | awk '{print $1}' \
  | katana -d 3 -jc -kf all -silent \
  | anew recon/$TARGET/urls.txt

# Historical URLs
echo $TARGET | gau --subs | anew recon/$TARGET/urls.txt

# Wayback diff: find newly-deployed endpoints
DATE_OLD=$(date -d "12 months ago" +%Y%m%d)
DATE_MID=$(date -d "6 months ago" +%Y%m%d)
curl -s "https://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&from=${DATE_OLD}&to=${DATE_MID}&output=text&fl=original&collapse=urlkey" \
  > recon/$TARGET/urls_old.txt
comm -23 <(grep '?' recon/$TARGET/urls.txt | sort -u) \
         <(grep '?' recon/$TARGET/urls_old.txt | sort -u) \
  > recon/$TARGET/new_endpoints.txt
echo "[+] New (recently deployed) endpoints: $(wc -l < recon/$TARGET/new_endpoints.txt)"
```

### Step 6: GraphQL Schema Extraction

```bash
# Try introspection on discovered GraphQL endpoints
for ep in $(grep -iE '/graphql|/gql' recon/$TARGET/urls.txt | sort -u); do
  curl -s -X POST $ep -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { types { name } mutationType { name } } }"}' \
    | python3 -c "import sys,json; d=json.load(sys.stdin); [print(t['name']) for t in d.get('data',{}).get('__schema',{}).get('types',[])]"
done
```

### Step 7: Deep JS Analysis

```bash
# Discover JS files from live hosts (katana picks up dynamically loaded bundles)
katana -list recon/$TARGET/live-hosts.txt -jc -d 2 -silent -extension-match js \
  > recon/$TARGET/js/all_js_urls.txt

# Download JS files
head -100 recon/$TARGET/js/all_js_urls.txt | while read url; do
  SAFE=$(echo $url | md5sum | awk '{print $1}')
  curl -s --max-time 15 -A "Mozilla/5.0" "$url" > recon/$TARGET/js/downloaded/${SAFE}.js
done

# Check for source maps (unminified source!)
cat recon/$TARGET/js/all_js_urls.txt | while read url; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${url}.map")
  [ "$STATUS" = "200" ] && echo "[SOURCE MAP EXPOSED] ${url}.map"
done

# Hidden endpoint extraction (Python deep scan in recon_engine.sh)
# Hidden parameter extraction from fetch/XHR/FormData patterns
# Secret scanning with 30+ patterns (AWS, GCP, GitHub, Slack, Stripe, JWT, etc.)
# trufflehog --only-verified on downloaded JS directory
```

### Step 8: Classify URLs

```bash
cat recon/$TARGET/urls.txt | gf xss       > recon/$TARGET/xss-candidates.txt
cat recon/$TARGET/urls.txt | gf ssrf      > recon/$TARGET/ssrf-candidates.txt
cat recon/$TARGET/urls.txt | gf idor      > recon/$TARGET/idor-candidates.txt
cat recon/$TARGET/urls.txt | gf sqli      > recon/$TARGET/sqli-candidates.txt
cat recon/$TARGET/urls.txt | gf redirect  > recon/$TARGET/redirect-candidates.txt
cat recon/$TARGET/urls.txt | gf lfi       > recon/$TARGET/lfi-candidates.txt

cat recon/$TARGET/urls.txt | grep -E "/api/|/v1/|/v2/|/graphql|/rest/" \
  > recon/$TARGET/api-endpoints.txt
```

### Step 9: Subdomain Takeover + Cloud + GitHub

```bash
# Subdomain takeover (dangling CNAME check)
subjack -w recon/$TARGET/subdomains.txt -t 20 -timeout 30 -ssl -o recon/$TARGET/takeover/subjack.txt
nuclei -l recon/$TARGET/live-hosts.txt -t takeovers/ -silent

# Cloud asset discovery (S3 + Firebase)
ORG=$(echo $TARGET | sed 's/\..*//')
curl -s -o /dev/null -w "%{http_code}" https://${ORG}.s3.amazonaws.com  # 200=public, 403=exists
curl -s https://${ORG}.firebaseio.com/.json | head -100

# Exposed .git
while read url; do
  [ "$(curl -so /dev/null -w '%{http_code}' ${url}/.git/HEAD)" = "200" ] && echo "EXPOSED: ${url}/.git"
done < recon/$TARGET/live-hosts.txt

# GitHub dorking
gh search code "api_key" --owner "$ORG" --json path,repository
gh search code "password" --owner "$ORG" --json path,repository
```

### Step 10: Tech-Aware Nuclei Scan

```bash
# Extract tech tags from httpx output
TAGS=$(grep -oE '\[[a-zA-Z0-9,]+\]' recon/$TARGET/live-hosts.txt | tr -d '[]' | tr ',' '\n' | sort -u | tr '\n' ',')

# Base scan
nuclei -l recon/$TARGET/live-hosts.txt -severity critical,high,medium -o recon/$TARGET/nuclei/base.txt

# Exposure + misconfiguration
nuclei -l recon/$TARGET/live-hosts.txt -t exposures/ -o recon/$TARGET/nuclei/exposures.txt
nuclei -l recon/$TARGET/live-hosts.txt -t misconfiguration/ -o recon/$TARGET/nuclei/misconfigs.txt

# Tech-specific (e.g. wordpress,springboot,nginx)
nuclei -l recon/$TARGET/live-hosts.txt -tags "$TAGS" -o recon/$TARGET/nuclei/tech_specific.txt
```

## Output

After running, you will have in `recon/<target>/`:
```
subdomains/all.txt        # All discovered subdomains
asn/cidrs.txt             # Owned IP ranges (ASN-based)
dns/                      # MX, TXT, SPF, DMARC, AXFR results
live/httpx_full.txt       # Live hosts with status/title/tech
live/urls.txt             # Clean URL list
ports/open_ports.txt      # Open ports from nmap
waf/                      # WAF detection results
urls/all.txt              # All crawled URLs
urls/new_endpoints.txt    # Recently deployed endpoints (high priority)
urls/api_endpoints.txt    # API-specific paths
graphql/                  # GraphQL schemas + mutation lists
js/all_js_urls.txt        # All discovered JS file URLs
js/downloaded/            # Downloaded JS bundles (up to 100)
js/source_maps.txt        # Exposed .js.map files (original source!)
js/endpoints.txt          # Hidden endpoints extracted from JS
js/hidden_params.txt      # Hidden parameter names from JS
js/secrets.txt            # Potential secrets (30+ pattern types)
js/trufflehog.json        # Verified secrets (trufflehog)
js/live_endpoints.txt     # JS-discovered API paths that returned live responses
screenshots/              # gowitness screenshots of all live hosts
takeover/                 # Subdomain takeover candidates
cloud/buckets.txt         # S3 / Firebase assets found
github/                   # GitHub dork results + exposed .git dirs
shodan/                   # Shodan/Censys host data (if API key set)
nuclei/all_findings.txt   # All nuclei findings (merged)
```

## What to Do Next

1. Review `js/secrets.txt` and `js/trufflehog.json` — **any verified secrets = instant critical**
2. Review `js/source_maps.txt` — exposed source maps mean you can read original unminified code
3. Check `urls/new_endpoints.txt` — recently deployed features = less reviewed = higher bounty odds
4. Review `nuclei/all_findings.txt` — any critical/high findings?
5. Check `graphql/introspection_enabled.txt` — open introspection = full schema + mutations available
6. Review `takeover/dangling_cnames.txt` — easy wins if any exist
7. Check `cloud/buckets.txt` — public S3 / Firebase = data exposure
8. Review `js/hidden_params.txt` + `js/live_endpoints.txt` — hidden API surface
9. Review `live/httpx_full.txt` — open interesting hosts in browser
10. Run `/hunt target.com` to start active vulnerability testing

## 5-Minute Rule

If after running this pipeline:
- All hosts return 403 or static pages
- No API endpoints visible
- No JavaScript bundles with interesting paths or parameters
- nuclei returns 0 medium/high findings
- No secrets, no source maps, no GraphQL endpoints

**→ Move on to a different target.**
