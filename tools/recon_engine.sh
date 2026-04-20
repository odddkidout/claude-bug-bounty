#!/bin/bash
# =============================================================================
# Enhanced Recon Engine
# Full reconnaissance pipeline for bug bounty targets
# Usage: ./recon_engine.sh <target-domain> [--quick]
# =============================================================================

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_ok()    { echo -e "${GREEN}[+]${NC} $1"; }
log_err()   { echo -e "${RED}[-]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_info()  { echo -e "${CYAN}[*]${NC} $1"; }
log_step()  { echo -e "    ${CYAN}[>]${NC} $1"; }
log_done()  { echo -e "    ${GREEN}[✓]${NC} $1"; }

TARGET="${1:?Usage: $0 <target> [--quick]  (target = FQDN, IP, or CIDR)}"
QUICK_MODE="${2:-}"
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RECON_DIR="${RECON_OUT_DIR:-$BASE_DIR/recon/$TARGET}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
THREADS=20
RATE_LIMIT=50  # requests per second

# Prefer Go tools in ~/go/bin
export PATH="$HOME/go/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

# macOS compatibility: GNU timeout may not exist; use gtimeout or passthrough
if ! command -v timeout &>/dev/null; then
    if command -v gtimeout &>/dev/null; then
        timeout() { gtimeout "$@"; }
        export -f timeout
    else
        timeout() { shift; "$@"; }
        export -f timeout
    fi
fi

# ── Detect target type (passed from hunt.py or auto-detected here) ────────────
_detect_target_type() {
    local t="$1"
    if [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then echo "cidr"
    elif [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]];        then echo "ip"
    else echo "domain"; fi
}

_expand_cidr_hosts() {
    local target="$1"
    python3 - "$target" <<'PY'
import ipaddress
import itertools
import sys

network = ipaddress.ip_network(sys.argv[1], strict=False)
hosts = [str(host) for host in itertools.islice(network.hosts(), 254)]
if not hosts:
    hosts = [str(network.network_address)]
print("\n".join(hosts))
PY
}
TARGET_TYPE="${TARGET_TYPE:-$(_detect_target_type "$TARGET")}"

# For IP/CIDR: always scope-lock — no subdomain enum needed
if [ "$TARGET_TYPE" = "ip" ] || [ "$TARGET_TYPE" = "cidr" ]; then
    SCOPE_LOCK=1
fi

mkdir -p "$RECON_DIR"/{subdomains,live,ports,urls,js,dirs,params,asn,dns,waf,graphql,screenshots,takeover,cloud,github,shodan,nuclei,exposure}

# Safety net: merge partial subdomain results on early exit (watchdog kill, etc.)
_emergency_merge_subs() {
    if [ ! -s "$RECON_DIR/subdomains/all.txt" ] && \
       ls "$RECON_DIR/subdomains/"*.txt &>/dev/null; then
        cat "$RECON_DIR/subdomains/"*.txt 2>/dev/null \
            | tr '[:upper:]' '[:lower:]' \
            | sed 's/^\*\.//' \
            | grep -E "^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$" \
            | sort -u > "$RECON_DIR/subdomains/all.txt" 2>/dev/null || true
    fi
}
trap _emergency_merge_subs EXIT

echo "============================================="
echo "  Recon Engine — $TARGET"
echo "  Output: $RECON_DIR/"
echo "  Mode: $([ "$QUICK_MODE" = "--quick" ] && echo "Quick" || echo "Full")"
echo "  Time: $(date)"
echo "============================================="
echo ""

# ============================================================
# Phase 0.5: ASN / IP Range Discovery
# ============================================================
log_info "Phase 0.5: ASN / IP Range Discovery"

if [ "$TARGET_TYPE" = "domain" ]; then
    TARGET_IP=$(dig +short "$TARGET" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
    if [ -n "$TARGET_IP" ]; then
        log_step "Resolved $TARGET → $TARGET_IP — querying bgpview.io for ASN/CIDRs..."
        ASN_DATA=$(curl -s --max-time 15 "https://api.bgpview.io/ip/$TARGET_IP" 2>/dev/null || true)
        if [ -n "$ASN_DATA" ]; then
            echo "$ASN_DATA" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    asns = set()
    prefixes = []
    for peer in data.get('data', {}).get('prefixes', []):
        asn = peer.get('asn', {}).get('asn', '')
        prefix = peer.get('prefix', '')
        if asn: asns.add(str(asn))
        if prefix: prefixes.append(prefix)
    for a in sorted(asns): print('ASN:', a)
    for p in sorted(set(prefixes)): print('CIDR:', p)
except: pass
" > "$RECON_DIR/asn/asn_info.txt" 2>/dev/null || true
            grep '^CIDR:' "$RECON_DIR/asn/asn_info.txt" 2>/dev/null \
                | awk '{print $2}' > "$RECON_DIR/asn/cidrs.txt" 2>/dev/null || true

            # Enrich via RIPE stat using detected ASN
            ASN_NUM=$(grep '^ASN:' "$RECON_DIR/asn/asn_info.txt" 2>/dev/null | head -1 | awk '{print $2}')
            if [ -n "$ASN_NUM" ]; then
                log_step "Enriching via RIPE stat for AS${ASN_NUM}..."
                curl -s --max-time 15 \
                    "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${ASN_NUM}" 2>/dev/null \
                    | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for p in data.get('data', {}).get('prefixes', []): print(p.get('prefix', ''))
except: pass
" | grep -E '^[0-9]' >> "$RECON_DIR/asn/cidrs.txt" 2>/dev/null || true
                sort -u "$RECON_DIR/asn/cidrs.txt" -o "$RECON_DIR/asn/cidrs.txt" 2>/dev/null || true
            fi
            CIDR_COUNT=$(wc -l < "$RECON_DIR/asn/cidrs.txt" 2>/dev/null || echo 0)
            if [ "$CIDR_COUNT" -gt 0 ]; then
                log_ok "IP ranges found: $CIDR_COUNT CIDRs (AS${ASN_NUM:-?})"
                log_step "CIDRs: $(head -5 "$RECON_DIR/asn/cidrs.txt" | tr '\n' ' ')"
            else
                log_warn "No CIDR data returned for $TARGET_IP"
            fi
        else
            log_warn "bgpview.io returned no data — skipping ASN lookup"
        fi
    else
        log_warn "Could not resolve $TARGET to IP — skipping ASN lookup"
    fi
else
    log_info "IP/CIDR target — skipping ASN lookup"
fi

echo ""

# ============================================================
# Phase 1: Subdomain Enumeration (or Host Discovery for IP/CIDR)
# ============================================================
log_info "Phase 1: Subdomain Enumeration"

# ── For IP / CIDR targets: skip subdomain tools, do host discovery instead ───
if [ "$TARGET_TYPE" = "cidr" ]; then
    log_info "CIDR target — running nmap ping sweep to discover live hosts"
    if command -v nmap &>/dev/null; then
        nmap -sn "$TARGET" -oG - 2>/dev/null \
            | awk '/Up$/{print $2}' \
            > "$RECON_DIR/subdomains/all.txt" || true
        LIVE_COUNT=$(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null || echo 0)
        if [ "$LIVE_COUNT" -eq 0 ]; then
            log_warn "nmap did not identify live hosts — expanding the CIDR locally for downstream probing"
            _expand_cidr_hosts "$TARGET" > "$RECON_DIR/subdomains/all.txt"
        fi
        log_ok "CIDR sweep: $(wc -l < "$RECON_DIR/subdomains/all.txt") live host(s) discovered"
    else
        log_warn "nmap not installed — expanding the CIDR locally for downstream probing"
        _expand_cidr_hosts "$TARGET" > "$RECON_DIR/subdomains/all.txt"
    fi
    # Skip all subdomain enum tools — jump straight to live host probing
elif [ "${SCOPE_LOCK:-0}" = "1" ] && [ "$TARGET_TYPE" = "ip" ]; then
    log_info "Single IP target — skipping subdomain enumeration"
    echo "$TARGET" > "$RECON_DIR/subdomains/all.txt"
else

# Subfinder (passive, fast)
if command -v subfinder &>/dev/null; then
    log_step "Running subfinder..."
    subfinder -d "$TARGET" -silent -all -o "$RECON_DIR/subdomains/subfinder.txt" 2>/dev/null || true
    log_done "subfinder: $(wc -l < "$RECON_DIR/subdomains/subfinder.txt" 2>/dev/null || echo 0) subdomains"
else
    log_warn "subfinder not installed — skipping"
fi

# Amass (passive)
if command -v amass &>/dev/null && [ "$QUICK_MODE" != "--quick" ]; then
    log_step "Running amass (passive, 5min timeout)..."
    timeout 300 amass enum -passive -d "$TARGET" -o "$RECON_DIR/subdomains/amass.txt" 2>/dev/null || true
    # Ensure amass output file exists even if amass failed
    [ ! -f "$RECON_DIR/subdomains/amass.txt" ] && touch "$RECON_DIR/subdomains/amass.txt"
    log_done "amass: $(wc -l < "$RECON_DIR/subdomains/amass.txt" 2>/dev/null || echo 0) subdomains"
else
    [ "$QUICK_MODE" = "--quick" ] && log_warn "Skipping amass (quick mode)"
fi

# crt.sh (certificate transparency)
log_step "Querying crt.sh..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
    | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    names = set()
    for entry in data:
        for name in entry.get('name_value', '').split('\n'):
            name = name.strip().lower()
            if name and '*' not in name and name.endswith('.$TARGET'):
                names.add(name)
            elif name and '*' not in name and '.' in name:
                names.add(name)
    for n in sorted(names):
        print(n)
except: pass
" > "$RECON_DIR/subdomains/crtsh.txt" 2>/dev/null || true
log_done "crt.sh: $(wc -l < "$RECON_DIR/subdomains/crtsh.txt" 2>/dev/null || echo 0) subdomains"

# Wayback subdomains
log_step "Querying Wayback Machine for subdomains..."
curl -s "https://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" 2>/dev/null \
    | sed -nE "s|.*://([a-zA-Z0-9._-]+\.$TARGET).*|\1|p" \
    | sort -u > "$RECON_DIR/subdomains/wayback_subs.txt" 2>/dev/null || true
log_done "wayback: $(wc -l < "$RECON_DIR/subdomains/wayback_subs.txt" 2>/dev/null || echo 0) subdomains"

# Merge and deduplicate all subdomains
cat "$RECON_DIR/subdomains/"*.txt 2>/dev/null | sort -u > "$RECON_DIR/subdomains/all.txt"
TOTAL_SUBS=$(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null || echo 0)
log_ok "Total unique subdomains: $TOTAL_SUBS"

fi  # end of domain-only subdomain enum block

# ============================================================
# Phase 1.5: DNS Record Deep Dive
# ============================================================
echo ""
log_info "Phase 1.5: DNS Record Deep Dive"

if [ "$TARGET_TYPE" = "domain" ]; then
    log_step "Collecting DNS records (MX, TXT, SPF, DMARC)..."
    dig +noall +answer MX  "$TARGET" 2>/dev/null > "$RECON_DIR/dns/mx_records.txt" || true
    dig +noall +answer TXT "$TARGET" 2>/dev/null > "$RECON_DIR/dns/txt_records.txt" || true
    dig +noall +answer TXT "_dmarc.$TARGET" 2>/dev/null > "$RECON_DIR/dns/dmarc.txt" || true

    if grep -qi "spf" "$RECON_DIR/dns/txt_records.txt" 2>/dev/null; then
        log_done "SPF record found"
    else
        log_warn "No SPF record — potential email spoofing vector"
    fi
    if [ -s "$RECON_DIR/dns/dmarc.txt" ]; then
        log_done "DMARC record found"
    else
        log_warn "No DMARC record — email spoofing may be possible"
    fi

    # Zone transfer attempt (AXFR)
    log_step "Attempting DNS zone transfer (AXFR)..."
    NS_LIST=$(dig +short NS "$TARGET" 2>/dev/null | head -3 || true)
    AXFR_SUCCESS=0
    for ns in $NS_LIST; do
        if dig axfr "$TARGET" @"$ns" 2>/dev/null | grep -qE "^$TARGET"; then
            dig axfr "$TARGET" @"$ns" 2>/dev/null > "$RECON_DIR/dns/axfr_${ns%.}.txt" || true
            log_warn "AXFR succeeded on $ns — zone transfer vulnerability!"
            AXFR_SUCCESS=1
        fi
    done
    [ "$AXFR_SUCCESS" -eq 0 ] && log_done "AXFR: all nameservers refused (expected)"

    # DNS wildcard detection (filters false positives from subdomain list)
    log_step "Checking for DNS wildcard..."
    RANDOM_SUB="nonexistent-$(date +%s)-check.$TARGET"
    WILDCARD_IP=$(dig +short "$RANDOM_SUB" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
    if [ -n "$WILDCARD_IP" ]; then
        log_warn "DNS wildcard detected ($RANDOM_SUB → $WILDCARD_IP) — subdomain list may have false positives"
        echo "$WILDCARD_IP" > "$RECON_DIR/dns/wildcard_ip.txt"
    else
        log_done "No DNS wildcard detected"
    fi
else
    log_info "IP/CIDR target — skipping DNS deep dive"
fi

# ============================================================
# Phase 2: HTTP Probing
# ============================================================
echo ""
log_info "Phase 2: HTTP Probing"

if command -v httpx &>/dev/null && [ -s "$RECON_DIR/subdomains/all.txt" ]; then
    log_step "Probing with httpx (status, title, tech, content-length)..."
    httpx -l "$RECON_DIR/subdomains/all.txt" \
        -silent \
        -status-code \
        -title \
        -tech-detect \
        -content-length \
        -follow-redirects \
        -threads "$THREADS" \
        -rate-limit "$RATE_LIMIT" \
        -o "$RECON_DIR/live/httpx_full.txt" 2>/dev/null || true

    # Extract just the URLs for other tools
    awk '{print $1}' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/urls.txt" 2>/dev/null || true

    LIVE_COUNT=$(wc -l < "$RECON_DIR/live/urls.txt" 2>/dev/null || echo 0)
    log_done "Live hosts: $LIVE_COUNT"

    # Separate by status code
    grep '\[200\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_200.txt" 2>/dev/null || true
    grep '\[30[12]\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_3xx.txt" 2>/dev/null || true
    grep '\[403\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_403.txt" 2>/dev/null || true
    grep '\[401\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_401.txt" 2>/dev/null || true

    log_done "200 OK: $(wc -l < "$RECON_DIR/live/status_200.txt" 2>/dev/null || echo 0)"
    log_done "3xx Redirect: $(wc -l < "$RECON_DIR/live/status_3xx.txt" 2>/dev/null || echo 0)"
    log_done "403 Forbidden: $(wc -l < "$RECON_DIR/live/status_403.txt" 2>/dev/null || echo 0)"
    log_done "401 Auth Required: $(wc -l < "$RECON_DIR/live/status_401.txt" 2>/dev/null || echo 0)"
else
    log_warn "httpx not installed or no subdomains found — skipping"
fi

# ============================================================
# Phase 2.5: WAF Detection
# ============================================================
echo ""
log_info "Phase 2.5: WAF Detection"

if [ -s "$RECON_DIR/live/urls.txt" ]; then
    if command -v wafw00f &>/dev/null; then
        log_step "Running wafw00f on live hosts (top 10)..."
        head -10 "$RECON_DIR/live/urls.txt" | while IFS= read -r url; do
            wafw00f "$url" 2>/dev/null \
                | grep -E "(Detected|behind|is behind)" >> "$RECON_DIR/waf/wafw00f.txt" || true
        done
        if [ -s "$RECON_DIR/waf/wafw00f.txt" ]; then
            log_warn "WAF detections: $(wc -l < "$RECON_DIR/waf/wafw00f.txt")"
        else
            log_done "No WAF detected by wafw00f"
        fi
    else
        # Lightweight header-based WAF fingerprinting
        log_step "wafw00f not installed — checking response headers for WAF signatures..."
        head -10 "$RECON_DIR/live/urls.txt" | while IFS= read -r url; do
            HEADERS=$(curl -sI --max-time 8 "$url" 2>/dev/null || true)
            WAF=""
            echo "$HEADERS" | grep -qi "cf-ray\|cloudflare" && WAF="Cloudflare"
            echo "$HEADERS" | grep -qi "x-sucuri-id"        && WAF="Sucuri"
            echo "$HEADERS" | grep -qi "x-fw-server"        && WAF="Fortiweb"
            echo "$HEADERS" | grep -qi "x-iinfo\|incapsula" && WAF="Imperva/Incapsula"
            echo "$HEADERS" | grep -qi "x-cdn.*akamai\|akamai-cache" && WAF="Akamai"
            echo "$HEADERS" | grep -qi "server: awselb\|x-amzn-requestid" && WAF="AWS"
            [ -n "$WAF" ] && echo "$url: $WAF" >> "$RECON_DIR/waf/detected.txt"
        done
        if [ -s "$RECON_DIR/waf/detected.txt" ]; then
            log_warn "WAF detected (header-based): $(cat "$RECON_DIR/waf/detected.txt" | tr '\n' ' ')"
        else
            log_done "No obvious WAF headers detected"
        fi
    fi
else
    log_warn "No live hosts — skipping WAF detection"
fi

# ============================================================
# Phase 3: Port Scanning
# ============================================================
echo ""
log_info "Phase 3: Port Scanning"

if command -v nmap &>/dev/null; then
    log_step "Running nmap (top 1000 ports) on $TARGET..."
    nmap -sV --top-ports 1000 -T4 --open "$TARGET" \
        -oN "$RECON_DIR/ports/nmap_results.txt" \
        -oG "$RECON_DIR/ports/nmap_greppable.txt" 2>/dev/null || true
    log_done "Nmap scan complete"

    # Extract open ports (macOS compatible - no grep -P)
    grep "open" "$RECON_DIR/ports/nmap_greppable.txt" 2>/dev/null \
        | sed -nE 's/.*[^0-9]([0-9]+)\/open.*/\1\/open/p' \
        | sort -u > "$RECON_DIR/ports/open_ports.txt" 2>/dev/null || true
    log_done "Open ports: $(wc -l < "$RECON_DIR/ports/open_ports.txt" 2>/dev/null || echo 0)"
else
    log_warn "nmap not installed — skipping"
fi

# ============================================================
# Phase 4: URL Collection
# ============================================================
echo ""
log_info "Phase 4: URL Collection"

# GAU - Get All URLs (wayback, commoncrawl, otx, urlscan)
if command -v gau &>/dev/null; then
    log_step "Running gau (historical URLs)..."
    echo "$TARGET" | gau --threads 5 --o "$RECON_DIR/urls/gau.txt" 2>/dev/null || \
    echo "$TARGET" | gau > "$RECON_DIR/urls/gau.txt" 2>/dev/null || true
    log_done "gau: $(wc -l < "$RECON_DIR/urls/gau.txt" 2>/dev/null || echo 0) URLs"
else
    log_warn "gau not installed — using wayback fallback"
    curl -s "https://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey&limit=5000" \
        > "$RECON_DIR/urls/wayback.txt" 2>/dev/null || true
    log_done "wayback: $(wc -l < "$RECON_DIR/urls/wayback.txt" 2>/dev/null || echo 0) URLs"
fi

# Merge all collected URLs
cat "$RECON_DIR/urls/"*.txt 2>/dev/null | sort -u > "$RECON_DIR/urls/all.txt" 2>/dev/null || true
log_done "Total unique URLs: $(wc -l < "$RECON_DIR/urls/all.txt" 2>/dev/null || echo 0)"

# Filter interesting URLs
if [ -s "$RECON_DIR/urls/all.txt" ]; then
    # URLs with parameters (potential injection points)
    grep '?' "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/with_params.txt" 2>/dev/null || true
    log_done "URLs with parameters: $(wc -l < "$RECON_DIR/urls/with_params.txt" 2>/dev/null || echo 0)"

    # JS files
    grep -iE '\.js(\?|$)' "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/js_files.txt" 2>/dev/null || true
    log_done "JS files: $(wc -l < "$RECON_DIR/urls/js_files.txt" 2>/dev/null || echo 0)"

    # API endpoints
    grep -iE '(/api/|/v[0-9]+/|/graphql|/rest/)' "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null || true
    log_done "API endpoints: $(wc -l < "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null || echo 0)"

    # Potentially sensitive paths
    grep -iE '\.(env|config|xml|json|yaml|yml|bak|backup|old|orig|sql|db|log|txt|conf|ini|htaccess|htpasswd|git)' \
        "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/sensitive_paths.txt" 2>/dev/null || true
    log_done "Sensitive paths: $(wc -l < "$RECON_DIR/urls/sensitive_paths.txt" 2>/dev/null || echo 0)"
fi

# ============================================================
# Phase 4.5: Wayback Endpoint Diff (New vs Old)
# ============================================================
echo ""
log_info "Phase 4.5: Wayback Endpoint Diff"

if [ "$TARGET_TYPE" = "domain" ] && [ "$QUICK_MODE" != "--quick" ]; then
    log_step "Fetching URLs from ~12 months ago for diff..."
    DATE_12M_AGO=$(date -d "12 months ago" +%Y%m%d 2>/dev/null || date -v-12m +%Y%m%d 2>/dev/null || true)
    DATE_6M_AGO=$(date -d "6 months ago" +%Y%m%d 2>/dev/null || date -v-6m +%Y%m%d 2>/dev/null || true)

    if [ -n "$DATE_12M_AGO" ] && [ -n "$DATE_6M_AGO" ]; then
        curl -s --max-time 30 \
            "https://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey&from=${DATE_12M_AGO}&to=${DATE_6M_AGO}&limit=5000" \
            2>/dev/null | sort -u > "$RECON_DIR/urls/wayback_old.txt" || true
        OLD_COUNT=$(wc -l < "$RECON_DIR/urls/wayback_old.txt" 2>/dev/null || echo 0)
        log_done "Old URLs (6-12m ago): $OLD_COUNT"

        if [ "$OLD_COUNT" -gt 0 ] && [ -s "$RECON_DIR/urls/all.txt" ]; then
            comm -23 \
                <(grep '?' "$RECON_DIR/urls/all.txt" 2>/dev/null | sort -u) \
                <(grep '?' "$RECON_DIR/urls/wayback_old.txt" 2>/dev/null | sort -u) \
                > "$RECON_DIR/urls/new_endpoints.txt" 2>/dev/null || true
            NEW_COUNT=$(wc -l < "$RECON_DIR/urls/new_endpoints.txt" 2>/dev/null || echo 0)
            if [ "$NEW_COUNT" -gt 0 ]; then
                log_warn "New endpoints (not in 12m-old snapshot): $NEW_COUNT — recently deployed, higher-priority targets"
            else
                log_done "No new endpoints vs 12-month-old snapshot"
            fi
        fi
    else
        log_warn "Could not compute date 12 months ago — skipping wayback diff"
    fi
else
    [ "$QUICK_MODE" = "--quick" ] && log_warn "Skipping wayback diff (quick mode)"
fi

# ============================================================
# Phase 4.6: GraphQL Schema Extraction
# ============================================================
echo ""
log_info "Phase 4.6: GraphQL Schema Extraction"

GRAPHQL_ENDPOINTS=""
if [ -s "$RECON_DIR/urls/api_endpoints.txt" ]; then
    GRAPHQL_ENDPOINTS=$(grep -iE '/graphql|/gql' "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null | sort -u || true)
fi

# Also probe common GraphQL paths on live hosts if none found yet
if [ -z "$GRAPHQL_ENDPOINTS" ] && [ -s "$RECON_DIR/live/urls.txt" ]; then
    GRAPHQL_ENDPOINTS=$(while IFS= read -r base; do
        for p in /graphql /api/graphql /gql /api/gql /v1/graphql; do
            echo "${base}${p}"
        done
    done < <(head -20 "$RECON_DIR/live/urls.txt"))
fi

if [ -n "$GRAPHQL_ENDPOINTS" ]; then
    INTROSPECTION_QUERY='{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name kind ofType { name kind } } } } } } }"}'
    echo "$GRAPHQL_ENDPOINTS" | sort -u | while IFS= read -r gql_url; do
        RESPONSE=$(curl -s --max-time 10 -X POST "$gql_url" \
            -H "Content-Type: application/json" \
            -d "$INTROSPECTION_QUERY" 2>/dev/null || true)
        if echo "$RESPONSE" | grep -q '__schema'; then
            log_warn "GraphQL introspection ENABLED: $gql_url"
            SAFE_NAME=$(echo "$gql_url" | sed 's|[^a-zA-Z0-9]|_|g')
            echo "$RESPONSE" > "$RECON_DIR/graphql/schema_${SAFE_NAME}.json"
            echo "$gql_url" >> "$RECON_DIR/graphql/introspection_enabled.txt"
            # Extract mutations (IDOR / auth-bypass candidates)
            echo "$RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    schema = data.get('data', {}).get('__schema', {})
    mut_type = schema.get('mutationType') or {}
    mut_name = mut_type.get('name', '')
    for t in schema.get('types', []):
        if t.get('name') == mut_name and t.get('fields'):
            print('[MUTATIONS]')
            for f in t['fields']: print(f'  {f[\"name\"]}')
except: pass
" >> "$RECON_DIR/graphql/mutations.txt" 2>/dev/null || true
        fi
    done
    if [ -s "$RECON_DIR/graphql/introspection_enabled.txt" ]; then
        log_warn "GraphQL introspection open on $(wc -l < "$RECON_DIR/graphql/introspection_enabled.txt") endpoint(s)"
        [ -s "$RECON_DIR/graphql/mutations.txt" ] && \
            log_step "Mutations found — review $RECON_DIR/graphql/mutations.txt for IDOR/auth bypass candidates"
    else
        log_done "GraphQL: endpoints not found or introspection disabled"
    fi
else
    log_done "No GraphQL endpoints detected"
fi

# ============================================================
# Phase 5: JavaScript Analysis (Deep)
# ============================================================
echo ""
log_info "Phase 5: JavaScript Analysis (Deep)"

mkdir -p "$RECON_DIR/js/downloaded"

# ── Step 5a: JS file discovery from live hosts ──────────────────────────────
# Finds JS bundles that never appeared in historical URL data
if [ -s "$RECON_DIR/live/urls.txt" ]; then
    if command -v katana &>/dev/null; then
        log_step "Crawling live hosts for JS files (katana -jc)..."
        katana -list "$RECON_DIR/live/urls.txt" \
            -jc -d 2 -silent \
            -extension-match js \
            -o "$RECON_DIR/js/katana_js.txt" 2>/dev/null || true
        cat "$RECON_DIR/js/katana_js.txt" "$RECON_DIR/urls/js_files.txt" 2>/dev/null \
            | sort -u > "$RECON_DIR/js/all_js_urls.txt" || true
        log_done "katana extra JS: $(wc -l < "$RECON_DIR/js/katana_js.txt" 2>/dev/null || echo 0)"
    else
        # Fallback: scrape <script src="..."> tags from live host HTML
        log_step "Scraping <script src> tags (katana not installed)..."
        head -20 "$RECON_DIR/live/urls.txt" | while IFS= read -r url; do
            BASE_HOST=$(echo "$url" | grep -oE 'https?://[^/]+')
            curl -s --max-time 10 "$url" 2>/dev/null \
                | grep -oiE 'src="([^"]*\.js[^"]*)"' \
                | sed -E 's/src="([^"]*)"/\1/' \
                | while IFS= read -r js_path; do
                    if echo "$js_path" | grep -qE '^https?://'; then
                        echo "$js_path"
                    else
                        echo "${BASE_HOST}${js_path}"
                    fi
                done
        done | sort -u >> "$RECON_DIR/urls/js_files.txt" 2>/dev/null || true
        sort -u "$RECON_DIR/urls/js_files.txt" -o "$RECON_DIR/urls/js_files.txt" 2>/dev/null || true
        cp "$RECON_DIR/urls/js_files.txt" "$RECON_DIR/js/all_js_urls.txt" 2>/dev/null || true
    fi
else
    cp "$RECON_DIR/urls/js_files.txt" "$RECON_DIR/js/all_js_urls.txt" 2>/dev/null || true
fi

JS_TOTAL=$(wc -l < "$RECON_DIR/js/all_js_urls.txt" 2>/dev/null || echo 0)
log_done "Total JS files to analyze: $JS_TOTAL"

if [ "$JS_TOTAL" -eq 0 ]; then
    log_warn "No JS files found — skipping JS deep analysis"
else

MAX_JS=$([ "$QUICK_MODE" = "--quick" ] && echo 30 || echo 100)
log_step "Downloading top $MAX_JS JS files..."

head -"$MAX_JS" "$RECON_DIR/js/all_js_urls.txt" | while IFS= read -r js_url; do
    SAFE=$(printf '%s' "$js_url" | md5sum | awk '{print $1}')
    curl -s --max-time 15 -A "Mozilla/5.0" "$js_url" 2>/dev/null \
        > "$RECON_DIR/js/downloaded/${SAFE}.js" || true
    [ ! -s "$RECON_DIR/js/downloaded/${SAFE}.js" ] && rm -f "$RECON_DIR/js/downloaded/${SAFE}.js"
    echo "$SAFE $js_url" >> "$RECON_DIR/js/file_map.txt"
done
DOWNLOADED=$(find "$RECON_DIR/js/downloaded" -name "*.js" 2>/dev/null | wc -l || echo 0)
log_done "Downloaded: $DOWNLOADED JS files"

# ── Step 5b: Source map extraction ──────────────────────────────────────────
# .js.map files expose original (unminified) source — massive recon win
log_step "Checking for exposed source maps (.js.map)..."
head -"$MAX_JS" "$RECON_DIR/js/all_js_urls.txt" | while IFS= read -r js_url; do
    MAP_URL="${js_url}.map"
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$MAP_URL" 2>/dev/null || echo "000")
    if [ "$STATUS" = "200" ]; then
        log_warn "Source map exposed: $MAP_URL"
        echo "$MAP_URL" >> "$RECON_DIR/js/source_maps.txt"
        SAFE=$(printf '%s' "$MAP_URL" | md5sum | awk '{print $1}')
        curl -s --max-time 15 "$MAP_URL" 2>/dev/null \
            > "$RECON_DIR/js/downloaded/${SAFE}.map" || true
    fi
done
if [ -s "$RECON_DIR/js/source_maps.txt" ]; then
    log_warn "Source maps: $(wc -l < "$RECON_DIR/js/source_maps.txt") found — original source may be recoverable"
else
    log_done "No source maps found"
fi

# ── Step 5c: Deep endpoint, hidden URL, and hidden parameter extraction ──────
log_step "Extracting hidden endpoints + parameters from JS (Python deep scan)..."
python3 - "$RECON_DIR/js/downloaded" "$RECON_DIR/js" <<'PY'
import os, re, sys, json

js_dir  = sys.argv[1]
out_dir = sys.argv[2]

endpoints = set()
params    = set()

PATH_PATTERNS = [
    # Quoted relative/absolute paths with at least one slash
    r'''["'`](/(?:api|v\d+|rest|gql|graphql|internal|admin|user|account|auth|oauth|token|service|data|config|upload|file|media|search|export|import|webhook|callback|health|status|metrics)[^\s"'`<>]{0,200})["'`]''',
    # Any quoted path 3+ segments deep
    r'''["'`](/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*)["'`]''',
    # fetch / axios / XMLHttpRequest / http calls
    r'''(?:fetch|axios\.(?:get|post|put|patch|delete|head|options)|(?:new\s+)?XMLHttpRequest|http\.(?:get|post|put|delete|patch))\s*[.(]\s*["'`]([^"'`\s]{5,})["'`]''',
    # Template literal API paths
    r'''`(/(?:api|v\d+|rest|gql)[^`\s]{2,})`''',
    # Router.navigate / history.push / window.location assignments
    r'''(?:navigate|\.push|\.replace|\.assign|location\.href\s*=)\s*["'`](/[^"'`\s]{3,})["'`]''',
    # Express/Koa/Hapi route definitions leaking into bundles
    r'''(?:router|app|server)\.(?:get|post|put|patch|delete|use)\s*\(\s*["'`](/[^"'`\s]{2,})["'`]''',
]

PARAM_PATTERNS = [
    # JSON object keys in fetch/axios body literals
    r'''[{,]\s*["'`]([a-zA-Z_][a-zA-Z0-9_]{1,40})["'`]\s*:''',
    # FormData.append / URLSearchParams.set|append
    r'''\.(?:append|set)\s*\(\s*["'`]([a-zA-Z_][a-zA-Z0-9_]{1,40})["'`]''',
    # Query-string params embedded in string literals
    r'''[?&]([a-zA-Z_][a-zA-Z0-9_]{1,40})=''',
    # Object destructuring that looks like API field names
    r'''const\s*\{\s*([a-zA-Z_][a-zA-Z0-9_]{1,40})\s*\}''',
]

BLACKLIST_PATHS = {
    '//', '/', '/index', '/en', '/us', '/static', '/assets',
    '/img', '/css', '/js', '/fonts', '/images', '/favicon.ico',
}
BLACKLIST_PARAMS = {
    'true', 'false', 'null', 'undefined', 'function', 'return',
    'const', 'let', 'var', 'class', 'this', 'super', 'import',
    'export', 'default', 'from', 'new', 'if', 'else', 'for',
    'while', 'try', 'catch', 'throw', 'type', 'name', 'key',
    'value', 'id', 'src', 'href', 'class', 'style', 'data',
    'props', 'state', 'event', 'error', 'result', 'response',
    'index', 'item', 'items', 'list', 'children', 'parent',
}

for fname in os.listdir(js_dir):
    fpath = os.path.join(js_dir, fname)
    if not os.path.isfile(fpath):
        continue
    # Handle source maps: extract original source file paths
    if fname.endswith('.map'):
        try:
            with open(fpath, 'r', errors='ignore') as f:
                sm = json.loads(f.read(2_000_000))
            for src in sm.get('sources', []):
                if src and not src.startswith('webpack:'):
                    endpoints.add(f'[SOURCEMAP] {src}')
        except Exception:
            pass
        continue
    if not fname.endswith('.js'):
        continue
    try:
        with open(fpath, 'r', errors='ignore') as f:
            content = f.read(2_000_000)
    except Exception:
        continue

    for pattern in PATH_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            path = m.group(1).split('?')[0].rstrip('/')
            if (len(path) > 3
                    and path not in BLACKLIST_PATHS
                    and not re.match(r'^/[0-9a-f]{8,}$', path)
                    and re.search(r'[a-zA-Z]', path)):
                endpoints.add(path)

    for pattern in PARAM_PATTERNS:
        for m in re.finditer(pattern, content):
            p = m.group(1)
            if p not in BLACKLIST_PARAMS and len(p) > 1:
                params.add(p)

with open(os.path.join(out_dir, 'endpoints.txt'), 'w') as f:
    for e in sorted(endpoints):
        f.write(e + '\n')

with open(os.path.join(out_dir, 'hidden_params.txt'), 'w') as f:
    for p in sorted(params):
        f.write(p + '\n')

print(f'endpoints:{len(endpoints)}')
print(f'params:{len(params)}')
PY

JS_ENDPOINTS=$(wc -l < "$RECON_DIR/js/endpoints.txt" 2>/dev/null || echo 0)
JS_PARAMS=$(wc -l < "$RECON_DIR/js/hidden_params.txt" 2>/dev/null || echo 0)
log_done "JS hidden endpoints:  $JS_ENDPOINTS"
log_done "JS hidden parameters: $JS_PARAMS"
if [ "$JS_PARAMS" -gt 0 ]; then
    log_step "Sample params: $(head -10 "$RECON_DIR/js/hidden_params.txt" | tr '\n' ', ')"
fi

# ── Step 5d: Comprehensive secret scanning (30+ pattern types) ───────────────
log_step "Scanning JS files for secrets (30+ pattern types)..."
python3 - "$RECON_DIR/js/downloaded" "$RECON_DIR/js/secrets.txt" <<'PY'
import os, re, sys

js_dir = sys.argv[1]
out_f  = sys.argv[2]

SECRET_PATTERNS = [
    ("AWS Access Key ID",    r'AKIA[0-9A-Z]{16}'),
    ("AWS Secret Key",       r'(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key["\'`]?\s*[:=]\s*["\'`]?([A-Za-z0-9/+]{40})'),
    ("Google API Key",       r'AIza[0-9A-Za-z\-_]{35}'),
    ("GCP Service Account",  r'"type"\s*:\s*"service_account"'),
    ("GitHub Token",         r'gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82}'),
    ("GitLab Token",         r'glpat-[0-9a-zA-Z\-]{20}'),
    ("Slack Token",          r'xox[baprs]-[0-9A-Za-z\-]+'),
    ("Slack Webhook",        r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24}'),
    ("Stripe Live Key",      r'sk_live_[0-9a-zA-Z]{24,}'),
    ("Stripe Publishable",   r'pk_live_[0-9a-zA-Z]{24,}'),
    ("SendGrid Key",         r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}'),
    ("Twilio Key",           r'SK[0-9a-fA-F]{32}'),
    ("JWT Token",            r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    ("RSA Private Key",      r'-----BEGIN RSA PRIVATE KEY-----'),
    ("Private Key",          r'-----BEGIN (?:EC |DSA |OPENSSH |PGP )?PRIVATE KEY'),
    ("Firebase Realtime DB", r'https://[a-z0-9-]+\.firebaseio\.com'),
    ("Firebase API Key",     r'(?i)firebase[_\-]?api[_\-]?key["\'`]?\s*[:=]\s*["\'`]?([A-Za-z0-9\-_]{20,})'),
    ("Heroku API Key",       r'(?i)heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'),
    ("Auth0 Secret",         r'(?i)auth0.*(?:secret|token)["\'`]?\s*[:=]\s*["\'`]?([A-Za-z0-9\-_]{20,})'),
    ("Bearer Token",         r'[Bb]earer [A-Za-z0-9\-._~+/]{20,}'),
    ("Basic Auth Header",    r'(?i)Authorization["\'`]?\s*[:=]\s*["\'`]?Basic [A-Za-z0-9+/=]{16,}'),
    ("Password in JS",       r'(?i)(?:password|passwd|pwd)["\'`]?\s*[:=]\s*["\'`]([^"\'`\s]{8,})["\'`]'),
    ("API Key Generic",      r'(?i)api[_\-]?key["\'`]?\s*[:=]\s*["\'`]([A-Za-z0-9\-_]{16,})["\'`]'),
    ("Secret Generic",       r'(?i)(?:app|client|oauth|hmac)?[_\-]?secret["\'`]?\s*[:=]\s*["\'`]([A-Za-z0-9\-_]{16,})["\'`]'),
    ("Access Token",         r'(?i)access[_\-]?token["\'`]?\s*[:=]\s*["\'`]([A-Za-z0-9\-_.]{16,})["\'`]'),
    ("Client Secret",        r'(?i)client[_\-]?secret["\'`]?\s*[:=]\s*["\'`]([A-Za-z0-9\-_]{16,})["\'`]'),
    ("Encryption Key",       r'(?i)encryption[_\-]?key["\'`]?\s*[:=]\s*["\'`]([A-Za-z0-9\-_+/=]{16,})["\'`]'),
    ("NPM Token",            r'npm_[A-Za-z0-9]{36}'),
    ("Mailgun Key",          r'key-[0-9a-zA-Z]{32}'),
    ("Square Token",         r'sq0atp-[0-9A-Za-z\-_]{22}|sq0csp-[0-9A-Za-z\-_]{43}'),
    ("Internal IP URL",      r'https?://(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.0\.0\.1)[^\s"\'`<>]+'),
    ("Admin Path",           r'["\'`](/(?:admin|internal|debug|console|manage|staff|superuser|backdoor|_debug|_admin)[^\s"\'`<>]*)["\'`]'),
    ("Hardcoded Subdomain",  r'["\'`](https?://(?:dev|staging|uat|test|qa|internal|corp|api-internal)[^\s"\'`<>]{5,})["\'`]'),
]

hits = []
for fname in os.listdir(js_dir):
    if not fname.endswith('.js'):
        continue
    fpath = os.path.join(js_dir, fname)
    try:
        with open(fpath, 'r', errors='ignore') as f:
            content = f.read(2_000_000)
    except Exception:
        continue
    for label, pattern in SECRET_PATTERNS:
        for m in re.finditer(pattern, content):
            snippet = m.group(0)[:140].replace('\n', ' ')
            hits.append(f'[{label}] {snippet}')

# Deduplicate by first 60 chars of snippet
seen, unique = set(), []
for h in hits:
    key = h[:60]
    if key not in seen:
        seen.add(key)
        unique.append(h)

with open(out_f, 'w') as f:
    for h in sorted(unique):
        f.write(h + '\n')

print(f'secrets:{len(unique)}')
PY

SECRET_COUNT=$(wc -l < "$RECON_DIR/js/secrets.txt" 2>/dev/null || echo 0)
if [ "$SECRET_COUNT" -gt 0 ]; then
    log_warn "Potential secrets in JS: $SECRET_COUNT — review $RECON_DIR/js/secrets.txt"
    head -5 "$RECON_DIR/js/secrets.txt" | while IFS= read -r line; do log_step "$line"; done
else
    log_done "No secrets found in JS files"
fi

# ── Step 5e: trufflehog (if installed — verified high-signal secrets) ────────
if command -v trufflehog &>/dev/null; then
    log_step "Running trufflehog on downloaded JS (verified secrets only)..."
    trufflehog filesystem "$RECON_DIR/js/downloaded/" \
        --only-verified \
        --no-update \
        --json 2>/dev/null \
        | head -200 > "$RECON_DIR/js/trufflehog.json" || true
    if [ -s "$RECON_DIR/js/trufflehog.json" ]; then
        log_warn "trufflehog verified secrets: $(wc -l < "$RECON_DIR/js/trufflehog.json")"
    else
        log_done "trufflehog: no verified secrets"
    fi
fi

# ── Step 5f: Probe live status of JS-discovered API endpoints ─────────────────
if [ -s "$RECON_DIR/js/endpoints.txt" ] && [ -s "$RECON_DIR/live/urls.txt" ]; then
    log_step "Probing live status of API paths discovered in JS..."
    BASE_HOST=$(head -1 "$RECON_DIR/live/urls.txt" | awk '{print $1}')
    grep -iE '^/(?:api|v[0-9]+|rest|internal)/' "$RECON_DIR/js/endpoints.txt" 2>/dev/null \
        | grep -v '^\[SOURCEMAP\]' | sort -u | head -30 \
        | while IFS= read -r path; do
            STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "${BASE_HOST}${path}" 2>/dev/null || echo "000")
            if [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ]; then
                echo "[HTTP $STATUS] ${BASE_HOST}${path}" >> "$RECON_DIR/js/live_endpoints.txt"
            fi
        done
    if [ -s "$RECON_DIR/js/live_endpoints.txt" ]; then
        log_ok "Live JS-discovered endpoints: $(wc -l < "$RECON_DIR/js/live_endpoints.txt")"
    else
        log_done "JS-discovered API paths: none returned live responses"
    fi
fi

fi  # end JS_TOTAL > 0

# ============================================================
# Phase 6: Directory Fuzzing
# ============================================================
echo ""
log_info "Phase 6: Directory Fuzzing"

WORDLIST_DIR="$BASE_DIR/tools/wordlists"

if command -v ffuf &>/dev/null && [ -s "$RECON_DIR/live/urls.txt" ]; then
    # Select wordlist
    WORDLIST=""
    if [ -f "$WORDLIST_DIR/common.txt" ]; then
        WORDLIST="$WORDLIST_DIR/common.txt"
    elif [ -f /usr/share/wordlists/dirb/common.txt ]; then
        WORDLIST="/usr/share/wordlists/dirb/common.txt"
    fi

    if [ -n "$WORDLIST" ]; then
        # Fuzz top 5 live hosts
        FUZZ_COUNT=0
        MAX_FUZZ=$([ "$QUICK_MODE" = "--quick" ] && echo 2 || echo 5)

        while IFS= read -r url && [ "$FUZZ_COUNT" -lt "$MAX_FUZZ" ]; do
            domain=$(echo "$url" | sed 's|https\?://||;s|[/:].*||')
            log_step "Fuzzing: $url"
            ffuf -u "${url}/FUZZ" \
                -w "$WORDLIST" \
                -mc 200,301,302,403,405 \
                -t "$THREADS" \
                -rate "$RATE_LIMIT" \
                -sf \
                -timeout 10 \
                -o "$RECON_DIR/dirs/ffuf_${domain}.json" \
                -of json 2>/dev/null || true
            ((FUZZ_COUNT++))
        done < "$RECON_DIR/live/urls.txt"

        log_done "Directory fuzzing complete ($FUZZ_COUNT hosts)"
    else
        log_warn "No wordlist found — run: python3 tools/hunt.py --setup-wordlists"
    fi
else
    log_warn "ffuf not installed or no live hosts — skipping directory fuzzing"
fi

# ============================================================
# Phase 6.5: Config File Exposure Check
# ============================================================
echo ""
log_info "Phase 6.5: Config File Exposure Check"

if [ -s "$RECON_DIR/live/urls.txt" ]; then
    log_step "Checking for exposed config files (env.js, app_env.js, .env, etc.)..."
    CONFIG_PATHS=(
        "/env.js"
        "/app_env.js"
        "/config.js"
        "/settings.js"
        "/.env"
        "/.env.local"
        "/.env.production"
        "/.env.development"
        "/config/env.js"
        "/static/env.js"
        "/assets/env.js"
    )

    mkdir -p "$RECON_DIR/exposure"
    : > "$RECON_DIR/exposure/config_files.txt"

    while IFS= read -r base_url; do
        for path in "${CONFIG_PATHS[@]}"; do
            STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${base_url}${path}" 2>/dev/null || echo "000")
            if [ "$STATUS" = "200" ]; then
                CONTENT_TYPE=$(curl -sI --max-time 5 "${base_url}${path}" 2>/dev/null | grep -i content-type | head -1)
                # Only flag if it returns JS/JSON/text (not HTML error pages)
                if echo "$CONTENT_TYPE" | grep -qiE '(javascript|json|text/plain)'; then
                    echo "[EXPOSED] ${base_url}${path}" >> "$RECON_DIR/exposure/config_files.txt"
                    log_vuln "Config exposed: ${base_url}${path}"
                fi
            fi
        done
    done < <(head -30 "$RECON_DIR/live/urls.txt")

    CONFIG_COUNT=$(wc -l < "$RECON_DIR/exposure/config_files.txt" 2>/dev/null | tr -d ' ')
    [ "$CONFIG_COUNT" -gt 0 ] && log_warn "Exposed config files: $CONFIG_COUNT" || log_done "Config files: clean"
else
    log_warn "No live hosts — skipping config check"
fi

# ============================================================
# Phase 6.6: Screenshot Automation
# ============================================================
echo ""
log_info "Phase 6.6: Screenshot Automation"

if command -v gowitness &>/dev/null && [ -s "$RECON_DIR/live/urls.txt" ]; then
    log_step "Running gowitness on live hosts..."
    # Try v3 syntax first, fall back to v2
    gowitness scan file -f "$RECON_DIR/live/urls.txt" \
        --screenshot-path "$RECON_DIR/screenshots/" \
        --disable-db 2>/dev/null || \
    gowitness file -f "$RECON_DIR/live/urls.txt" \
        --screenshot-path "$RECON_DIR/screenshots/" 2>/dev/null || true
    SHOT_COUNT=$(find "$RECON_DIR/screenshots/" -name "*.png" 2>/dev/null | wc -l || echo 0)
    if [ "$SHOT_COUNT" -gt 0 ]; then
        log_ok "Screenshots captured: $SHOT_COUNT (review for admin panels / login pages)"
    else
        log_warn "gowitness ran but no screenshots generated (check if a browser is available)"
    fi
else
    log_warn "gowitness not installed — skipping screenshots (install: go install github.com/sensepost/gowitness/v3@latest)"
fi

# ============================================================
# Phase 7: Parameter Discovery
# ============================================================
echo ""
log_info "Phase 7: Parameter Discovery"

if [ -s "$RECON_DIR/urls/with_params.txt" ]; then
    log_step "Extracting parameters from collected URLs..."

    # Extract parameter names (macOS compatible - no grep -P)
    sed -nE 's/.*[?&]([^=&]+)=.*/\1/p' "$RECON_DIR/urls/with_params.txt" 2>/dev/null \
        | sort | uniq -c | sort -rn > "$RECON_DIR/params/param_frequency.txt" 2>/dev/null || true

    # Get unique param names
    awk '{print $2}' "$RECON_DIR/params/param_frequency.txt" > "$RECON_DIR/params/unique_params.txt" 2>/dev/null || true
    log_done "Unique parameters: $(wc -l < "$RECON_DIR/params/unique_params.txt" 2>/dev/null || echo 0)"

    # Flag interesting params (potential injection points)
    grep -iE '(url|redirect|next|return|callback|dest|file|path|page|template|include|src|ref|uri|link|target|goto|out|view|dir|show|site|domain|rurl|return_to|continue|window|data|reference|to|img|load|doc|download)' \
        "$RECON_DIR/params/unique_params.txt" > "$RECON_DIR/params/interesting_params.txt" 2>/dev/null || true

    if [ -s "$RECON_DIR/params/interesting_params.txt" ]; then
        log_warn "Interesting params (potential vulns): $(wc -l < "$RECON_DIR/params/interesting_params.txt")"
        echo "      Params: $(head -5 "$RECON_DIR/params/interesting_params.txt" | tr '\n' ', ')"
    fi
else
    log_warn "No parameterized URLs found — skipping"
fi

# ============================================================
# Phase 7.5: Subdomain Takeover Scanning
# ============================================================
echo ""
log_info "Phase 7.5: Subdomain Takeover Scanning"

if [ "$TARGET_TYPE" = "domain" ] && [ -s "$RECON_DIR/subdomains/all.txt" ]; then
    # Method 1: subjack (if installed)
    if command -v subjack &>/dev/null; then
        log_step "Running subjack for subdomain takeover fingerprinting..."
        subjack -w "$RECON_DIR/subdomains/all.txt" \
            -t "$THREADS" \
            -timeout 30 \
            -o "$RECON_DIR/takeover/subjack.txt" \
            -ssl 2>/dev/null || true
        if [ -s "$RECON_DIR/takeover/subjack.txt" ]; then
            log_warn "Takeover candidates (subjack): $(wc -l < "$RECON_DIR/takeover/subjack.txt")"
        else
            log_done "subjack: no takeover candidates found"
        fi
    fi

    # Method 2: nuclei takeover templates (no extra tools needed beyond nuclei)
    if command -v nuclei &>/dev/null && [ -s "$RECON_DIR/live/urls.txt" ]; then
        log_step "Running nuclei takeover templates..."
        nuclei -l "$RECON_DIR/live/urls.txt" \
            -t takeovers/ \
            -silent \
            -o "$RECON_DIR/takeover/nuclei_takeover.txt" 2>/dev/null || true
        if [ -s "$RECON_DIR/takeover/nuclei_takeover.txt" ]; then
            log_warn "Takeover findings (nuclei): $(wc -l < "$RECON_DIR/takeover/nuclei_takeover.txt")"
        else
            log_done "nuclei takeovers: no findings"
        fi
    fi

    # Method 3: Lightweight dangling CNAME check (no external tools)
    log_step "Checking for dangling CNAMEs (top 200 subdomains)..."
    TAKEOVER_SERVICES="github\.io|amazonaws\.com|heroku\.com|fastly\.net|azurewebsites\.net|cloudfront\.net|pantheon\.io|wpengine\.com|netlify\.app|webflow\.io|ghost\.io|surge\.sh"
    while IFS= read -r sub; do
        CNAME=$(dig +short CNAME "$sub" 2>/dev/null | head -1 || true)
        if [ -n "$CNAME" ]; then
            CNAME_IP=$(dig +short "$CNAME" 2>/dev/null | head -1 || true)
            if [ -z "$CNAME_IP" ] && echo "$CNAME" | grep -qiE "$TAKEOVER_SERVICES"; then
                echo "$sub → $CNAME (DANGLING)" >> "$RECON_DIR/takeover/dangling_cnames.txt"
            fi
        fi
    done < <(head -200 "$RECON_DIR/subdomains/all.txt")
    if [ -s "$RECON_DIR/takeover/dangling_cnames.txt" ]; then
        log_warn "Dangling CNAMEs: $(wc -l < "$RECON_DIR/takeover/dangling_cnames.txt") — potential takeover!"
    else
        log_done "No dangling CNAMEs found in top 200 subdomains"
    fi
else
    log_warn "No subdomain list or non-domain target — skipping takeover scan"
fi

# ============================================================
# Phase 7.6: Cloud Asset Discovery
# ============================================================
echo ""
log_info "Phase 7.6: Cloud Asset Discovery"

ORG_NAME=$(echo "$TARGET" | sed 's/\..*//' | tr '[:upper:]' '[:lower:]' | tr -d '-')
ORG_NAME_DASH=$(echo "$TARGET" | sed 's/\..*//' | tr '[:upper:]' '[:lower:]')
PERMUTATIONS=(
    "$ORG_NAME" "$ORG_NAME_DASH"
    "${ORG_NAME}-dev"    "${ORG_NAME}-staging" "${ORG_NAME}-prod"
    "${ORG_NAME}-backup" "${ORG_NAME}-data"    "${ORG_NAME}-assets"
    "${ORG_NAME}-static" "${ORG_NAME}-media"   "${ORG_NAME}-uploads"
    "${ORG_NAME}-logs"   "${ORG_NAME}-public"  "${ORG_NAME}-files"
)

log_step "Probing S3 bucket permutations..."
for perm in "${PERMUTATIONS[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        "https://${perm}.s3.amazonaws.com" 2>/dev/null || echo "000")
    if [ "$STATUS" = "200" ] || [ "$STATUS" = "403" ]; then
        echo "S3: https://${perm}.s3.amazonaws.com [HTTP $STATUS]" >> "$RECON_DIR/cloud/buckets.txt"
        [ "$STATUS" = "200" ] && log_warn "Public S3 bucket: https://${perm}.s3.amazonaws.com"
    fi
done

log_step "Checking Firebase endpoints..."
for perm in "$ORG_NAME" "$ORG_NAME_DASH"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        "https://${perm}.firebaseio.com/.json" 2>/dev/null || echo "000")
    if [ "$STATUS" = "200" ]; then
        log_warn "Firebase open database: https://${perm}.firebaseio.com/.json"
        echo "Firebase: https://${perm}.firebaseio.com/.json [OPEN]" >> "$RECON_DIR/cloud/buckets.txt"
    elif [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
        echo "Firebase: https://${perm}.firebaseio.com/.json [EXISTS, auth required]" >> "$RECON_DIR/cloud/buckets.txt"
    fi
done

CLOUD_COUNT=$(wc -l < "$RECON_DIR/cloud/buckets.txt" 2>/dev/null || echo 0)
if [ "$CLOUD_COUNT" -gt 0 ]; then
    log_ok "Cloud assets found: $CLOUD_COUNT"
else
    log_done "Cloud asset discovery: no public/exposed assets found"
fi

# ============================================================
# Phase 7.7: GitHub Dorking (Automated)
# ============================================================
echo ""
log_info "Phase 7.7: GitHub Dorking"

# Collect GitHub org names from earlier recon data
GH_ORGS=""
for f in "$RECON_DIR/live/httpx_full.txt" "$RECON_DIR/js/endpoints.txt" "$RECON_DIR/urls/all.txt"; do
    if [ -f "$f" ]; then
        GH_ORGS="$GH_ORGS $(grep -oE 'github\.com/[a-zA-Z0-9_-]+' "$f" 2>/dev/null \
            | sed 's|github.com/||' | grep -v '^$' || true)"
    fi
done
# Also try org name derived from domain as fallback
DOMAIN_ORG=$(echo "$TARGET" | sed 's/\..*//')
GH_ORGS=$(printf '%s\n%s\n' "$GH_ORGS" "$DOMAIN_ORG" | tr ' ' '\n' | grep -v '^$' | sort -u | head -5)

if command -v gh &>/dev/null && [ -n "$GH_ORGS" ]; then
    log_step "GitHub dorking with gh CLI..."
    DORK_PATTERNS=("api_key" "password" "secret" ".env" "Authorization: Bearer" "BEGIN PRIVATE KEY" "aws_access_key")
    for org in $GH_ORGS; do
        log_step "Dorking org: $org"
        mkdir -p "$RECON_DIR/github/$org"
        for pattern in "${DORK_PATTERNS[@]}"; do
            RESULTS=$(gh search code "$pattern" --owner "$org" \
                --json path,repository --limit 5 2>/dev/null || true)
            if [ -n "$RESULTS" ] && echo "$RESULTS" | grep -q '"path"'; then
                echo "=== $pattern ===" >> "$RECON_DIR/github/$org/dorks.txt"
                echo "$RESULTS" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for item in data:
        print(f'  {item[\"repository\"][\"nameWithOwner\"]}: {item[\"path\"]}')
except: pass
" >> "$RECON_DIR/github/$org/dorks.txt" 2>/dev/null || true
            fi
        done
    done
    if find "$RECON_DIR/github" -name "dorks.txt" -size +0 &>/dev/null 2>&1; then
        log_warn "GitHub dork hits found — review $RECON_DIR/github/ for secrets"
    else
        log_done "GitHub dorking: no obvious secret patterns found"
    fi
else
    if ! command -v gh &>/dev/null; then
        log_warn "gh CLI not installed — manual dork: github.com search for org:TARGET api_key password .env"
    else
        log_warn "No GitHub org identified — skipping GitHub dorking"
    fi
fi

# Check for exposed .git on live hosts
if [ -s "$RECON_DIR/live/urls.txt" ]; then
    log_step "Checking for exposed .git directories (top 30 hosts)..."
    while IFS= read -r url; do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${url}/.git/HEAD" 2>/dev/null || echo "000")
        if [ "$STATUS" = "200" ]; then
            log_warn "Exposed .git: ${url}/.git/HEAD"
            echo "${url}/.git/HEAD" >> "$RECON_DIR/github/exposed_git.txt"
        fi
    done < <(head -30 "$RECON_DIR/live/urls.txt")
    if [ -s "$RECON_DIR/github/exposed_git.txt" ]; then
        log_warn "Exposed .git directories: $(wc -l < "$RECON_DIR/github/exposed_git.txt")"
    else
        log_done ".git exposure: none found"
    fi
fi

# ============================================================
# Phase 7.8: Shodan / Censys Integration (optional, API-key gated)
# ============================================================
echo ""
log_info "Phase 7.8: Shodan / Censys Integration"

if [ -n "${SHODAN_API_KEY:-}" ]; then
    TARGET_IP=$(dig +short "$TARGET" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
    if [ -n "$TARGET_IP" ]; then
        log_step "Querying Shodan for $TARGET_IP..."
        curl -s --max-time 20 \
            "https://api.shodan.io/shodan/host/$TARGET_IP?key=${SHODAN_API_KEY}" 2>/dev/null \
            | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(f'IP: {data.get(\"ip_str\",\"\")}')
    print(f'Org: {data.get(\"org\",\"\")} | OS: {data.get(\"os\",\"\")}')
    print(f'Hostnames: {data.get(\"hostnames\",[])}')
    for s in data.get('data', []):
        banner = s.get('data','')[:80].replace('\n',' ')
        print(f'  Port {s.get(\"port\")}/{s.get(\"transport\",\"tcp\")}: {s.get(\"product\",\"\")} {s.get(\"version\",\"\")} | {banner}')
except: pass
" > "$RECON_DIR/shodan/host_info.txt" 2>/dev/null || true

        if [ -s "$RECON_DIR/shodan/host_info.txt" ]; then
            log_ok "Shodan data retrieved for $TARGET_IP"
            # Flag ports that nmap may have missed
            grep 'Port ' "$RECON_DIR/shodan/host_info.txt" 2>/dev/null \
                | while IFS= read -r line; do
                    PORT=$(echo "$line" | grep -oE 'Port [0-9]+' | awk '{print $2}')
                    if [ -n "$PORT" ] && ! grep -q "^$PORT" "$RECON_DIR/ports/open_ports.txt" 2>/dev/null; then
                        echo "[NEW] $line" >> "$RECON_DIR/shodan/new_ports.txt"
                    fi
                done
            [ -s "$RECON_DIR/shodan/new_ports.txt" ] && \
                log_warn "Shodan found ports not in nmap scan: $(wc -l < "$RECON_DIR/shodan/new_ports.txt")"
        fi
    fi
elif [ -n "${CENSYS_API_ID:-}" ] && [ -n "${CENSYS_API_SECRET:-}" ]; then
    TARGET_IP=$(dig +short "$TARGET" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
    if [ -n "$TARGET_IP" ]; then
        log_step "Querying Censys for $TARGET_IP..."
        curl -s --max-time 20 \
            --user "${CENSYS_API_ID}:${CENSYS_API_SECRET}" \
            "https://search.censys.io/api/v2/hosts/$TARGET_IP" 2>/dev/null \
            | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    r = data.get('result', {})
    print(f'IP: {r.get(\"ip\",\"\")} | AS: {r.get(\"autonomous_system\",{}).get(\"name\",\"\")}')
    for svc in r.get('services', []):
        print(f'  Port {svc.get(\"port\")}/{svc.get(\"transport_protocol\",\"\")} — {svc.get(\"service_name\",\"\")}')
except: pass
" > "$RECON_DIR/shodan/censys_host.txt" 2>/dev/null || true
        [ -s "$RECON_DIR/shodan/censys_host.txt" ] && log_ok "Censys data retrieved for $TARGET_IP"
    fi
else
    log_warn "SHODAN_API_KEY / CENSYS_API_ID not set — skipping (export SHODAN_API_KEY=xxx to enable)"
fi

# ============================================================
# Phase 8: CI/CD Workflow Scan (auto-detect GitHub org)
# ============================================================
log_info "Phase 8: CI/CD Workflow Scan"

GITHUB_ORGS=""
CICD_SCANNER="$(dirname "$0")/cicd_scanner.sh"

# Extract github.com/<org> patterns from recon data
for f in "$RECON_DIR/live/httpx_full.txt" "$RECON_DIR/js/endpoints.txt" "$RECON_DIR/urls/all.txt"; do
    if [ -f "$f" ]; then
        GITHUB_ORGS="$GITHUB_ORGS $(grep -oP 'github\.com/\K[a-zA-Z0-9_-]+' "$f" 2>/dev/null || true)"
    fi
done

# Deduplicate and limit to 5
GITHUB_ORGS=$(echo "$GITHUB_ORGS" | tr ' ' '\n' | grep -v '^$' | sort -u | head -5)

if [ -n "$GITHUB_ORGS" ] && [ -x "$CICD_SCANNER" ] && command -v sisakulint &>/dev/null; then
    for ORG in $GITHUB_ORGS; do
        log_info "CI/CD scan: org:$ORG"
        bash "$CICD_SCANNER" "org:$ORG" --output-dir "$RECON_DIR/cicd/$ORG/" || true
    done
else
    if [ -z "$GITHUB_ORGS" ]; then
        log_warn "GitHub org not detected — CI/CD scan skipped"
    elif ! command -v sisakulint &>/dev/null; then
        log_warn "sisakulint not installed — CI/CD scan skipped"
    fi
fi

# ============================================================
# Phase 9: Nuclei Vulnerability Scan (Tech-Aware)
# ============================================================
echo ""
log_info "Phase 9: Nuclei Vulnerability Scan"

if command -v nuclei &>/dev/null && [ -s "$RECON_DIR/live/urls.txt" ]; then
    # Detect tech stack from httpx output and map to nuclei tags
    NUCLEI_TAGS=""
    if [ -s "$RECON_DIR/live/httpx_full.txt" ]; then
        TECH_STACK=$(grep -oE '\[[a-zA-Z0-9,._-]+\]' "$RECON_DIR/live/httpx_full.txt" 2>/dev/null \
            | tr -d '[]' | tr ',' '\n' | tr '[:upper:]' '[:lower:]' | sort -u || true)
        NUCLEI_TAGS_LIST=""
        for tech in $TECH_STACK; do
            case "$tech" in
                wordpress|wp)       NUCLEI_TAGS_LIST="$NUCLEI_TAGS_LIST,wordpress" ;;
                drupal)             NUCLEI_TAGS_LIST="$NUCLEI_TAGS_LIST,drupal" ;;
                joomla)             NUCLEI_TAGS_LIST="$NUCLEI_TAGS_LIST,joomla" ;;
                spring|springboot)  NUCLEI_TAGS_LIST="$NUCLEI_TAGS_LIST,springboot" ;;
                laravel)            NUCLEI_TAGS_LIST="$NUCLEI_TAGS_LIST,laravel" ;;
                django)             NUCLEI_TAGS_LIST="$NUCLEI_TAGS_LIST,django" ;;
                nginx)              NUCLEI_TAGS_LIST="$NUCLEI_TAGS_LIST,nginx" ;;
                apache)             NUCLEI_TAGS_LIST="$NUCLEI_TAGS_LIST,apache" ;;
                iis)                NUCLEI_TAGS_LIST="$NUCLEI_TAGS_LIST,iis" ;;
                graphql)            NUCLEI_TAGS_LIST="$NUCLEI_TAGS_LIST,graphql" ;;
                jenkins)            NUCLEI_TAGS_LIST="$NUCLEI_TAGS_LIST,jenkins" ;;
                gitlab)             NUCLEI_TAGS_LIST="$NUCLEI_TAGS_LIST,gitlab" ;;
                elasticsearch)      NUCLEI_TAGS_LIST="$NUCLEI_TAGS_LIST,elasticsearch" ;;
                redis)              NUCLEI_TAGS_LIST="$NUCLEI_TAGS_LIST,redis" ;;
                tomcat)             NUCLEI_TAGS_LIST="$NUCLEI_TAGS_LIST,tomcat" ;;
                phpmyadmin)         NUCLEI_TAGS_LIST="$NUCLEI_TAGS_LIST,phpmyadmin" ;;
            esac
        done
        NUCLEI_TAGS=$(echo "$NUCLEI_TAGS_LIST" | sed 's/^,//' | tr -d ' ')
        [ -n "$NUCLEI_TAGS" ] && log_step "Tech-aware nuclei tags: $NUCLEI_TAGS"
    fi

    # Base scan: critical/high/medium across all templates
    log_step "Running base nuclei scan (critical, high, medium)..."
    nuclei -l "$RECON_DIR/live/urls.txt" \
        -severity critical,high,medium \
        -silent \
        -o "$RECON_DIR/nuclei/base_findings.txt" 2>/dev/null || true
    log_done "Base findings: $(wc -l < "$RECON_DIR/nuclei/base_findings.txt" 2>/dev/null || echo 0)"

    # Exposure scan: admin panels, dashboards, exposed configs
    log_step "Running nuclei exposure templates..."
    nuclei -l "$RECON_DIR/live/urls.txt" \
        -t exposures/ \
        -silent \
        -o "$RECON_DIR/nuclei/exposures.txt" 2>/dev/null || true
    log_done "Exposure findings: $(wc -l < "$RECON_DIR/nuclei/exposures.txt" 2>/dev/null || echo 0)"

    # Misconfiguration scan: CORS, security headers, etc.
    log_step "Running nuclei misconfiguration templates..."
    nuclei -l "$RECON_DIR/live/urls.txt" \
        -t misconfiguration/ \
        -silent \
        -o "$RECON_DIR/nuclei/misconfigs.txt" 2>/dev/null || true
    log_done "Misconfiguration findings: $(wc -l < "$RECON_DIR/nuclei/misconfigs.txt" 2>/dev/null || echo 0)"

    # Tech-specific scan (only if tags were detected)
    if [ -n "$NUCLEI_TAGS" ]; then
        log_step "Running tech-specific nuclei scan (tags: $NUCLEI_TAGS)..."
        nuclei -l "$RECON_DIR/live/urls.txt" \
            -tags "$NUCLEI_TAGS" \
            -silent \
            -o "$RECON_DIR/nuclei/tech_specific.txt" 2>/dev/null || true
        log_done "Tech-specific findings: $(wc -l < "$RECON_DIR/nuclei/tech_specific.txt" 2>/dev/null || echo 0)"
    fi

    # Merge all nuclei results
    cat "$RECON_DIR/nuclei/"*.txt 2>/dev/null | sort -u > "$RECON_DIR/nuclei/all_findings.txt" || true
    TOTAL_NUCLEI=$(wc -l < "$RECON_DIR/nuclei/all_findings.txt" 2>/dev/null || echo 0)
    if [ "$TOTAL_NUCLEI" -gt 0 ]; then
        log_warn "Total nuclei findings: $TOTAL_NUCLEI"
    else
        log_done "Nuclei: no findings"
    fi
else
    log_warn "nuclei not installed or no live hosts — skipping (install: brew install nuclei)"
fi

# ============================================================
# Summary
# ============================================================
echo ""
echo "============================================="
echo "  Recon Summary — $TARGET"
echo "  Completed: $(date)"
echo "============================================="
echo ""
echo "  Subdomains:        $(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/asn/cidrs.txt" ] && \
echo "  ASN CIDRs:         $(wc -l < "$RECON_DIR/asn/cidrs.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/live/urls.txt" ] && \
echo "  Live hosts:        $(wc -l < "$RECON_DIR/live/urls.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/ports/open_ports.txt" ] && \
echo "  Open ports:        $(wc -l < "$RECON_DIR/ports/open_ports.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/waf/detected.txt" ] || [ -f "$RECON_DIR/waf/wafw00f.txt" ] && \
echo "  WAF detected:      $(cat "$RECON_DIR/waf/detected.txt" "$RECON_DIR/waf/wafw00f.txt" 2>/dev/null | wc -l || echo 0) hosts"
[ -f "$RECON_DIR/urls/all.txt" ] && \
echo "  URLs collected:    $(wc -l < "$RECON_DIR/urls/all.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/urls/new_endpoints.txt" ] && \
echo "  New endpoints:     $(wc -l < "$RECON_DIR/urls/new_endpoints.txt" 2>/dev/null || echo 0) (recently deployed — high priority)"
[ -f "$RECON_DIR/urls/with_params.txt" ] && \
echo "  Parameterized:     $(wc -l < "$RECON_DIR/urls/with_params.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/urls/api_endpoints.txt" ] && \
echo "  API endpoints:     $(wc -l < "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/js/all_js_urls.txt" ] && \
echo "  JS files:          $(wc -l < "$RECON_DIR/js/all_js_urls.txt" 2>/dev/null || echo 0) discovered / $(find "$RECON_DIR/js/downloaded" -name "*.js" 2>/dev/null | wc -l || echo 0) downloaded"
[ -f "$RECON_DIR/js/endpoints.txt" ] && \
echo "  JS endpoints:      $(wc -l < "$RECON_DIR/js/endpoints.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/js/hidden_params.txt" ] && \
echo "  JS hidden params:  $(wc -l < "$RECON_DIR/js/hidden_params.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/js/secrets.txt" ] && [ -s "$RECON_DIR/js/secrets.txt" ] && \
echo "  JS secrets:        $(wc -l < "$RECON_DIR/js/secrets.txt" 2>/dev/null || echo 0) potential hits  ← REVIEW"
[ -f "$RECON_DIR/js/source_maps.txt" ] && [ -s "$RECON_DIR/js/source_maps.txt" ] && \
echo "  Source maps:       $(wc -l < "$RECON_DIR/js/source_maps.txt" 2>/dev/null || echo 0)  ← REVIEW (original source exposed)"
[ -f "$RECON_DIR/params/unique_params.txt" ] && \
echo "  Unique params:     $(wc -l < "$RECON_DIR/params/unique_params.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/graphql/introspection_enabled.txt" ] && [ -s "$RECON_DIR/graphql/introspection_enabled.txt" ] && \
echo "  GraphQL open:      $(wc -l < "$RECON_DIR/graphql/introspection_enabled.txt" 2>/dev/null || echo 0) endpoint(s)  ← REVIEW"
[ -f "$RECON_DIR/takeover/dangling_cnames.txt" ] && [ -s "$RECON_DIR/takeover/dangling_cnames.txt" ] && \
echo "  Takeover leads:    $(wc -l < "$RECON_DIR/takeover/dangling_cnames.txt" 2>/dev/null || echo 0)  ← REVIEW"
[ -f "$RECON_DIR/cloud/buckets.txt" ] && [ -s "$RECON_DIR/cloud/buckets.txt" ] && \
echo "  Cloud assets:      $(wc -l < "$RECON_DIR/cloud/buckets.txt" 2>/dev/null || echo 0)  ← REVIEW"
[ -f "$RECON_DIR/github/exposed_git.txt" ] && [ -s "$RECON_DIR/github/exposed_git.txt" ] && \
echo "  Exposed .git:      $(wc -l < "$RECON_DIR/github/exposed_git.txt" 2>/dev/null || echo 0)  ← REVIEW"
SCREENSHOTS=$(find "$RECON_DIR/screenshots" -name "*.png" 2>/dev/null | wc -l || echo 0)
[ "$SCREENSHOTS" -gt 0 ] && \
echo "  Screenshots:       $SCREENSHOTS"
[ -f "$RECON_DIR/nuclei/all_findings.txt" ] && \
echo "  Nuclei findings:   $(wc -l < "$RECON_DIR/nuclei/all_findings.txt" 2>/dev/null || echo 0)"
[ -d "$RECON_DIR/cicd" ] && \
echo "  CI/CD findings:    $(find "$RECON_DIR/cicd" -name 'scan_results.txt' -exec grep -c '\.github/workflows/' {} + 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}')"

echo ""
echo "  Results: $RECON_DIR/"
echo "============================================="
echo ""
echo "  Next: Run vulnerability scanner"
echo "    ./tools/vuln_scanner.sh $RECON_DIR"
echo "============================================="
