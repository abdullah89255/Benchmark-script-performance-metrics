# Benchmark-script-performance-metrics
To benchmark the performance metrics of the optimized `js_all_in_one_recon.sh` script, we need to measure key aspects such as execution time, CPU usage, memory consumption, I/O operations, and regex efficiency. Below, I outline a comprehensive approach to benchmarking the script, including tools, methodologies, and specific metrics to collect, tailored to the script’s tasks (downloading JS files, prettifying, extracting data with regexes, probing URLs, and generating reports). Since I cannot execute the script directly, I’ll provide a detailed guide on how to benchmark it, including commands to run, metrics to track, and modifications to the script to enable profiling. I’ll also integrate the advanced optimization techniques (parallelism, regex optimization, I/O minimization) discussed previously to ensure we’re measuring the most efficient version.

---

### Benchmarking Approach

#### Objectives
- Measure **total execution time** and time per major step (download, prettify, extract, probe, report).
- Track **CPU usage** to identify bottlenecks in parallelized tasks or regex processing.
- Monitor **memory usage** to ensure in-memory processing (`/dev/shm`) doesn’t exhaust resources.
- Evaluate **I/O performance** (disk and network) to optimize file writes and downloads.
- Assess **regex efficiency** to confirm the optimized patterns (`ABS_URL_RE`, `SECRETS_RE`, etc.) perform well.
- Compare performance with and without optimizations (e.g., caching, parallel vs. sequential).

#### Tools
- **GNU `time`**: Measure execution time for the entire script and individual steps.
- **htop** or **top**: Monitor CPU and memory usage in real-time.
- **iotop**: Track disk I/O to identify bottlenecks in file writes/reads.
- **perf**: Profile CPU-intensive operations (e.g., regex processing with `rg`).
- **strace**: Count system calls (e.g., file operations, network requests).
- **curl** and **httpx**: Measure network performance for downloads and probes.
- **ripgrep (`rg`)**: Profile regex performance with `--stats` or `--trace`.
- **jq**: Analyze JSON output size and parsing efficiency (if `-o json` is used).

#### Setup
- **Test Environment**: Run on a consistent system (e.g., Linux with 4 CPU cores, 8GB RAM, SSD) to ensure comparable results.
- **Input Data**: Use a representative `js_list_file` with 100–1000 URLs to balance realism and test duration. Example:
  ```bash
  echo -e "https://example.com/script1.js\nhttps://example.com/script2.js" > js_files.txt
  ```
- **Output Directory**: Use `/dev/shm` for in-memory processing, as per the optimized script.
- **Dependencies**: Ensure all dependencies (`curl`, `rg`, `httpx`, `parallel`, `js-beautify`/`prettier`, `jq`, `timeout`) are installed.

---

### Modifications to the Script for Benchmarking
To collect detailed performance metrics, we’ll modify the script to:
- Add timing for each major step using `time`.
- Log CPU and memory usage with `ps` or `top`.
- Enable `rg --stats` for regex performance.
- Track I/O operations with a counter for file writes/reads.
- Output a benchmark report in JSON or text format.

Here’s the modified script with benchmarking integrated:

```bash
#!/usr/bin/env bash
# js_all_in_one_recon.sh - Ultra-optimized with benchmarking
# Usage: ./js_all_in_one_recon.sh -f <js_list_file> [-d <target_domain>] [-s <status_codes>] [-c <concurrency>] [-o <output_format>] [-p] [-C] [-r] [-b]
# Example: ./js_all_in_one_recon.sh -f js_files.txt -d example.com -s 200,404 -c 20 -o json -p -C -r -b

set -euo pipefail

# Defaults
INFILE=""
TARGET_DOMAIN=""
STATUS_CODES=""
CONCURRENCY=$(nproc 2>/dev/null || echo 20)
OUTPUT_FORMAT="txt"
PROGRESS=false
CACHE=false
PROFILE_REGEX=false
BENCHMARK=false
OUTDIR="/dev/shm/js_recon_out_$(date +%Y%m%d_%H%M%S)"
USE_PARALLEL=false
command -v parallel >/dev/null 2>&1 && USE_PARALLEL=true
BENCHMARK_LOG="$OUTDIR/benchmark_metrics.json"
IO_COUNT=0

# Parse flags
while getopts ":f:d:s:c:o:pCrb" opt; do
  case $opt in
    f) INFILE="$OPTARG" ;;
    d) TARGET_DOMAIN="$OPTARG" ;;
    s) STATUS_CODES="$OPTARG" ;;
    c) CONCURRENCY="$OPTARG" ;;
    o) OUTPUT_FORMAT="$OPTARG" ;;
    p) PROGRESS=true ;;
    C) CACHE=true ;;
    r) PROFILE_REGEX=true ;;
    b) BENCHMARK=true ;;
    \?) echo "Invalid option: -$OPTARG" >&2; exit 1 ;;
    :) echo "Option -$OPTARG requires an argument." >&2; exit 1 ;;
  esac
done

# Validate
[[ -z "$INFILE" || ! -f "$INFILE" ]] && { echo "Usage: $0 -f <js_list_file> [-d <target_domain>] [-s <status_codes>] [-c <concurrency>] [-o txt|json] [-p] [-C] [-r] [-b]"; exit 1; }
[[ "$OUTPUT_FORMAT" != "txt" && "$OUTPUT_FORMAT" != "json" ]] && { echo "Invalid output format"; exit 1; }
mkdir -p "$OUTDIR"/{raw,pretty,extracted,probes,report}
trap 'rm -rf "$OUTDIR"' EXIT

log_error() { echo "[ERROR] $(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >> "$OUTDIR/errors.log"; }

# Benchmarking functions
log_benchmark() {
  local step="$1" time_taken="$2" cpu="$3" mem="$4"
  if [[ "$BENCHMARK" == true && -x "$(command -v jq)" ]]; then
    jq -n --arg step "$step" --arg time "$time_taken" --arg cpu "$cpu" --arg mem "$mem" \
      --arg io "$IO_COUNT" '{step: $step, time_s: $time, cpu_percent: $cpu, mem_mb: $mem, io_ops: $io | tonumber}' \
      >> "$BENCHMARK_LOG"
  fi
}

track_io() { ((IO_COUNT++)); }

# Initialize benchmark log
[[ "$BENCHMARK" == true ]] && : > "$BENCHMARK_LOG"

echo "[*] Reading JS list: $INFILE"
mapfile -t JS_URLS < <(awk '!/^\s*($|#)/ {print}' "$INFILE" | sort -u)
[[ ${#JS_URLS[@]} -eq 0 ]] && { log_error "No valid URLs"; exit 1; }

# --- 1) Download files ---
download_js() {
  local url="$1" i="$2"
  local outfn="$OUTDIR/raw/$(echo -n "$url" | md5sum | cut -d' ' -f1).js"
  $CACHE && [[ -s "$outfn" ]] && { $PROGRESS && echo "Cached: $url" >&2; return; }
  curl -fsSL --max-time 30 --retry 2 --retry-delay 1 "$url" -o "$outfn" || log_error "Download failed: $url"
  track_io
  $PROGRESS && echo "[*] Downloaded $i/${#JS_URLS[@]}" >&2
}

echo "[*] Downloading ${#JS_URLS[@]} files (concurrency=$CONCURRENCY)..."
if $BENCHMARK; then
  { time (
    if $USE_PARALLEL; then
      export -f download_js OUTDIR CACHE PROGRESS
      parallel --line-buffer --load 80% -j "$CONCURRENCY" download_js '{1}' {#} ::: "${JS_URLS[@]}"
    else
      i=0
      for url in "${JS_URLS[@]}"; do
        i=$((i+1))
        download_js "$url" "$i" &
        (( i % CONCURRENCY == 0 )) && wait
      done
      wait
    fi
  ) } 2> "$OUTDIR/download_time.txt"
  TIME_TAKEN=$(awk '/real/ {print $2}' "$OUTDIR/download_time.txt" | sed 's/m.*s//')
  CPU=$(ps -eo %cpu --sort=-%cpu | head -n 1)
  MEM=$(ps -eo rss --sort=-rss | head -n 1 | awk '{print $1/1024}')
  log_benchmark "download" "$TIME_TAKEN" "$CPU" "$MEM"
else
  if $USE_PARALLEL; then
    export -f download_js OUTDIR CACHE PROGRESS
    parallel --line-buffer --load 80% -j "$CONCURRENCY" download_js '{1}' {#} ::: "${JS_URLS[@]}"
  else
    i=0
    for url in "${JS_URLS[@]}"; do
      i=$((i+1))
      download_js "$url" "$i" &
      (( i % CONCURRENCY == 0 )) && wait
    done
    wait
  fi
fi

# --- 2) Prettify files ---
prettify_js() {
  local f="$1" base="$(basename "$f")" pretty="$OUTDIR/pretty/$base.js"
  $CACHE && [[ -s "$pretty" ]] && return
  if command -v js-beautify >/dev/null 2>&1; then
    js-beautify "$f" > "$pretty" 2>/dev/null || cp "$f" "$pretty"
  elif command -v prettier >/dev/null 2>&1; then
    prettier --parser babel "$f" > "$pretty" 2>/dev/null || cp "$f" "$pretty"
  else
    tr -s '[:space:]' ' ' < "$f" | sed 's/^[[:space:]]*//g' > "$pretty" || cp "$f" "$pretty"
  fi
  track_io
  $PROGRESS && echo "[*] Prettified $f" >&2
}

echo "[*] Prettifying files..."
if $BENCHMARK; then
  { time (
    if $USE_PARALLEL; then
      export -f prettify_js OUTDIR CACHE PROGRESS
      parallel -j "$CONCURRENCY" prettify_js ::: "$OUTDIR"/raw/*
    else
      for f in "$OUTDIR"/raw/*; do
        prettify_js "$f" &
        (( $(jobs -p | wc -l) >= CONCURRENCY )) && wait -n
      done
      wait
    fi
  ) } 2> "$OUTDIR/prettify_time.txt"
  TIME_TAKEN=$(awk '/real/ {print $2}' "$OUTDIR/prettify_time.txt" | sed 's/m.*s//')
  CPU=$(ps -eo %cpu --sort=-%cpu | head -n 1)
  MEM=$(ps -eo rss --sort=-rss | head -n 1 | awk '{print $1/1024}')
  log_benchmark "prettify" "$TIME_TAKEN" "$CPU" "$MEM"
else
  if $USE_PARALLEL; then
    export -f prettify_js OUTDIR CACHE PROGRESS
    parallel -j "$CONCURRENCY" prettify_js ::: "$OUTDIR"/raw/*
  else
    for f in "$OUTDIR"/raw/*; do
      prettify_js "$f" &
      (( $(jobs -p | wc -l) >= CONCURRENCY )) && wait -n
    done
    wait
  fi
fi

# --- 3) Extractions ---
ABS_URL_RE='https?://[a-zA-Z0-9.-]+(?=/|$|[/?#])[A-Za-z0-9./?&=%_-]*'
REL_EP_RE='(?<=^/)[A-Za-z0-9._/?=&-]{3,100}(?<!/)'
SECRETS_RE1='AKIA[0-9A-Z]{16}'
SECRETS_RE2='AIza[0-9A-Za-z-_]{35}'
SECRETS_RE3='hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,50}'
SECRETS_RE4='[A-Za-z0-9_-]{20,50}\.[A-Za-z0-9_-]{20,50}\.[A-Za-z0-9_-]{20,50}'
AUTH_RE='\b(?:local|session)Storage|cookie|Authorization|(?:access|refresh)_token|(?:set|get)Item|Bearer\b'
DANGEROUS_RE1='document\.write'
DANGEROUS_RE2='innerHTML'
DANGEROUS_RE3='insertAdjacentHTML'
DANGEROUS_RE4='eval\('
DANGEROUS_RE5='new Function'
DANGEROUS_RE6='setTimeout\('
DANGEROUS_RE7='Function\('
DANGEROUS_RE8='outerHTML'
PRE_FILTER='https?://|AKIA|AIza|hooks\.slack|localStorage|sessionStorage|cookie|Authorization|access_token|refresh_token|setItem|getItem|Bearer|document\.write|innerHTML|insertAdjacentHTML|eval|new Function|setTimeout|Function|outerHTML'

echo "[*] Performing extractions..."
if $BENCHMARK || $PROFILE_REGEX; then
  { time (
    rg -l "$PRE_FILTER" "$OUTDIR/pretty" | \
      xargs -r rg --pcre2 -Pho --no-line-number --multiline --stats \
      "$ABS_URL_RE|$REL_EP_RE|$SECRETS_RE1|$SECRETS_RE2|$SECRETS_RE3|$SECRETS_RE4|$AUTH_RE|$DANGEROUS_RE1|$DANGEROUS_RE2|$DANGEROUS_RE3|$DANGEROUS_RE4|$DANGEROUS_RE5|$DANGEROUS_RE6|$DANGEROUS_RE7|$DANGEROUS_RE8" 2> "$OUTDIR/regex_stats.txt" | \
      awk -F'|' '{if ($0 ~ /https?:\/\//) print $0 > "'"$OUTDIR/extracted/absolute_urls.txt"'";
                  else if ($0 ~ /^\/[A-Za-z0-9]/) print $0 > "'"$OUTDIR/extracted/relative_endpoints.txt"'";
                  else if ($0 ~ /AKIA|AIza|hooks\.slack/) print $0 > "'"$OUTDIR/extracted/suspected_secrets.txt"'";
                  else if ($0 ~ /localStorage|sessionStorage|cookie|Authorization|access_token|refresh_token|setItem|getItem|Bearer/) print $0 > "'"$OUTDIR/extracted/auth_related_strings.txt"'";
                  else print $0 > "'"$OUTDIR/extracted/dangerous_sinks_with_ctx.txt"'"}' &
    wait
  ) } 2> "$OUTDIR/extract_time.txt"
  TIME_TAKEN=$(awk '/real/ {print $2}' "$OUTDIR/extract_time.txt" | sed 's/m.*s//')
  CPU=$(ps -eo %cpu --sort=-%cpu | head -n 1)
  MEM=$(ps -eo rss --sort=-rss | head -n 1 | awk '{print $1/1024}')
  log_benchmark "extract" "$TIME_TAKEN" "$CPU" "$MEM"
else
  rg -l "$PRE_FILTER" "$OUTDIR/pretty" | \
    xargs -r rg --pcre2 -Pho --no-line-number --multiline \
    "$ABS_URL_RE|$REL_EP_RE|$SECRETS_RE1|$SECRETS_RE2|$SECRETS_RE3|$SECRETS_RE4|$AUTH_RE|$DANGEROUS_RE1|$DANGEROUS_RE2|$DANGEROUS_RE3|$DANGEROUS_RE4|$DANGEROUS_RE5|$DANGEROUS_RE6|$DANGEROUS_RE7|$DANGEROUS_RE8" | \
    awk -F'|' '{if ($0 ~ /https?:\/\//) print $0 > "'"$OUTDIR/extracted/absolute_urls.txt"'";
                else if ($0 ~ /^\/[A-Za-z0-9]/) print $0 > "'"$OUTDIR/extracted/relative_endpoints.txt"'";
                else if ($0 ~ /AKIA|AIza|hooks\.slack/) print $0 > "'"$OUTDIR/extracted/suspected_secrets.txt"'";
                else if ($0 ~ /localStorage|sessionStorage|cookie|Authorization|access_token|refresh_token|setItem|getItem|Bearer/) print $0 > "'"$OUTDIR/extracted/auth_related_strings.txt"'";
                else print $0 > "'"$OUTDIR/extracted/dangerous_sinks_with_ctx.txt"'"}' &
  wait
fi
for f in "$OUTDIR/extracted/"*.txt; do
  [[ -s "$f" ]] && awk '!seen[$0]++' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
  track_io
done

# --- 4) Host detection & URL mapping ---
echo "[*] Building host list and probing URLs..."
if $BENCHMARK; then
  { time (
    : > "$OUTDIR/extracted/hosts.txt"
    : > "$OUTDIR/extracted/urls_to_probe.txt"
    if [[ -s "$OUTDIR/extracted/absolute_urls.txt" ]]; then
      tee >(cut -d/ -f3 | sed 's/:.*//' | awk '!seen[$0]++' > "$OUTDIR/extracted/hosts.txt") \
          < "$OUTDIR/extracted/absolute_urls.txt" >> "$OUTDIR/extracted/urls_to_probe.txt"
    elif [[ -n "$TARGET_DOMAIN" ]]; then
      echo "$TARGET_DOMAIN" > "$OUTDIR/extracted/hosts.txt"
    fi
    if [[ -s "$OUTDIR/extracted/relative_endpoints.txt" && -s "$OUTDIR/extracted/hosts.txt" ]]; then
      if [[ -n "$TARGET_DOMAIN" ]]; then
        echo "[*] Mapping to target domain: $TARGET_DOMAIN"
        awk -v d="$TARGET_DOMAIN" '{print "https://" d ($0 ~ /^\// ? $0 : "/" $0)}' "$OUTDIR/extracted/relative_endpoints.txt" >> "$OUTDIR/extracted/urls_to_probe.txt"
      else
        echo "[*] Mapping to discovered hosts..."
        while read -r host; do
          awk -v h="$host" '{print "https://" h ($0 ~ /^\// ? $0 : "/" $0)}' "$OUTDIR/extracted/relative_endpoints.txt" >> "$OUTDIR/extracted/urls_to_probe.txt"
        done < "$OUTDIR/extracted/hosts.txt"
      fi
    fi
    sort -u -o "$OUTDIR/extracted/urls_to_probe.txt" "$OUTDIR/extracted/urls_to_probe.txt"
    track_io
  ) } 2> "$OUTDIR/mapping_time.txt"
  TIME_TAKEN=$(awk '/real/ {print $2}' "$OUTDIR/mapping_time.txt" | sed 's/m.*s//')
  CPU=$(ps -eo %cpu --sort=-%cpu | head -n 1)
  MEM=$(ps -eo rss --sort=-rss | head -n 1 | awk '{print $1/1024}')
  log_benchmark "mapping" "$TIME_TAKEN" "$CPU" "$MEM"
else
  : > "$OUTDIR/extracted/hosts.txt"
  : > "$OUTDIR/extracted/urls_to_probe.txt"
  if [[ -s "$OUTDIR/extracted/absolute_urls.txt" ]]; then
    tee >(cut -d/ -f3 | sed 's/:.*//' | awk '!seen[$0]++' > "$OUTDIR/extracted/hosts.txt") \
        < "$OUTDIR/extracted/absolute_urls.txt" >> "$OUTDIR/extracted/urls_to_probe.txt"
  elif [[ -n "$TARGET_DOMAIN" ]]; then
    echo "$TARGET_DOMAIN" > "$OUTDIR/extracted/hosts.txt"
  fi
  if [[ -s "$OUTDIR/extracted/relative_endpoints.txt" && -s "$OUTDIR/extracted/hosts.txt" ]]; then
    if [[ -n "$TARGET_DOMAIN" ]]; then
      echo "[*] Mapping to target domain: $TARGET_DOMAIN"
      awk -v d="$TARGET_DOMAIN" '{print "https://" d ($0 ~ /^\// ? $0 : "/" $0)}' "$OUTDIR/extracted/relative_endpoints.txt" >> "$OUTDIR/extracted/urls_to_probe.txt"
    else
      echo "[*] Mapping to discovered hosts..."
      while read -r host; do
        awk -v h="$host" '{print "https://" h ($0 ~ /^\// ? $0 : "/" $0)}' "$OUTDIR/extracted/relative_endpoints.txt" >> "$OUTDIR/extracted/urls_to_probe.txt"
      done < "$OUTDIR/extracted/hosts.txt"
    fi
  fi
  sort -u -o "$OUTDIR/extracted/urls_to_probe.txt" "$OUTDIR/extracted/urls_to_probe.txt"
  track_io
fi

probe_count=$(wc -l < "$OUTDIR/extracted/urls_to_probe.txt" || echo 0)
echo "[*] URLs to probe: $probe_count"
if [[ $probe_count -gt 10000 ]]; then
  log_error "Too many URLs, truncating to 10,000"
  head -n 10000 "$OUTDIR/extracted/urls_to_probe.txt" > "$OUTDIR/extracted/urls_to_probe_limited.txt"
  mv "$OUTDIR/extracted/urls_to_probe_limited.txt" "$OUTDIR/extracted/urls_to_probe.txt"
  track_io
fi

# --- 5) Probe with httpx ---
if command -v httpx >/dev/null 2>&1 && [[ -s "$OUTDIR/extracted/urls_to_probe.txt" ]]; then
  echo "[*] Probing with httpx..."
  httpx_cmd="httpx -silent -status -title -ip -content-type -threads $CONCURRENCY -follow-redirects -timeout 10 -o $OUTDIR/probes/httpx_results.txt"
  [[ -n "$STATUS_CODES" ]] && httpx_cmd="$httpx_cmd -sc $STATUS_CODES"
  if $BENCHMARK; then
    { time timeout 300s cat "$OUTDIR/extracted/urls_to_probe.txt" | $httpx_cmd || log_error "httpx probe failed"; } 2> "$OUTDIR/probe_time.txt"
    TIME_TAKEN=$(awk '/real/ {print $2}' "$OUTDIR/probe_time.txt" | sed 's/m.*s//')
    CPU=$(ps -eo %cpu --sort=-%cpu | head -n 1)
    MEM=$(ps -eo rss --sort=-rss | head -n 1 | awk '{print $1/1024}')
    log_benchmark "probe" "$TIME_TAKEN" "$CPU" "$MEM"
  else
    timeout 300s cat "$OUTDIR/extracted/urls_to_probe.txt" | $httpx_cmd || log_error "httpx probe failed"
  fi
  track_io
fi

# --- 6) Query param URLs ---
if [[ -s "$OUTDIR/probes/httpx_results.txt" ]]; then
  awk '/\?/{print $1}' "$OUTDIR/probes/httpx_results.txt" | sort -u > "$OUTDIR/extracted/urls_with_query.txt"
elif [[ -s "$OUTDIR/extracted/urls_to_probe.txt" ]]; then
  grep '?' "$OUTDIR/extracted/urls_to_probe.txt" | sort -u > "$OUTDIR/extracted/urls_with_query.txt"
fi
track_io

# --- 7) Cookie header checks ---
if command -v httpx >/dev/null 2>&1 && [[ -s "$OUTDIR/extracted/hosts.txt" ]]; then
  echo "[*] Checking cookie flags..."
  if $BENCHMARK; then
    { time (
      : > "$OUTDIR/probes/cookie_flags_summary.txt"
      while read -r host; do
        echo "---- $host ----" >> "$OUTDIR/probes/cookie_flags_summary.txt"
        echo "https://$host" | httpx -silent -H 'User-Agent: recon-bot' -headers | rg -i 'set-cookie' -n || echo "No Set-Cookie" >> "$OUTDIR/probes/cookie_flags_summary.txt"
        echo "" >> "$OUTDIR/probes/cookie_flags_summary.txt"
      done < "$OUTDIR/extracted/hosts.txt"
      track_io
    ) } 2> "$OUTDIR/cookie_time.txt"
    TIME_TAKEN=$(awk '/real/ {print $2}' "$OUTDIR/cookie_time.txt" | sed 's/m.*s//')
    CPU=$(ps -eo %cpu --sort=-%cpu | head -n 1)
    MEM=$(ps -eo rss --sort=-rss | head -n 1 | awk '{print $1/1024}')
    log_benchmark "cookie_check" "$TIME_TAKEN" "$CPU" "$MEM"
  else
    : > "$OUTDIR/probes/cookie_flags_summary.txt"
    while read -r host; do
      echo "---- $host ----" >> "$OUTDIR/probes/cookie_flags_summary.txt"
      echo "https://$host" | httpx -silent -H 'User-Agent: recon-bot' -headers | rg -i 'set-cookie' -n || echo "No Set-Cookie" >> "$OUTDIR/probes/cookie_flags_summary.txt"
      echo "" >> "$OUTDIR/probes/cookie_flags_summary.txt"
    done < "$OUTDIR/extracted/hosts.txt"
    track_io
  fi
fi

# --- 8) CSV for httpx ---
if [[ -s "$OUTDIR/probes/httpx_results.txt" ]]; then
  awk 'BEGIN{OFS=","}{gsub(/,/, " "); print $1,$2,$3,$4,$5}' "$OUTDIR/probes/httpx_results.txt" > "$OUTDIR/probes/httpx_results.csv"
  track_io
fi

# --- 9) Generate report ---
echo "[*] Generating report..."
REPORT="$OUTDIR/report/triage_summary.${OUTPUT_FORMAT}"
if [[ "$OUTPUT_FORMAT" == "json" && -x "$(command -v jq)" ]]; then
  if $BENCHMARK; then
    { time (
      jq -n --arg infile "$INFILE" --arg target "$TARGET_DOMAIN" --arg status "$STATUS_CODES" \
        --arg js "$(ls -1 "$OUTDIR/raw" | wc -l)" \
        --arg abs "$(wc -l < "$OUTDIR/extracted/absolute_urls.txt" || echo 0)" \
        --arg rel "$(wc -l < "$OUTDIR/extracted/relative_endpoints.txt" || echo 0)" \
        --arg secrets "$(wc -l < "$OUTDIR/extracted/suspected_secrets.txt" || echo 0)" \
        --arg auth "$(wc -l < "$OUTDIR/extracted/auth_related_strings.txt" || echo 0)" \
        --arg sinks "$(wc -l < "$OUTDIR/extracted/dangerous_sinks_with_ctx.txt" || echo 0)" \
        --arg probe "$(wc -l < "$OUTDIR/extracted/urls_to_probe.txt" || echo 0)" \
        --arg httpx "$(wc -l < "$OUTDIR/probes/httpx_results.txt" || echo 0)" \
        '{
          generated: (now | strftime("%Y-%m-%d %H:%M:%SZ")),
          input_file: $infile, target_domain: $target, status_codes: $status,
          counts: {js_files: $js|tonumber, absolute_urls: $abs|tonumber, relative_endpoints: $rel|tonumber, 
                   suspected_secrets: $secrets|tonumber, auth_strings: $auth|tonumber, dangerous_sinks: $sinks|tonumber,
                   urls_to_probe: $probe|tonumber, probed_urls: $httpx|tonumber},
          recommendations: ["Review secrets/sinks", "Test XSS safely", "Disclose responsibly"]
        }' > "$REPORT"
      track_io
    ) } 2> "$OUTDIR/report_time.txt"
    TIME_TAKEN=$(awk '/real/ {print $2}' "$OUTDIR/report_time.txt" | sed 's/m.*s//')
    CPU=$(ps -eo %cpu --sort=-%cpu | head -n 1)
    MEM=$(ps -eo rss --sort=-rss | head -n 1 | awk '{print $1/1024}')
    log_benchmark "report" "$TIME_TAKEN" "$CPU" "$MEM"
  else
    jq -n --arg infile "$INFILE" --arg target "$TARGET_DOMAIN" --arg status "$STATUS_CODES" \
      --arg js "$(ls -1 "$OUTDIR/raw" | wc -l)" \
      --arg abs "$(wc -l < "$OUTDIR/extracted/absolute_urls.txt" || echo 0)" \
      --arg rel "$(wc -l < "$OUTDIR/extracted/relative_endpoints.txt" || echo 0)" \
      --arg secrets "$(wc -l < "$OUTDIR/extracted/suspected_secrets.txt" || echo 0)" \
      --arg auth "$(wc -l < "$OUTDIR/extracted/auth_related_strings.txt" || echo 0)" \
      --arg sinks "$(wc -l < "$OUTDIR/extracted/dangerous_sinks_with_ctx.txt" || echo 0)" \
      --arg probe "$(wc -l < "$OUTDIR/extracted/urls_to_probe.txt" || echo 0)" \
      --arg httpx "$(wc -l < "$OUTDIR/probes/httpx_results.txt" || echo 0)" \
      '{
        generated: (now | strftime("%Y-%m-%d %H:%M:%SZ")),
        input_file: $infile, target_domain: $target, status_codes: $status,
        counts: {js_files: $js|tonumber, absolute_urls: $abs|tonumber, relative_endpoints: $rel|tonumber, 
                 suspected_secrets: $secrets|tonumber, auth_strings: $auth|tonumber, dangerous_sinks: $sinks|tonumber,
                 urls_to_probe: $probe|tonumber, probed_urls: $httpx|tonumber},
        recommendations: ["Review secrets/sinks", "Test XSS safely", "Disclose responsibly"]
      }' > "$REPORT"
    track_io
  fi
else
  if $BENCHMARK; then
    { time (
      {
        echo "JS Recon Triage Report"
        echo "Generated: $(date -u +"%Y-%m-%d %H:%M:%SZ")"
        echo "Input: $INFILE"
        [[ -n "$TARGET_DOMAIN" ]] && echo "Target: $TARGET_DOMAIN"
        [[ -n "$STATUS_CODES" ]] && echo "Status filter: $STATUS_CODES"
        echo "Counts:"
        echo " - JS files: $(ls -1 "$OUTDIR/raw" | wc -l)"
        echo " - Abs URLs: $(wc -l < "$OUTDIR/extracted/absolute_urls.txt" || echo 0)"
        echo " - Rel EPs: $(wc -l < "$OUTDIR/extracted/relative_endpoints.txt" || echo 0)"
        echo " - Secrets: $(wc -l < "$OUTDIR/extracted/suspected_secrets.txt" || echo 0)"
        echo " - Auth: $(wc -l < "$OUTDIR/extracted/auth_related_strings.txt" || echo 0)"
        echo " - Sinks: $(wc -l < "$OUTDIR/extracted/dangerous_sinks_with_ctx.txt" || echo 0)"
        echo " - Probes: $(wc -l < "$OUTDIR/extracted/urls_to_probe.txt" || echo 0)"
        echo " - Httpx: $(wc -l < "$OUTDIR/probes/httpx_results.txt" || echo 0)"
        echo "Top Abs URLs:"; head -15 "$OUTDIR/extracted/absolute_urls.txt" || true
        echo "Top Secrets:"; head -15 "$OUTDIR/extracted/suspected_secrets.txt" || true
        echo "Top Sinks:"; head -20 "$OUTDIR/extracted/dangerous_sinks_with_ctx.txt" || true
        echo "Recommendations: Review secrets/sinks, test XSS safely, disclose responsibly"
      } > "$REPORT"
      track_io
    ) } 2> "$OUTDIR/report_time.txt"
    TIME_TAKEN=$(awk '/real/ {print $2}' "$OUTDIR/report_time.txt" | sed 's/m.*s//')
    CPU=$(ps -eo %cpu --sort=-%cpu | head -n 1)
    MEM=$(ps -eo rss --sort=-rss | head -n 1 | awk '{print $1/1024}')
    log_benchmark "report" "$TIME_TAKEN" "$CPU" "$MEM"
  else
    {
      echo "JS Recon Triage Report"
      echo "Generated: $(date -u +"%Y-%m-%d %H:%M:%SZ")"
      echo "Input: $INFILE"
      [[ -n "$TARGET_DOMAIN" ]] && echo "Target: $TARGET_DOMAIN"
      [[ -n "$STATUS_CODES" ]] && echo "Status filter: $STATUS_CODES"
      echo "Counts:"
      echo " - JS files: $(ls -1 "$OUTDIR/raw" | wc -l)"
      echo " - Abs URLs: $(wc -l < "$OUTDIR/extracted/absolute_urls.txt" || echo 0)"
      echo " - Rel EPs: $(wc -l < "$OUTDIR/extracted/relative_endpoints.txt" || echo 0)"
      echo " - Secrets: $(wc -l < "$OUTDIR/extracted/suspected_secrets.txt" || echo 0)"
      echo " - Auth: $(wc -l < "$OUTDIR/extracted/auth_related_strings.txt" || echo 0)"
      echo " - Sinks: $(wc -l < "$OUTDIR/extracted/dangerous_sinks_with_ctx.txt" || echo 0)"
      echo " - Probes: $(wc -l < "$OUTDIR/extracted/urls_to_probe.txt" || echo 0)"
      echo " - Httpx: $(wc -l < "$OUTDIR/probes/httpx_results.txt" || echo 0)"
      echo "Top Abs URLs:"; head -15 "$OUTDIR/extracted/absolute_urls.txt" || true
      echo "Top Secrets:"; head -15 "$OUTDIR/extracted/suspected_secrets.txt" || true
      echo "Top Sinks:"; head -20 "$OUTDIR/extracted/dangerous_sinks_with_ctx.txt" || true
      echo "Recommendations: Review secrets/sinks, test XSS safely, disclose responsibly"
    } > "$REPORT"
    track_io
  fi
fi

# Summarize benchmark metrics
if [[ "$BENCHMARK" == true && -s "$BENCHMARK_LOG" && -x "$(command -v jq)" ]]; then
  jq -s '{
    total_time_s: map(.time_s | tonumber) | add,
    avg_cpu_percent: map(.cpu_percent | tonumber) | add / length,
    max_mem_mb: map(.mem_mb | tonumber) | max,
    total_io_ops: map(.io_ops | tonumber) | max,
    steps: .
  }' "$BENCHMARK_LOG" > "$OUTDIR/benchmark_summary.json"
fi

echo "[*] Done. Outputs in $OUTDIR"
echo "Report: $REPORT"
[[ "$BENCHMARK" == true ]] && echo "Benchmark: $OUTDIR/benchmark_summary.json"
echo "Reminder: Responsible use only."
```

---

### Benchmarking Metrics to Collect

#### 1. Execution Time
- **Total Time**: Measure the entire script runtime.
  ```bash
  time ./js_all_in_one_recon.sh -f js_files.txt -b
  ```
- **Per-Step Time**: Extract from `$OUTDIR/*_time.txt` files (download, prettify, extract, mapping, probe, cookie_check, report).
  - Example output: `download_time.txt` shows `real 1m23.456s`.
  - Summarized in `$OUTDIR/benchmark_summary.json` (if `-b` is used).
- **Metric**: Seconds per step, total seconds.

#### 2. CPU Usage
- **Per-Step CPU**: Captured via `ps -eo %cpu` in `log_benchmark`.
  - Example: `cpu_percent: 75.2` for the download step.
- **System-Wide CPU**: Monitor with `htop` or:
  ```bash
  top -b -n 1 | head -n 5
  ```
- **Metric**: Average CPU % per step, peak CPU usage.

#### 3. Memory Usage
- **Per-Step Memory**: Captured via `ps -eo rss` in `log_benchmark`.
  - Example: `mem_mb: 512.3` for the extraction step.
- **System-Wide Memory**: Monitor with:
  ```bash
  free -m
  ```
- **Metric**: Peak memory (MB), average memory per step.

#### 4. I/O Operations
- **Disk I/O**: Track file writes/reads with `IO_COUNT` in the script.
  - Example: `io_ops: 150` in `$OUTDIR/benchmark_summary.json`.
  - Use `iotop` for real-time disk I/O:
    ```bash
    sudo iotop -o
    ```
- **Network I/O**: Measure download/probe bandwidth with `iftop`:
  ```bash
  sudo iftop -i eth0
  ```
- **Metric**: Number of file operations, bytes read/written, network bytes sent/received.

#### 5. Regex Performance
- **Matches and Time**: Use `rg --stats` to get match counts and time:
  ```bash
  rg --stats -Pho "$ABS_URL_RE" "$OUTDIR/pretty" > /dev/null
  ```
  - Example output: `1000 matches in 0.234s`.
- **Per-Pattern Metrics**: Extract from `$OUTDIR/regex_stats.txt` when `-r` or `-b` is used.
- **Metric**: Matches per second, total regex processing time.

#### 6. System Calls
- **Count System Calls**: Use `strace` to count file and network operations:
  ```bash
  strace -c -o strace_summary.txt ./js_all_in_one_recon.sh -f js_files.txt
  ```
- **Metric**: Number of `open`, `read`, `write`, `connect` calls.

#### 7. Output Size
- **File Sizes**: Measure output file sizes to ensure efficiency:
  ```bash
  du -sh "$OUTDIR"/*
  ```
- **Metric**: Size (MB) of `absolute_urls.txt`, `suspected_secrets.txt`, etc.

---

### Running the Benchmark
1. **Prepare Input**: Create a test file with 100–1000 JS URLs:
   ```bash
   for i in {1..100}; do echo "https://example.com/script$i.js"; done > js_files.txt
   ```
2. **Run with Benchmarking**:
   ```bash
   ./js_all_in_one_recon.sh -f js_files.txt -d example.com -s 200,404 -c 20 -o json -p -C -r -b
   ```
3. **Monitor Real-Time**:
   - CPU/Memory: `htop` or `top -b -n 1`.
   - Disk I/O: `sudo iotop -o`.
   - Network: `sudo iftop -i eth0`.
4. **Collect Metrics**:
   - Check `$OUTDIR/benchmark_summary.json` for a summary.
   - Review `$OUTDIR/regex_stats.txt` for regex performance.
   - Analyze `strace_summary.txt` for system calls.

---

### Expected Metrics (Hypothetical)
Based on a test with 100 URLs, 4-core CPU, 8GB RAM, SSD, and `/dev/shm`:
- **Total Time**: ~60–120s (depends on network speed).
- **Download**: 30–60s, 50–80% CPU, 200–500MB memory.
- **Prettify**: 10–20s, 60–90% CPU, 300–600MB memory.
- **Extract**: 5–15s, 70–100% CPU, 100–300MB memory (optimized regexes reduce this).
- **Probe**: 15–30s, 40–70% CPU, 200–400MB memory.
- **I/O Ops**: ~200–500 file operations, ~50–200MB written.
- **Regex Matches**: 1000–5000 matches, ~0.1–0.5s per pattern.

---

### Analysis and Optimization
- **Bottlenecks**:
  - **Network**: Download and probe steps are network-bound. Optimize with `--retry` and `-timeout` in `curl`/`httpx`.
  - **Regex**: Extraction is CPU-intensive. The pre-filtering (`rg -l`) and split patterns reduce this significantly.
  - **I/O**: Using `/dev/shm` minimizes disk I/O, but large URL lists may still hit memory limits.
- **Improvements**:
  - Increase `CONCURRENCY` if network latency is low.
  - Further split regexes if `regex_stats.txt` shows slow patterns.
  - Cache more aggressively with `-C` for repeated runs.

---

### Visualizing Metrics
To visualize the benchmark results, you can generate a chart from `$OUTDIR/benchmark_summary.json`. Since you didn’t explicitly request a chart, I’ll provide the command to generate one if desired:

```bash
jq -r '.steps[] | [.step, .time_s] | @csv' "$OUTDIR/benchmark_summary.json" > "$OUTDIR/benchmark_times.csv"
```

Then, use a tool like Python’s `matplotlib` or a spreadsheet to plot step times. If you want a Chart.js chart, run:

```bash
# Example Chart.js config (run in a JavaScript environment or use a tool to render)
{
  type: 'bar',
  data: {
    labels: ['download', 'prettify', 'extract', 'mapping', 'probe', 'cookie_check', 'report'],
    datasets: [{
      label: 'Time (seconds)',
      data: $(jq -r '.steps[] | .time_s' "$OUTDIR/benchmark_summary.json" | tr '\n' ','),
      backgroundColor: ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2']
    }]
  },
  options: { scales: { y: { beginAtZero: true, title: { display: true, text: 'Time (s)' } } } }
}
```

This script and benchmarking setup provide a comprehensive way to measure and optimize performance. Run it with `-b` and analyze `$OUTDIR/benchmark_summary.json` to identify bottlenecks. Let me know if you need help interpreting results or further optimizations!
