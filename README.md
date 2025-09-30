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
