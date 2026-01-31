# spiderfoot-rust
rust impl of spiderfoot
## Main problem with python - sucks, not resources efficient, not prod resilient

## Truverack’s mission is to rewrite and maintain

Sounds good—diving into the SpiderFoot repo is the perfect starting point for planning a Rust rewrite. The official repository is at [github.com/smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) (16.5k stars, 2.8k forks as of early 2026, actively maintained with ongoing commits).

### Current Structure Overview
- **Core components** (top-level and in `spiderfoot/` dir):
  - `sf.py`: Main entry point for the web server/UI.
  - `sfcli.py`: CLI interface.
  - `sfscan.py`: The core scanner/orchestrator.
  - `sflib.py`: Library with utilities (logging, DB handling, event processing).
  - `sfwebui.py`: Web UI (Flask-based).
- **Modules**: Flat directory at `/modules` with **223** files named `sfp_*.py` (e.g., `sfp_dnsresolve.py`, `sfp_shodan.py`, `sfp_virustotal.py`). No subfolders—purely flat. Many are tied to specific APIs/services (DNS, threat intel, social, whois, tools like Nmap/Nuclei wrappers). There's a `sfp_template.py` for new module development.
- **Other key dirs**:
  - `correlations/`: YAML-based correlation rules (37+ pre-defined).
  - `docs/`: Documentation.
- **Architecture basics** (from README and code patterns): Publisher/subscriber (event-driven) model. Scans start with a seed target → modules watch for specific event types (e.g., DOMAIN_NAME) → produce new events (e.g., IP_ADDRESS) → other modules consume them. Everything stored in SQLite. Correlation engine links related data post-scan.

This event-driven flow is what makes SpiderFoot powerful but also bloated/slow in Python (GIL limits true parallelism, sync-heavy I/O).

### Proposed Rust Rewrite Plan: Incremental, Performant Focus
We'll aim for a **native, compiled binary** (single static executable, no Python deps) with Tokio for async concurrency (massive perf win on I/O-bound API calls/DNS/web ops). Use rusqlite for DB compatibility (easy migration), reqwest for HTTP, trust-dns or similar for DNS.

Start **minimal viable core** (CLI-only, no web UI yet), prove it works on a simple scan, then add modules iteratively. Prioritize high-impact ones first (passive/fast, no API keys).

| Phase | Goals | Key Implementations | Estimated Effort | Why This Order/Perf Wins |
|-------|-------|---------------------|------------------|--------------------------|
| **0: Setup & Foundations** | Project skeleton, basic types. | - Cargo project with Tokio, rusqlite, serde, clap (CLI), log/env_logger.<br>- Define core enums: `EventType` (50+ from SpiderFoot, e.g., INTERNET_NAME, IP_ADDRESS, EMAILADDR, AFFILIATE_IPADDR).<br>- `Event` struct (type, data, source_module, target).<br>- Simple in-memory event bus (later replace with channel-based async queue). | 1-2 weeks | Gets compile-time safety early; Rust enums prevent invalid events (vs Python strings). |
| **1: Minimal Scanner Core** | Run a basic scan end-to-end (seed → events → DB storage). | - Scan config (target, selected modules, opts via TOML/CLI).<br>- `Scanner` struct: async task spawner, event queue (mpsc channel), module registry.<br>- DB schema mimic (tables for scans, events, entities).<br>- Two required modules:<br>  - Storage module (`sfp__stor_db` equivalent): Persists all events.<br>  - Output module (`sfp__stor_stdout`): Prints results.<br>- Basic internal modules: `sfp_dnsresolve` (async DNS lookups via trust-dns), `sfp_dnsbrute` (simple wordlist brute-force). | 2-4 weeks | This gives a working "hello world" scan (e.g., domain → resolve IPs). Async from day 1 = 5-10x faster on multi-module runs vs Python. |
| **2: Module System & First Batch** | Trait-based modules, easy to add more. | - `Module` trait: `info()`, `watches() -> Vec<EventType>`, `produces() -> Vec<EventType>`, `async fn handle_event(&self, event: Event) -> Vec<Event>`.<br>- Hardcode/register modules statically (use inventory crate later for "plugins").<br>- Add 10-15 high-value passive modules:<br>  - DNS: `sfp_dnscommonsrv`, `sfp_dnsraw`, `sfp_dnsneighbor`.<br>  - Web: `sfp_spider` (async crawler with scraper/reqwest), `sfp_pageinfo`.<br>  - Intel: `sfp_abusech`, `sfp_spamhaus` (public feeds, no keys).<br>  - Utilities: `sfp_filemeta`, `sfp_hashes`.<br>- Basic correlation (port YAML rules to Rust logic). | 4-6 weeks | Trait system makes adding modules trivial (one file per). Parallel execution: spawn module tasks, feed events concurrently—no GIL bottlenecks. |
| **3: Mid-Tier Expansion** | Broader coverage, API support. | - Config for API keys (encrypted storage?).<br>- Add 20-30 popular keyed modules: `sfp_shodan`, `sfp_virustotal`, `sfp_censys`, `sfp_binaryedge`, `sfp_fullhunt`.<br>- Active modules: `sfp_portscan_tcp` (via async sockets), tool wrappers (exec Nmap/Nuclei if installed).<br>- Exports: JSON/CSV (serde), basic GEXF. | 6-8 weeks | Rate-limiting/throttling per-module (async semaphores) prevents bans, far more efficient than Python threads. |
| **4: Polish & Advanced** | Usability, full parity. | - Web UI (Axum or Rocket server, HTMX/Svelte frontend).<br>- Full 200+ modules (community contributions?).<br>- TOR/proxy support, visualizations (export to Graphviz?), Docker binary.<br>- Dynamic module loading (if needed, via libloading). | Ongoing | Single binary deployment = huge win over Python env hell. |

This phased approach keeps motivation high—you'll have a usable, faster tool after Phase 1 (e.g., basic domain recon in seconds vs minutes). We can prioritize modules based on your needs (e.g., focus on threat intel or subdomain enum first?).

What do you think—start coding Phase 0/1? Any specific modules or features you want in the minimal version? Or preferences on crates/UI? Let's iterate!
