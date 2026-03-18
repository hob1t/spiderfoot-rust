# spiderfoot-rust
Rust implementation of SpiderFoot.

## The Problem
SpiderFoot is a powerful OSINT tool, but its Python implementation faces several challenges:
- **Performance:** Python's GIL and synchronous I/O limit scanning speed.
- **Efficiency:** High resource consumption during large-scale scans.
- **Stability:** Maintenance of the original project has slowed (last commit to `master` was in late 2023).

## Truverack’s Mission
Our mission is to rewrite and maintain SpiderFoot in Rust to provide a high-performance, resource-efficient, and production-ready alternative.

The original project can be found at [github.com/smicallef/spiderfoot](https://github.com/smicallef/spiderfoot).

## Project Structure
- `src/core/`: The foundational traits and types for the module system and event-driven architecture.
- `src/modules/`: Individual OSINT modules implemented as async tasks.
- `src/rate_limit/`: Rate-limiting logic for module execution.
- `tests/`: Integration and unit tests, including live scan verifications.

## Currently Implemented Modules
- `sfp_spider`: Asynchronous web crawler to fetch page content.
- `sfp_dnsresolve`: Forward and reverse DNS resolution (A, AAAA, MX, NS, TXT, PTR).
- `sfp_google_tag_manager`: Extracts GTM IDs and identifies shared hostnames.
- `sfp_company`: Identifies company names from web content and WHOIS data.
- `sfp_whois`: RDAP/WHOIS lookup module (Skeleton).
- `sfp_accounts`: Checks for account existence on various platforms (Skeleton).

## Roadmap
1. **Phase 1: Foundation (Completed)**
   - Core async architecture with Tokio.
   - Event emission and logging system.
   - Initial set of passive modules.
2. **Phase 2: Expansion (In Progress)**
   - Implement more passive and active modules.
   - Enhance the event bus and rate-limiting manager.
   - Expand test coverage with more real-world scenarios.
3. **Phase 3: Integration**
   - Persistence layer (SQLite integration).
   - API key management.
4. **Phase 4: Advanced Features**
   - Correlation engine.
   - CLI and Web UI.

## Running Tests
To run all tests:
```bash
cargo test
```
To run live network tests (ignored by default):
```bash
cargo test -- --ignored
```
