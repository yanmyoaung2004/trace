# InnoIgniterAI — Next Steps

## Short Term

- [ ] Run `innoigniter init` to configure API keys (VT, AbuseIPDB, OTX)
- [ ] Start the server: `innoigniter server --http-addr :8080`
- [ ] Connect edge nodes: `innoigniter serve --siem --server-addr http://host:8080`
- [ ] Feed real logs into SIEM watcher (`--log-dir`)
- [ ] Run investigations on actual indicators
- [ ] Run the demo: `.\docs\end-to-end-demo.ps1`

## Medium Term

- [ ] Write custom playbooks for your specific environment
- [ ] Tune SIEM rules to reduce false positives
- [ ] Set up TLS for production: `innoigniter genkey --host your-server.com`
- [ ] Deploy via Docker Compose: `docker compose up server`
- [ ] Add more built-in IOCs as you discover them
- [ ] Write integration tests for your custom playbooks

## Long Term

- [ ] Containerize edge nodes for endpoint deployment
- [ ] Connect to existing SIEM (Splunk/Elastic)
- [ ] Build a custom web UI on top of the API
- [ ] Set up a release pipeline (GitHub Actions already configured)
- [ ] Performance profiling under real workload
- [ ] Security audit before production
