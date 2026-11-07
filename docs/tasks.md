# Tasks

Update this file in the same PR as the work it describes.

## Now: Phase 1, first working checker

- [x] Checker with fixed wording for results, so it can't say "safe"
- [x] Command-line check for a single message
- [x] Eval runner with a small prompt-injection set
- [x] First live eval: `evals/reports/2026-11-06T214353Z-anthropic_claude-haiku-5.5.json`. Smoke test only: 24 messages, 5 of them legit
- [x] Merge the first checker with its eval results

## Next: data foundation

Do these before any more features, in this order:

1. [x] Source check: results in `docs/data-sources.md`. Start with Scamwatch, the ATO and CommBank, once CommBank's terms are read
2. [x] Grow the eval set to 100 messages, split evenly between scam and legit. Latest report: `evals/reports/2026-11-07T011406Z-anthropic_claude-haiku-5.5.json`
3. [ ] Private config backup, because the knowledge base is scam-pattern intelligence
4. [ ] Knowledge base in Postgres on local Docker, kept out of the public repo, with scam types, variants, sources and dates from 2–3 independent sources
5. [ ] Run the evals with and without the knowledge base, and only build on it if results improve

Keep eval messages out of the knowledge base, ideally using newer alerts, or scores will be inflated.

## Deferred from Phase 0

| Task | Reason deferred | Revisit |
|---|---|---|
| Privacy design | Deferred until after the first checker | Before any public launch or stored user data |
| ADRs: stack, model routing, data retention, eval gates | Deferred until after the first checker | Before the knowledge base is built |
| 100 more labelled messages | At 100 of 200 | Add in batches alongside the build |
| Owner review of every label | Required by the labelling guide | Before quoting results as a performance claim |
| Relabel 10% and record the disagreement rate | Set reached 100 messages; not yet done | After the owner label review |
| Private config backup | Backup not yet set up | Before the knowledge base or red-team findings go in |
| Security contact | No launch yet | Before launch |
| Product brief questions: iPhone or Android, brand name and domain | Not blocking the build | Before the browser-installable app ships |
| Review recurring false alarms: syn-040, syn-045, syn-048, syn-065, syn-066 and syn-076 | Found in the 100-message evals. syn-048 is ambiguous by design | Before the knowledge base comparison |
| Pin a provider and report repeated eval runs | Identical runs varied | Before the knowledge base comparison |
| Source real legit messages, with consent or clear licences | All 50 are synthetic, so real-world false alarms are unmeasured | Before quoting results as a performance claim |
| Competitor benchmark: Norton Genie, Scamio, Truyu | Needs a useful checker and dataset first | After the first reliable eval |

## After the data foundation: rest of Phase 1

- [ ] Parallel tool agents: domain age, URL reputation, ABN lookup, phone line type
- [ ] Escalate uncertain results to a stronger model
- [ ] Plain-English writer and safety reviewer
- [ ] Move tuned prompts to private config once tuning starts
- [ ] CI regression gates for evals
- [ ] Tracing with personal data masked
- [ ] Browser-installable app and forward-to-email
- [ ] Screenshot and voicemail input
- [ ] README: live link, product walkthrough, architecture diagram, eval results and eval history chart

## Decisions we may revisit

- **Scamwatch quoted messages:** treated as covered by CC BY 3.0 AU. Revisit before any public launch.
- **Real messages:** 14 from Scamwatch. Look for more sources, including messages people contribute, if results depend too heavily on synthetic data.
- **Public datasets not used:** Mendeley and Super SMS have unclear terms; see `docs/data-sources.md`.
- **User submissions as a data source:** conflicts with process-and-delete. Keep them out until the privacy design is done.
- **Eval repeatability:** Haiku 5.5 doesn't list `temperature` as supported, so runs aren't pinned to a fixed setting. Runs of the same code on 7 Nov 2026 gave false-positive rates of 0.08 and 0.12. Pin a provider and repeat runs before comparing small differences.
- **Default model:** Haiku 5.5 stays the default. On 7 Nov 2026, two runs each: GPT-6.1 Sol had fewer false alarms (1–2 of 50 against 5 of 50) but missed one real scam (`sw-006`) that Haiku caught, at about 9 times the cost per check and with slower p95 latency (about 5.1 s against 3.1 s). The set is too small to settle this, so repeat the comparison on a larger set with real legit messages.
- **OpenRouter rate limit:** new accounts were limited to 20 requests a minute on GPT-6.1 Sol. Use `--max-per-minute` for evals, and check the limits on the production account before launch.
- **Synthetic data:** 86 of the 100 messages are synthetic, written by an AI model, and all 50 legit messages are synthetic. Real-world false alarms are unmeasured until there are real legit messages. Recall is also likely overstated: only 14 scams are real, and defanged links and placeholders appear only in those real scams.
- **Browser access:** Scamwatch and the ATO returned 403 to Playwright earlier, but plain requests with an identified user agent worked on 6 Nov 2026. Cyber.gov.au is the reverse. Recheck access before building the alert agents.
- **ASIC investor alert list:** local only until its terms are clear. Strong candidate for exact website and phone matching.
- **New variant volume:** tested sources give about 2 descriptive entries a week, not the earlier estimate of 5–20. Revisit once there's a privacy design for user submissions.
- **X sweep cost:** check current `x_search` per-result pricing before building the alert agents.
- **Sources not assessed:** NAB, ANZ, Telstra, Australia Post, Netsafe, Report Fraud, X and phone lookup services. See `docs/data-sources.md`.
