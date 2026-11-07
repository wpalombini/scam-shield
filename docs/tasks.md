# Tasks

Update this file in the same PR as the work it describes.

## Now: Phase 1, first working checker

- [x] Checker with fixed wording for results, so it can't say "safe"
- [x] Command-line check for a single message
- [x] Eval runner with a small prompt-injection set
- [x] First live eval: `evals/reports/2026-11-06T214353Z-anthropic_claude-haiku-5.5.json`. Smoke test only: 24 messages, 5 of them legit
- [ ] Merge the first checker with its eval results

## Next: data foundation

Do these before any more features, in this order:

1. [x] Source check: results in `docs/data-sources.md`. Start with Scamwatch, the ATO and CommBank, once CommBank's terms are read
2. [ ] Grow the eval set to about 100 messages, mostly legit and non-SMS
3. [ ] Private config backup, because the knowledge base is scam-pattern intelligence
4. [ ] Knowledge base in Postgres on local Docker, kept out of the public repo, with scam types, variants, sources and dates from 2–3 independent sources
5. [ ] Run the evals with and without the knowledge base, and only build on it if results improve

Keep eval messages out of the knowledge base, ideally using newer alerts, or scores will be inflated.

## Left behind from Phase 0: come back to these

| Task | Why it's parked | Come back |
|---|---|---|
| Privacy design | Deferred until after the first checker | Before any public launch or stored user data |
| ADRs: stack, model routing, data retention, eval gates | Deferred until after the first checker | Once the first eval results exist |
| 176 more labelled messages, mostly legit and non-SMS | At 24 of 200 | Add in batches alongside the build |
| Owner review of every label | Required by the labelling guide | Before quoting results publicly |
| Relabel 10% and record the disagreement rate | Needs more labelled messages | Around 100 messages |
| Private config backup | Kept local for now | Before the knowledge base or red-team findings go in |
| Security contact | No launch yet | Before launch |
| Product brief questions: iPhone or Android, brand name and domain | Not blocking the build | Before the browser-installable app ships |
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

## Decisions we may revisit

- **Scamwatch quoted messages:** treated as covered by CC BY 3.0 AU. Revisit before commercial launch.
- **Real messages:** 14 from Scamwatch. Look for more sources, including messages people contribute, if results depend too heavily on synthetic data.
- **Public datasets not used:** Mendeley and Super SMS have unclear terms; see `docs/data-sources.md`.
- **User submissions as a data source:** conflicts with process-and-delete. Keep them out until the privacy design is done.
- **Eval repeatability:** Haiku 5.5 doesn't list `temperature` as supported, so runs aren't pinned to a fixed setting and scores may vary between runs. Pin a provider and repeat runs before comparing small differences.
- **Browser access:** Scamwatch and the ATO returned 403 to Playwright earlier, but plain requests with an identified user agent worked on 6 Nov 2026. Cyber.gov.au is the reverse. Recheck access before building the alert agents.
- **ASIC investor alert list:** local only until its terms are clear. Strong candidate for exact website and phone matching.
- **New variant volume:** tested sources give about 2 descriptive entries a week, not the earlier estimate of 5–20. Revisit once there's a privacy design for user submissions.
- **Sources not assessed:** NAB, ANZ, Telstra, Australia Post, Netsafe, Report Fraud, X and phone lookup services. See `docs/data-sources.md`.
