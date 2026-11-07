# Tasks

Update this file in the same PR as the work it describes.

## Now: Phase 1, first working checker

- [x] Checker with fixed wording for results, so it can't say "safe"
- [x] Command-line check for a single message
- [x] Eval runner with a small prompt-injection set
- [x] First live eval: `evals/reports/2026-11-06T214353Z-anthropic_claude-haiku-5.5.json`. Smoke test only: 24 messages, 5 of them legit
- [x] Merge the first checker with its eval results

## Next: data foundation

Do these before any more product features, in this order. The local page is a testing aid:

1. [x] Source check: results in `docs/data-sources.md`. Start with Scamwatch, the ATO and CommBank, once CommBank's terms are read
2. [x] Grow the eval set to 100 messages, split evenly between scam and legit. Latest report for the default model: `evals/reports/2026-11-07T023243Z-anthropic_claude-haiku-5.5.json`
3. [x] Local checker page, to try the checker by hand: `docker compose up --build web`
4. [x] Knowledge base in Postgres on local Docker, with data kept out of the public repo: 18 patterns from Scamwatch and the ATO
5. [x] Run the evals with and without the knowledge base. Results are promising but not settled; see "Knowledge base" under decisions. It stays off by default

Keep eval messages out of the knowledge base, ideally using newer alerts, or scores will be inflated.

## Deferred from Phase 0

| Task | Reason deferred | Revisit |
|---|---|---|
| Privacy design | Deferred until after the first checker | Before any public launch or stored user data |
| ADRs: stack, model routing, data retention, eval gates | Deferred until after the first checker | Before the knowledge base is turned on by default. It was built without them |
| 100 more labelled messages, each with owner review | At 100 of 200 | Add in batches alongside the build |
| Relabel 10% and record the disagreement rate | Not yet done. The owner's review of the first 100 was a quick pass: 100 of 100 agreed in about 4 minutes on 7 Nov 2026. It doesn't replace this check | Before quoting results as a performance claim |
| Private config backup | Deferred until a working system is running. Until then, private files and knowledge base data exist only on one machine | Before the knowledge base is turned on by default |
| Security contact | No launch yet | Before launch |
| Product brief questions: iPhone or Android, brand name and domain | Not blocking the build | Before the browser-installable app ships |
| Review recurring false alarms: syn-040, syn-045, syn-048, syn-065, syn-066, syn-074 and syn-076 | Found in the 100-message evals. syn-048 is ambiguous by design | Before the knowledge base is turned on by default. The comparison ran without this review |
| Pin a provider and report repeated eval runs | Identical runs varied | Before the knowledge base is turned on by default. The comparison ran with providers unpinned |
| Source real legit messages, with consent or clear licences | All 50 are synthetic, so real-world false alarms are unmeasured | Before quoting results as a performance claim |
| Repeat the Sol comparison on a larger set with real legit messages | The current set can't settle it | Before changing the default model |
| Check production account rate limits | Evals hit 20 requests a minute | Before launch |
| Automated browser tests for the checker page | Tested by hand in a browser so far | Before the page is used beyond local testing |
| Add CommBank alerts to the knowledge base | No clear terms found yet. Read them first, then store facts, our own summary and a link | Before relying on the knowledge base |
| Merge duplicate patterns across sources and record which sources confirm each one | 18 patterns so far, so not needed yet | When sources overlap |
| Find relevant patterns by meaning, such as embeddings | Keyword matching couldn't separate related patterns. Sending all patterns works while the set is small | Before the set passes 50 patterns |
| Test whether patterns make new scam types easier to miss | One scam was missed with patterns and none without | Before turning the knowledge base on by default |
| Add a prompt-only eval setting and repeat the comparison | The prompt-only runs used a temporary script | Before promoting the prompt line |
| Read-only database role for the checker and page, passing its URL only where needed | Both currently share one full-access URL | Before launch |
| Try prompt caching for the patterns | They're identical on every check, and sending them costs about 5 times as much per check | During tuning |
| Human review of the 32 sender eval cases | Written by an AI model, with no review yet | Before quoting sender results |
| Free sender and link checks: phone type with libphonenumber, a lookalike check against official Australian domains, and Google Web Risk for links | See "Sender and link lookups" in `docs/data-sources.md` | Next, after sender context |
| Trial a phone and email reputation service, starting with IPQualityScore. First get written answers on Australian coverage, data retention and showing results to users | Needs an account and vendor terms. No service has shown Australian scam coverage yet | Owner decision |
| Legal review of result wording, and a consent prompt for checking someone else's number | Spoofed or recycled numbers could lead to false accusations, and numbers are personal information | Before launch |
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
- **Default model:** Haiku 5.5 stays the default. On 7 Nov 2026, two runs each: GPT-6.1 Sol had fewer false alarms (1–2 of 50 against 5 of 50, with Haiku at 4–6 across all its complete runs that day) but cost about 9 times as much per check and had slower p95 latency (about 5.1 s against 3.1 s). Providers weren't pinned and concurrency differed, so cost and latency aren't a controlled comparison. Sol also missed one real message (`sw-006`) that Haiku caught, though one message can't separate their recall. This evidence doesn't justify switching, and it doesn't show Haiku is better.
- **OpenRouter rate limit:** new accounts were limited to 20 requests a minute on GPT-6.1 Sol. Use `--max-per-minute` for evals.
- **Knowledge base:** off by default. On 7 Nov 2026, two runs each of Haiku 5.5 on 100 messages. Baseline: 50 of 50 scams caught, 5–6 of 50 false alarms, $0.00014 per check. New prompt line without patterns: 50 of 50, 3–4 false alarms, $0.00013. All 18 patterns, after adding limits and an instruction to ignore instructions in patterns: 49–50 of 50, 1 false alarm in each run, $0.00072. Before those changes, the same patterns gave 49 of 50 and 0 false alarms. The miss, `syn-028`, is ambiguous by design. Identical baseline runs varied between 4 and 6 false alarms, so the prompt-only difference may be noise. The legit messages are all synthetic, and the patterns and eval set share at least one topic (myGov impersonation), so this isn't settled. Promote the prompt line separately if it holds up.
- **Sender context:** optional on the page. On 7 Nov 2026, two runs each on 32 AI-written cases. With patterns, suspicious senders flagged rose from 0 of 12 (text alone) to 10 of 12, and plausible senders flagged rose from 0 of 12 to 2 of 12. Clear scams from plausible-looking senders stayed at 6 of 6. A sender can add suspicion but must never clear a message.
- **Synthetic data:** 86 of the 100 messages are synthetic, written by an AI model, and all 50 legit messages are synthetic. Real-world false alarms are unmeasured until there are real legit messages. Recall is also likely overstated: only 14 scams are real, and defanged links and placeholders appear only in those real scams.
- **Browser access:** Scamwatch and the ATO returned 403 to Playwright earlier, but plain requests with an identified user agent worked on 6 Nov 2026. Cyber.gov.au is the reverse. Recheck access before building the alert agents.
- **ASIC investor alert list:** local only until its terms are clear. Strong candidate for exact website and phone matching.
- **New variant volume:** tested sources give about 2 descriptive entries a week, not the earlier estimate of 5–20. Revisit once there's a privacy design for user submissions.
- **X sweep cost:** check current `x_search` per-result pricing before building the alert agents.
- **Sources not assessed:** NAB, ANZ, Telstra, Australia Post, Netsafe, Report Fraud, X and phone lookup services. See `docs/data-sources.md`.
