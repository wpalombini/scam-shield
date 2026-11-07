# Scam Shield — Product Brief

## Goal
A production-grade AI product that protects older people and their families from scams, with minimal personal data and low running cost.

## Positioning
Not "another scam checker" (Norton Genie, McAfee, Trend Micro ScamCheck, Bitdefender Scamio and CommBank's Truyu Scam Checker are all free).
**Scam protection for older people and their families:** multilingual, phone-call aware, local alerts, white-label for small institutions.

### Gaps to exploit
- Language: Norton Genie is English-only. Targets: Portuguese (Brazil), plus Chinese, Vietnamese and Arabic speakers in AU.
- Family/carer layer: "protect Mum" — adult child alerts, shared history, family safe-word setup.
- Phone calls: post-call description, number check and voicemail analysis (no live call audio; OS and legal limits).
- Small institutions: credit unions, customer-owned banks, retirement villages, councils, aged care providers (big banks build in-house).
- Regional timely alerts: "the scam doing the rounds in your area this week".

## Why the audience matters
- 2025 (AU, combined data): 481,523 scam reports, $2.18B lost.
- People 65+ are ~17.1% of the population but 26.5% of Scamwatch-reported losses.
- Emerging threat: AI voice-clone "family emergency" calls.

## Product surfaces (all one product)
1. **"Is this a scam?" checker:** paste text, screenshot, voice note, call description or phone number. Process and delete, no account needed for basic use.
2. **Free weekly regional email brief;** paid local alerts per region.
3. **Mobile app:** browser-installable web app first, then a native Expo app (iOS share sheet).
4. **Browser extension.**
5. **Paid API + MCP server.**
6. **Education:** AI video explainers of scams (Leonardo), online-safety course for seniors (B2B to villages/U3A).
7. **White-label:** branded instances for credit unions, villages and so on (multi-tenant config).

## Monetisation
- Free: weekly brief and limited checks.
- Family plan: unlimited checks and family alerts.
- B2B white-label licences (illustrative: ~A$1/member/year; a 50k-member credit union ≈ A$50k/yr). Sales cycles are 6–12 months.
- API usage billing (Stripe metered).
- Licensing to small institutions is the realistic path (big-bank acquisition unrealistic).

## Phone call evaluation approach
- Number lookup: line type (VoIP/mobile posing as a bank), community reports, spoofing heuristics.
- Post-call description (typed or voice note): match against scam scripts (urgency, remote access, "safe account", gift cards, "Hi Mum").
- Voicemail upload: transcribe and analyse; deepfake detection experimental only.
- Teach: hang up and call back on the official number; family safe word.

## Architecture sketch (to refine)
- Agent pipeline: read screenshot → extract links/numbers/claims → parallel tool agents (RDAP domain age, URL reputation, ABN Lookup, phone line type) → verdict agent → plain-English writer (reading-level constrained) → safety reviewer.
- Models via **OpenRouter** (5.5% credit fee): a cheap model first, escalate when uncertain. Production uses API keys, not a Claude subscription.
- Alerts: scheduled agents over Scamwatch, bank/telco alerts, news, plus an X sweep via the xAI API `x_search` tool (check current per-result pricing).
- Infra: small VM (Oracle A1 / Digital Ocean), Docker, Cloudflare (Pages, Email Workers for forward-to-check), Stripe.
- Observability: full trace per check (OpenTelemetry/Langfuse), cost/latency/drift dashboards.
- Rule: never say "safe". Say "No red flags found — if in doubt, call them back on the official number."

## Engineering capabilities
Multi-agent orchestration · evals (recall, false-positive rate, calibration, CI regression gates) · competitor benchmark vs Norton Genie / Scamio / Truyu · prompt-injection red-teaming · model routing and cost engineering · observability · privacy by design · accessibility for older users · multimodal input · autonomous scheduled agents · MCP server · multi-tenant SaaS.

**README must include:** live link, product walkthrough, architecture diagram, eval results as numbers (recall vs competitors, $/check, p95 latency), eval history chart.
**Docs:** product brief, architecture, ADRs, threat model, system card (honest limits).
**Keep private:** tuned prompts and scam-pattern intelligence (config, not the public repo).

### Repo layout
```
scam-shield/
├── docs/ (product-brief, data-sources, architecture, adr/, threat-model, system-card)
├── apps/ (web, api [+MCP], alerts)
├── packages/ (agents, tools)
├── evals/ (datasets, runners [incl. competitor benchmark], reports)
├── infra/
└── observability/
```

## Roadmap
| Phase | When | Deliverable |
|---|---|---|
| 0 Foundations | Weeks 1–2 | Product brief, ADRs, threat model, privacy design, first 200-message labelled eval set |
| 1 Checker MVP | Weeks 3–8 | Browser-installable app + forward-to-email; agent pipeline; eval harness and tracing |
| 2 Content + money | Month 3 | Free AU weekly brief; paid local alerts; Stripe |
| 3 Reach | Months 4–6 | Expo native app; browser extension; paid API/MCP |
| 4 Education + B2B | Month 6+ | Video explainers; white-label pilot; NZ/UK, then Brazil (Portuguese) |

**Immediate next steps:**
1. Design the labelled eval dataset (categories, sources, labelling scheme).
2. Finalise this product brief.
3. Run the competitor benchmark (Norton Genie, Scamio, Truyu) as the first public artifact.

## Open questions
- iPhone or Android: which matters most for the target audience?
- Brand name / domain.

## Decisions
- First region: AU only (6 Nov 2026).
