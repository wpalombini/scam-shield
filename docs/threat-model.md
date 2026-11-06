# Threat model

_Public summary, 6 Nov 2026. Review this whenever a new product surface, tool or data flow is added._

**Status:** design stage. The checker isn't built yet, so every defence below is planned and untested unless a later version says otherwise. Results will be published as the evals are built.

Specific weaknesses, detection details and unfixed findings are kept private, so this page doesn't help attackers.

## What we protect

In priority order:

1. **People's money and safety:** a wrong or misleading answer can lead to real losses, especially for older people.
2. **Personal data:** pasted messages can contain names, account details and family information.
3. **Trust in the verdict:** a result is only useful if it can't be manipulated by the message being checked.
4. **The service:** availability, running costs, API keys and private configuration.

## Who could cause harm

- **Scammers** who craft messages to get past the checker.
- **Automated abusers** who use the free checker at volume or try to extract its prompts.
- **People close to the user** who misuse family and carer features to monitor or control someone.
- **Our own system,** through honest mistakes, outages or data handling errors. No attacker is needed for these.

## Threats and planned defences

| # | Threat | Impact | Planned defence | How we'll test it |
|---|---|---|---|---|
| 1 | **Missed scam:** the checker finds no red flags on a real scam, and the person trusts that | Critical | Never say "safe". Say: "No red flags found — if in doubt, call them back on the official number." Escalate uncertain cases to a stronger model. If a check fails, say so rather than showing a "no red flags" result | Recall by scam category, with real and synthetic messages reported separately; forced-failure tests |
| 2 | **Prompt injection:** text in a message, screenshot or voicemail tells the AI to report no problems | High | Treat all submitted content as untrusted data, kept separate from instructions. Use structured outputs, a fixed list of tools, and a separate safety review | Red-team injection set in the evals, run on every pipeline change |
| 3 | **Harmful advice:** the answer repeats a scammer's phone number or link as the way to get help | High | Never present contact details from the message as trusted. Direct people to official channels they find themselves | Eval checks on every written answer |
| 4 | **False alarm:** a real bank or government message is flagged, so someone ignores something important | Medium | Word results around what was found and how to verify it, rather than as absolute verdicts | False-positive rate on hard negatives, which are real-looking legitimate messages |
| 5 | **False confidence from spoofing:** a familiar caller ID or message thread makes a scam look genuine | High | Treat number and sender checks as extra signals only. Never let them lower the risk on their own | Eval cases with spoofed-sender scenarios |
| 6 | **Personal data exposure:** submitted content ends up in logs, traces, the database or with third parties | High | Process and delete. Don't store message content. Mask traces. Prefer model providers with no-retention terms | Seeded test data searched for in logs, traces and storage |
| 7 | **Tool abuse:** links in a message make our tools reach dangerous or internal addresses | High | Look up reputation data rather than opening untrusted links directly. Run any fetching in isolation, with internal addresses blocked and strict timeouts | Security tests using internal and redirecting addresses |
| 8 | **Cost and capacity abuse:** bots flood the free checker to run up model bills | Medium | Rate limits, input size limits, per-check and daily spending caps, and budget alerts | Load tests; spending-cap tests |
| 9 | **Family feature misuse:** alerts or shared history are used to watch or control an older person | High | The protected person must consent, can see what is shared, and can withdraw at any time. Share alerts rather than message content by default | Permission tests; design review with older users before launch |
| 10 | **Secret or prompt leakage:** API keys, tuned prompts or scam-pattern intelligence are exposed | Medium | Keep them out of the public repo. Use API keys with spending limits. Don't rely on prompts staying secret for safety | Secret scanning; prompt-extraction tests |
| 11 | **Poisoned alert sources:** scheduled agents pick up false or malicious content and send it to subscribers | Medium | Treat sources as untrusted, prefer official ones, and require human review before anything is sent | Injection tests on source content |
| 12 | **Cross-customer data exposure:** one white-label customer sees another's data or settings | High | Separate each customer's data and test that separation before any pilot | Automated tests across customer boundaries |

Threats 9, 11 and 12 apply to later phases. Their defences must be in place before those features launch.

## Known limits

- **No checker catches everything.** New scams will get through, so results can't promise that a message is genuine.
- **Spoofing can't be fully detected.** A number or sender that looks right proves little.
- **Voice-clone detection is experimental.** We won't treat it as evidence that a call was genuine.
- **Live calls aren't monitored.** Checks happen after the call, from a description, number or voicemail.
- **It isn't professional advice.** Results don't replace advice from a bank, the police or a lawyer.
- **The eval set is small and partly synthetic.** Results will be reported with those limits stated.

## Reporting a problem

A security contact will be added before launch.
