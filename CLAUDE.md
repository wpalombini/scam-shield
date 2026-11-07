# Scam Shield

Scam protection for older people and their families (AU first). Multilingual, phone-call aware, family/carer layer, white-label for small institutions.

## Priorities (in order)
1. Evals-first: no pipeline change merges without eval results
2. Minimal personal data: process and delete; no account needed for basic checks
3. Low running cost; prefer small, finishable steps

## Hard rules
- Never tell a user something is "safe". Say: "No red flags found — if in doubt, call them back on the official number."
- Production model calls use API keys (OpenRouter), never a Claude subscription login.
- Tuned prompts and scam-pattern intelligence stay out of the public repo (config/private).
- Check dataset/feed licences before committing data (e.g. OpenPhish community feed and Google Safe Browsing are non-commercial).

## Context docs
- Product brief: @docs/product-brief.md
- Data sources research: @docs/data-sources.md
- Task tracker: @docs/tasks.md (update it in the same PR as the work, including anything left behind)

## Current phase
Phase 1 — Checker MVP, started ahead of the Phase 0 finish. Unfinished Phase 0 work is parked in docs/tasks.md and still needs doing.
