# Scam Shield

Scam protection for older people and their families (AU first). Multilingual, phone-call aware, family/carer layer, white-label for small institutions.

## Priorities (in order)
1. Showcase agentic AI engineering skills (portfolio + interviews) > profit
2. Evals-first: no pipeline change merges without eval results
3. Minimal personal data: process and delete; no account needed for basic checks
4. Low running cost; ~1 h/day of owner time, so prefer small, finishable steps

## Hard rules
- Never tell a user something is "safe". Say: "No red flags found — if in doubt, call them back on the official number."
- Production model calls use API keys (OpenRouter), never a Claude subscription login.
- Tuned prompts and scam-pattern intelligence stay out of the public repo (config/private).
- Check dataset/feed licences before committing data (e.g. OpenPhish community feed and Google Safe Browsing are non-commercial).

## Context docs
- Product brief: @docs/product-brief.md
- Data sources research: @docs/data-sources.md

## Current phase
Phase 0 — Foundations: product brief, ADRs, threat model, privacy design, first 200-message labelled eval set.
