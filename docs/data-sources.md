# Scam data sources (researched 6 Nov 2026)

Key finding: aggregate statistics are plentiful; **labelled, current scam message text is scarce**. The eval dataset must be built ourselves (public alerts + public datasets + synthetic variants). That dataset is a core product asset.

## Government statistics (aggregates, no message text)
| Region | Source | Access |
|---|---|---|
| AU | Scamwatch / NASC — scamwatch.gov.au/research-and-resources/scam-statistics | Interactive dashboard, monthly; Targeting Scams annual report; NASC quarterly updates |
| US | FTC Consumer Sentinel — ftc.gov/exploredata | Quarterly dashboards + CSV data files (public domain). Raw reports law-enforcement only |
| CA | CAFC Fraud Reporting System dataset — open.canada.ca (id 6a09c998-cddb-4a22-beff-4dca67ab892f) | **Record-level CSV**, quarterly, Open Government Licence – Canada |
| UK | Action Fraud / ONS appendix tables | Aggregates only; ONS says not a good trend indicator (under-reporting) |
| BR | Febraban, Serasa Experian | Press releases / headline figures only; no open dataset found |
| Global | GASA / Feedzai Global State of Scams 2025 | Survey (46k adults, 42 markets) — good for pitch, not evals |

## Threat feeds (for tool agents)
| Feed | Licence / notes |
|---|---|
| URLhaus (abuse.ch) | Free, all uses, full dumps — malware URLs, not scams |
| PhishTank (Cisco Talos) | Free API with registration; community-verified (lower FP, slower) |
| OpenPhish | Community feed free for **non-commercial** use only |
| Google Safe Browsing | **Non-commercial**; commercial = paid Web Risk API |
| PhishStats | Real-time API + CSV every 90 min |

## Labelled text datasets (for evals)
| Dataset | Size | Notes |
|---|---|---|
| UCI SMS Spam Collection | 5,574 | 2012 — outdated |
| Mendeley SMS Phishing (Mishra & Soni) | 5,971 | ham / spam / smishing labels |
| Smishtank dataset (Timko & Rahman, arXiv 2402.18430) | ~1,062 | sender, brand, URL analysis |
| Super SMS corpus (Salman, Ikram, Kaafar — arXiv 2210.10451) | 153,551 | includes Scamwatch-crawled items; most AU-relevant |
| Smishing Data Hub — github.com/MarazMia/SMISH_DT | aggregate | refined + original versions of most public sets |

## Gaps
- Non-English (PT-BR, ZH, VI, AR) labelled scam text: almost nonexistent → own collection + synthetic.
- Phone-call scripts / voicemails: no public labelled set found.
- Alert sources (Scamwatch news, bank/telco alerts) have no API → scraping/scheduled agents.
