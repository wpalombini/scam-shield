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

## Licence check (6 Nov 2026)
Working policy for this project, not legal advice. **Commit** means the text may go in this repo. **Local only** means it stays out of the repo and nothing derived from it is published until its terms are clear.

| Source | What the source states | Decision |
|---|---|---|
| [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection) | CC BY 4.0, "for any purpose" with credit. Corpus was "collected from free or free for research sources" | **Commit** with attribution (DOI 10.24432/C5CC84). Not AU, and spam isn't necessarily scam |
| [Mendeley SMS Phishing](https://data.mendeley.com/datasets/f45bkkt8pr/1) | Licence field says CC BY 4.0, but the site footer reserves rights including AI training. Messages were converted from images found online | **Local only** until the conflict is resolved |
| [Super SMS corpus](https://github.com/smspamresearch/spstudy) | No licence in the repo; asks for citation only. The paper calls its sources "free for research" | **Local only**; ask the authors |
| [SMISH_DT](https://github.com/MarazMia/SMISH_DT) | No licence; redistributes third-party data | **Don't use**; go to the original sources |
| Smishtank (smishtank.com/dataset) | **Unverified:** page returned 404, so no terms seen | **Don't use** until terms are found |
| [Scamwatch alerts](https://www.scamwatch.gov.au/about-us/using-our-website/disclaimer-and-copyright) | CC BY 3.0 AU, excluding logos, the Coat of Arms, third-party content and material marked otherwise. Asks re-publishers to check currency and accuracy with the ACCC first. Doesn't mention quoted scam messages. Read manually in a browser on 6 Nov 2026 | **Commit** text not labelled third-party, with `licence` set to `CC-BY-3.0-AU`, the alert's URL as `source_url`, and attribution to the ACCC as "© Commonwealth of Australia". Don't imply ACCC endorsement. Quoted scam messages are treated as covered; revisit before any public launch |
| [cyber.gov.au](https://www.cyber.gov.au/copyright) | CC BY 4.0, excluding the Coat of Arms, the ACSC logo and third-party content. Attribute to the Australian Signals Directorate as "© Commonwealth of Australia 2026" | **Commit** with attribution, but no word-for-word messages found in the 4 alerts and advisories, or the 2 guidance pages, checked on 6 Nov 2026. Useful for scenarios |
| [Reddit](https://redditinc.com/policies/user-agreement) | User Agreement prohibits scraping without written consent and collecting data by any means except as permitted. Users keep ownership of their posts. Blocked our test environment with a 403. Secondary sources say the Data API restricts commercial and AI use | **Don't use** |
| [Services Australia](https://www.servicesaustralia.gov.au/copyright) | CC BY 4.0, but **images are excluded**, and its scam examples are images. Page text only describes the scams | **Commit** page text only; don't transcribe example images. Useful for writing synthetic messages |
| ATO scam alerts | **Unverified:** returned 403 to headless Chromium | **Don't use** unless the owner reads the terms in a browser |
| [Moneysmart](https://moneysmart.gov.au/about-us/copyright) | Search snippet only: terms vary by section, and teaching resources are CC BY-NC-SA 3.0 AU | **Don't commit** until its terms for each page are read |
| NAB, CommBank | Copyright notice with no open licence seen on the alert pages; full terms not read. Few word-for-word messages in page text | **Don't commit** |
| Telstra, Australia Post, Linkt | No open licence seen; Telstra's copyright notice not read, and no copyright wording on the Australia Post or Linkt legal pages checked | **Don't commit** |

## Gaps
- Non-English (PT-BR, ZH, VI, AR) labelled scam text: almost nonexistent → own collection + synthetic.
- Phone-call scripts / voicemails: no public labelled set found.
- Alert sources (Scamwatch news, bank/telco alerts) have no API → scraping/scheduled agents.
