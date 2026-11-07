# Scam data sources (researched 6 Nov 2026)

Key finding: aggregate statistics are plentiful; **labelled, current scam message text is scarce**. The eval dataset must be built ourselves (public alerts + public datasets + synthetic variants). That dataset is a core product asset.

## Knowledge base sources (checked 6 Nov 2026)

Tested from our test environment with an identified user agent. Working policy, not legal advice. "New items" counts what each source published, not how long after a scam began it did so. We haven't measured that delay.

**Start with these:**

| Source | Role | Access | New items | Terms | Decision |
|---|---|---|---|---|---|
| [Scamwatch RSS](https://www.scamwatch.gov.au/rss/news-feed.xml) | Official national alerts | RSS works | 10 items from 13 Apr to 2 Nov 2026, some of them news rather than alerts | CC BY 3.0 AU, see below | **Use** |
| [ATO scam alerts](https://www.ato.gov.au/online-services/scams-cyber-safety-and-identity-protection/scam-alerts) | Tax and myGov impersonation | Page works. It mentions RSS, but we haven't tested the feed | Oct, Sep, Jul and Feb 2026 | [Free to copy and adapt](https://www.ato.gov.au/copyright) without implying endorsement | **Use** |
| [CommBank alerts](https://www.commbank.com.au/support/security/latest-scams-and-security-alerts.html) | Bank impersonation, and the freshest source tested | Page works, and `robots.txt` allows crawlers | Page updated 5 Nov 2026; at least 4 entries since October | Copyright notice; full terms not read | **Use after reading its terms.** No clear terms page found yet, so not in the knowledge base. Store facts, our own summary and a link, not copied text |

**Keep for lookups or later:**

| Source | What it offers | Finding | Decision |
|---|---|---|---|
| [ASIC investor alert list](https://moneysmart.gov.au/check-and-report-scams/investor-alert-list) | [JSON download](https://static.moneysmart.gov.au/_data/investor-alert-list.json): 4,686 entries, with 4,331 listing websites, 1,977 phones and 620 marked as imposters | 125 added in the last 30 days, the newest on 5 Nov 2026. Investment scams only. No open licence identified, and the [copyright page](https://moneysmart.gov.au/about-us/copyright) says some material needs permission | **Local only** until its terms are clear. Strong candidate for exact website and phone matching |
| [Westpac alerts](https://www.westpac.com.au/security/latest-scams/) | Bank impersonation examples | Oct, Jul, May and Mar 2026. Copyright notice; full terms not read | **Second bank to add**, on the same basis as CommBank |
| [phishunt.io](https://phishunt.io/tos) | About 1,020 active phishing links | Terms release the feed data as CC0, though the docs page also links a CC BY-NC-SA licence we couldn't tie to anything. A rough keyword match found only 6 AU-related links | **Later**, for the URL check agent |
| [Google Web Risk](https://cloud.google.com/web-risk/pricing) | URL lookup | First 100,000 lookups a month are free, then US$0.50 per 1,000. API not tested | **Later**, for the URL check agent |
| [crt.sh](https://crt.sh) | Certificate logs for look-alike domains | Query works | **Later**. Not needed for the first knowledge base |
| [Cyber.gov.au](https://www.cyber.gov.au/alerts-and-advisories) | Technical alerts | Direct requests fail, and the page loads in a browser. Few word-for-word scam messages | **Skip for now** |

**Not usable or not assessed:**

| Source | Finding | Decision |
|---|---|---|
| [URLhaus](https://abuse.ch/terms-of-use/) | Terms say commercial use may need a paid subscription. The recent-links URL we tried returned 410 | **Skip** |
| OpenPhish | Free feed downloads, but we didn't recheck its non-commercial terms | **Skip** |
| FTC consumer alerts | Blocks our test environment with a 403 | **Skip**; not worked around |
| NAB, ANZ, Telstra, Australia Post | NAB's alert page loads, but no dated alerts were found. The URLs tried for the others returned 404 | **Not assessed** |
| Netsafe (NZ), Report Fraud (UK) | Sites load; alerts, dates and terms not checked | **Not assessed** |
| X, phone lookup services, user submissions | Not tested. User submissions also conflict with process-and-delete until the privacy design is done | **Not assessed** |

**Volume:** the tested sources that describe scams published about 7 entries in the last 30 days, before removing duplicates. That's about 2 a week, well below the earlier estimate of 5–20 new variants a week. The higher figure would need faster sources, such as messages people submit or social media, neither of which we can use yet.

## Sender and link lookups (researched 7 Nov 2026)

Desk research from public docs, not tested with real lookups. Prices are USD. No service found has shown Australian scam-report coverage, and no public Australian government number feed was found. Treat any hit as a weak signal that can add suspicion, and a clean result as adding nothing.

| Service | Gives | Cost | Decision |
|---|---|---|---|
| [libphonenumber](https://github.com/google/libphonenumber) | Number type, locally. Doesn't track current carriers | Free | **Use first** |
| [Google Web Risk](https://cloud.google.com/web-risk/pricing) | Known-bad URLs | 100,000 free a month | **Use first**, for links in messages |
| [RDAP](https://about.rdap.org/) | Domain age for many TLDs. [.au creation dates are hidden and automated queries prohibited](https://www.auda.org.au/whois-policy) | Free | **Use later**, for non-.au domains |
| [IPQualityScore](https://www.ipqualityscore.com/plans) | Phone and email fraud scores | Free 1,000 a month. Paid about $99 for 5,000, from a third-party source | **Trial only.** [Terms](https://www.ipqualityscore.com/terms-of-service) bar republishing responses and allow model use, and [retention is about a year](https://www.ipqualityscore.com/privacy-policy) |
| [Twilio Lookup](https://www.twilio.com/en-us/user-authentication-identity/pricing/lookup) | Line type and carrier, no reputation | $0.008 per request | **Fallback** |
| Hiya, Telesign, Prove, tellows | Reputation scores | Unpublished | **Not assessed**; needs sales contact |
| SEON, Vonage Number Insights | Too costly, or being retired | | **Don't use** |
| Community number sites | Terms not confirmed | | **Don't scrape** |

Google's spam labels have no third-party API that we found. A pasted email address carries no headers, so we can't tell whether SPF, DKIM or DMARC passed for that message.

**Risks:** [spoofing](https://www.acma.gov.au/calling-line-identification-and-spoofing) and [recycled numbers](https://www.acma.gov.au/recycled-phone-numbers) can point at innocent people, so results must never call a number a scammer. [Phone numbers are personal information](https://www.oaic.gov.au/privacy/your-privacy-rights/your-personal-information/what-is-personal-information), so vendor retention conflicts with process-and-delete unless agreed otherwise. Get legal advice before launch.

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
| [ATO scam alerts](https://www.ato.gov.au/copyright) | "Free to copy, adapt, modify, transmit and distribute this material as you wish", without implying endorsement. Notice last updated 2012 | **Commit** with attribution to "© Australian Taxation Office for the Commonwealth of Australia". Don't imply endorsement |
| [Moneysmart](https://moneysmart.gov.au/about-us/copyright) | Some material can be reproduced without permission and some can't; open licences are identified on the material itself. Teaching resources are CC BY-NC-SA 3.0 AU according to a search snippet. No open licence identified on the investor alert list page | **Don't commit** until its terms for each page are read |
| NAB, CommBank, Westpac | Copyright notice with no open licence seen on the alert pages; full terms not read. Few word-for-word messages in page text | **Don't commit** |
| Telstra, Australia Post, Linkt | No open licence seen; Telstra's copyright notice not read, and no copyright wording on the Australia Post or Linkt legal pages checked | **Don't commit** |

## Gaps
- Non-English (PT-BR, ZH, VI, AR) labelled scam text: almost nonexistent → own collection + synthetic.
- Phone-call scripts / voicemails: no public labelled set found.
- Alert sources: Scamwatch has RSS and the ATO mentions it. Bank and telco alerts have no API that we found → scraping/scheduled agents.
