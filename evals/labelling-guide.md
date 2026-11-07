# Eval dataset labelling guide

Rules for labelling `evals/datasets/*.jsonl`. `evals/runners/validate_dataset.py` enforces the record format.

Check that a source is cleared in [data-sources.md](../docs/data-sources.md#licence-check-6-nov-2026) before using it.

## Scam or legit

- **`scam`:** the message tries to deceive someone into giving up money, credentials, personal data or device access.
- **`legit`:** the message is what it appears to be, even if it is unwanted or annoying. Real marketing is `legit`.

Label from evidence about where the message came from, not from how it reads:

- **Real messages:** use the source's verdict, such as an official alert quoting it as a scam.
- **Synthetic messages:** use what the author wrote it to be. A "Hi Mum" message can be `legit` if written as a real family text.
- **Unsure:** leave the message out. Never guess.

Spam labels in public datasets don't mean scam. Review each message rather than converting `spam` to `scam`.

`legit` is an internal eval label only. Product text must still never call a message "safe".

## Categories

If more than one fits, use the first rule that applies: who is being impersonated, then what the lure is.

### Scam

| Category | Use for |
|---|---|
| `bank_impersonation` | Pretends to be a bank or its fraud team, including "safe account" requests |
| `delivery_toll` | Fake parcel, postage or road toll fees |
| `government_impersonation` | Pretends to be a government agency, such as the ATO, myGov or Services Australia |
| `hi_mum` | Pretends to be a family member or friend in need, including voice-clone calls |
| `remote_access` | Tech or telco support asking for access to a device |
| `investment` | Fake investments, crypto or guaranteed returns |
| `job` | Fake jobs or paid tasks |
| `romance` | Builds a relationship in order to ask for money |
| `fake_notification` | Fake voicemail, missed call or photo-sharing alerts that push a link |
| `other_scam` | Any other scam; review these for a new category |

### Legit

| Category | Use for |
|---|---|
| `bank_notice` | Real bank alerts and statements |
| `delivery_notice` | Real delivery updates |
| `government_notice` | Real government reminders and notices |
| `appointment` | Medical, service or other bookings |
| `family` | Real messages from family and friends |
| `marketing` | Real promotions and newsletters |
| `other_legit` | Any other real message |

## Hard negatives

Set `hard_negative` to `true` on a `legit` message that could reasonably be mistaken for a scam, such as a real bank alert about a declined payment. These measure false alarms. Set it to `false` on all scam messages.

## Other fields

| Field | Rule |
|---|---|
| `id` | Unique across all files |
| `channel` | `sms`, `email`, `call_description`, `voicemail_transcript` or `social` |
| `language` | `en-AU` for Australian messages; otherwise the closest tag, such as `en` |
| `source` | `synthetic`, `public_alert` or `public_dataset` |
| `source_url` | Required unless `source` is `synthetic` |
| `licence` | `project-original` for synthetic messages; otherwise the source's licence, such as `CC-BY-4.0` |
| `source_date` | Optional. Date the source was published, as `YYYY-MM-DD` |
| `notes` | Optional. Any change from the source wording, such as replaced details or transcription from an image |

## Personal data

- **Real messages:** replace names, phone numbers, addresses and account details with placeholders such as `[NAME]`, unless they are the public details of an organisation.
- **Real links:** defang them, for example `hxxp://bad[.]example`.
- **Synthetic messages:** use `.example` domains and ACMA's phone numbers reserved for fiction. Never use a real person's details.
- **Don't add:** private messages from anyone without their consent.

## Target mix for the first 200

These are starting targets, to be adjusted as the set grows.

| Scam (100) | Count | Legit (100) | Count |
|---|---|---|---|
| `bank_impersonation` | 15 | `bank_notice` | 25 |
| `delivery_toll` | 15 | `delivery_notice` | 15 |
| `government_impersonation` | 15 | `government_notice` | 15 |
| `hi_mum` | 15 | `appointment` | 15 |
| `remote_access` | 10 | `family` | 15 |
| `investment` | 10 | `marketing` | 10 |
| `job` | 5 | `other_legit` | 5 |
| `romance` | 5 | | |
| `fake_notification` | 5 | | |
| `other_scam` | 5 | | |

- **Hard negatives:** at least 30 of the legit messages.
- **Channels:** 90 `sms`, 50 `call_description`, 40 `email`, 10 `voicemail_transcript` and 10 `social`.
- **Balance:** keep scam and legit roughly even within each channel, so the channel doesn't give away the label.
- **Language:** English only for this first set, because the first region is AU.
- **Real vs synthetic:** 14 real scams from Scamwatch, 100 real casual texts from the UCI SMS Spam Collection, and the rest synthetic. Report metrics for real and synthetic separately, because synthetic messages can overstate performance.

## Quality checks

- **Independent review:** the owner reviews every label. An AI model being evaluated must not be the only labeller.
- **Agreement:** relabel a random 10% without looking at the first label, and record the disagreement rate.
- **Disagreements:** resolve each one and update this guide if a rule was unclear.
