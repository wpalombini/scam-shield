# Scam Shield

Scam protection for older people and their families, starting in Australia.

**Status:** early development. The first checker runs from the command line or a local page and isn't ready for real use. See the [product brief](docs/product-brief.md), [tasks](docs/tasks.md) and [threat model](docs/threat-model.md).

## Try the checker

Requires Docker and an [OpenRouter](https://openrouter.ai) API key. Copy `.env.example` to `.env` and add your key, ideally with a low spending limit.

```bash
docker compose run --rm --build checker python -m scam_shield "Hi Mum, I lost my phone. Please send money to my new account today."
```

Or use the checker page:

```bash
docker compose up --build web
```

Then open <http://localhost:8080>. It only accepts connections from the same machine. On a remote server, connect first with `ssh -L 8080:localhost:8080 <server>`.

Submitted text goes to the model provider through OpenRouter. Don't use real messages containing personal details.

## Run the evals

```bash
# Validate the dataset and report progress (free, no network)
docker compose run --rm --build evals

# Run the tests (free, no network)
docker compose run --rm --build evals python -m unittest discover -s runners
docker compose run --rm --build --no-deps web python -m unittest test_server

# Score the checker on the dataset and red-team set (uses your API key)
docker compose run --rm --build checker python runners/run_checker_evals.py
```

Scored runs save a report to `evals/reports`, with record ids and numbers but no message text.

## Knowledge base

The checker can use scam patterns extracted from official alerts. It's off by default, and the data stays in a private database rather than this repo. Set `POSTGRES_PASSWORD` and `SCAM_SHIELD_DATABASE_URL` in `.env`, then:

```bash
# Fetch alerts and extract patterns (uses your API key)
docker compose run --rm --build ingest

# Score the checker with the patterns (uses your API key)
docker compose --profile knowledge up -d db
docker compose run --rm --build checker python runners/run_checker_evals.py --knowledge
```

To use the patterns on the checker page, also set `SCAM_SHIELD_KNOWLEDGE=on`, and run `docker compose --profile knowledge up -d --build db web`. Alerts used by the eval set are held out, so the checker isn't scored on its own source material.

## Licence

This project is under the [MIT License](LICENSE), except for third-party records in `evals/datasets`. Those keep the licence named in each record's `licence` field; see `evals/datasets/ATTRIBUTION.md`.
