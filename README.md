# Scam Shield

Scam protection for older people and their families, starting in Australia.

**Status:** Phase 0 (foundations). There is no checker to use yet. See the [product brief](docs/product-brief.md).

## Check the eval dataset

Requires Docker.

```bash
docker compose run --rm --build evals
docker compose run --rm --build evals python -m unittest discover -s runners
```

The first command validates `evals/datasets/*.jsonl` and reports progress towards the 200-message Phase 0 target. The second runs the validator's tests.

## Licence

This project is under the [MIT License](LICENSE), except for third-party records in `evals/datasets`. Those keep the licence named in each record's `licence` field; see `evals/datasets/ATTRIBUTION.md`.
