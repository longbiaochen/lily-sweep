# Rulepack

## Built-in Pattern Rules

The first release keeps pattern rules in `src/lily_sweep/builtin_rules.json`.

Each rule has:

- `id`
- `title`
- `severity`
- `category`
- `regex`
- `extensions`
- `remediation`

## Custom Rules

You can pass an extra JSON rule file with:

```bash
python3 -m lily_sweep scan /path/to/repo --rules custom-rules.json
```

Accepted shapes:

- a top-level JSON array of pattern rules
- or an object with `pattern_rules`

Custom rules are appended to the built-in rules.

## Repo Policy

For non-regex repo policy, place `lilysweep.json` at the target root or pass `--config`.

Current supported policy knobs:

- `exclude_paths`
- `ros.dangerous_topics`
- `ros.dangerous_services`
- `ros.dangerous_actions`
- `suppressions`

Suppression entries may match by:

- `id`
- `location`
- `line`
- `evidence_contains`
- `reason`

`reason` is required by convention even though the scanner does not enforce it yet.

## Baselines

For existing repos, generate a baseline with:

```bash
PYTHONPATH=src python3 -m lily_sweep baseline /path/to/repo --output lilysweep-baseline.json
```

Then use it in CI:

```bash
PYTHONPATH=src python3 -m lily_sweep scan /path/to/repo --baseline lilysweep-baseline.json --fail-on high
```

Baseline entries suppress findings by stable fingerprint. This lets teams adopt the gate without stopping on known existing risk, while still failing on newly introduced findings.

## Rule Quality Bar

- Rules should describe a concrete preflight hazard, not a vague code smell.
- Findings should survive a quick manual audit; avoid adding signatures that trigger on common safe scaffolding.
- If a rule introduces a new category, add at least one fixture and one test.
