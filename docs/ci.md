# CI Integration

LilySweep can run as a deployment gate in CI and can also emit SARIF for GitHub code scanning.

## Local CI-Style Commands

Generate a SARIF report:

```bash
PYTHONPATH=src python3 -m lily_sweep scan . --format sarif --output lily-sweep.sarif
```

Fail on new high-severity findings:

```bash
PYTHONPATH=src python3 -m lily_sweep scan . --fail-on high
```

Adopt LilySweep in a repo that already has known findings:

```bash
PYTHONPATH=src python3 -m lily_sweep init . --with-baseline
```

Or generate the baseline manually:

```bash
PYTHONPATH=src python3 -m lily_sweep baseline . --output lilysweep-baseline.json
PYTHONPATH=src python3 -m lily_sweep scan . --baseline lilysweep-baseline.json --fail-on high
```

## GitHub Actions

The sample workflow lives at `.github/workflows/lilysweep.yml`.

It runs LilySweep twice:

- first to write `lily-sweep.sarif` for code scanning upload
- then as a blocking gate with `--fail-on high`

If `lilysweep-baseline.json` is present, the gate uses it so known existing findings do not block adoption.

## Exit Codes

- `0`: scan completed and no finding matched `--fail-on`
- `2`: scan completed and at least one finding matched `--fail-on`
- other non-zero codes: command or runtime failure
