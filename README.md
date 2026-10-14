# Rekor Monitor

A command-line verifier for the [Rekor](https://docs.sigstore.dev/logging/overview/) transparency log. It can fetch the latest checkpoint, check that a log entry is included in the log, and check that two checkpoints are consistent.

## Installation

Requires Python 3.10+ and [Poetry](https://python-poetry.org/).

```bash
git clone https://github.com/JeffreyRathgeber/sscs-assignment1.git
cd sscs-assignment1
poetry install --no-root
```

## Usage

Run commands with `poetry run python main.py ...`.

| Command | What it does |
|---|---|
| `-c`, `--checkpoint` | Print the latest checkpoint from Rekor |
| `--inclusion LOG_INDEX --artifact FILE` | Verify the entry's signature over `FILE` and its Merkle inclusion proof |
| `--consistency --tree-id ID --tree-size N --root-hash HASH` | Verify a previous checkpoint is consistent with the latest one |
| `-d`, `--debug` | Print extra detail; with `-c`, also saves `checkpoint.json` |

Examples:

```bash
poetry run python main.py -c
poetry run python main.py --inclusion 3067372672 --artifact artifact.md
poetry run python main.py --consistency --tree-id 1193050959916656506 \
    --tree-size 2947620239 \
    --root-hash 9cf81f7b2c7d94b0ec028842f6f6eef0ec859b5918aa0dcb7984300e153f01da
```

## Development

```bash
poetry run ruff format .                         # format
poetry run ruff check .                          # lint
poetry run mypy main.py merkle_proof.py util.py  # type check
poetry run bandit -c pyproject.toml -r .         # security scan
poetry run pytest                                # tests
```

`bandit` needs `-c pyproject.toml` so it reads the settings in that file.

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR and [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

See [LICENSE](LICENSE).
