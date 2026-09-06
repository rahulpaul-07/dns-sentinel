# Vendored component — not authored by this project

This directory contains the upstream Zeek `exfil_detect` package in full,
including its own build scaffolding (`CMakeLists.txt`, `Makefile`, `configure`,
`zkg.meta`, `VERSION`, `CHANGES`), its C++ plugin sources under `src/`, its
Zeek scripts under `scripts/`, and its `btest` baselines under `testing/`.

- Author: saiiman
- License: BSD 3-Clause, reproduced verbatim in `COPYING`
- Modifications: none. The package is used as an external dependency.

It lives here rather than at the repository root so that the root describes
this project and not its dependency. All integration with it is downstream, in
`backend/ingest_zeek.py`. See `THIRD_PARTY.md` at the repository root for the
full attribution.
