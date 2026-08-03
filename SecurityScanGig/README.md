# Security Scan Gig Kit

Turns your existing **RangeCheck** tool into a sellable Fiverr service with a
professional, client-ready PDF deliverable. This is Play 4 from your action plan.

## What's here
- `generate_report.py` � renders a branded multi-page PDF from RangeCheck's JSON output.
- `run_gig.py` � one command: scan an authorized target, then build the PDF.
- `CLIENT_AUTHORIZATION.md` � the written authorization you MUST collect before scanning.
- `FIVERR_GIG.md` � ready-to-paste gig title, description, pricing, and message templates.
- `sample_full_report.json` � an example RangeCheck result for testing.
- `deliverables/` � where finished client PDFs are written.

## Setup (one time)
```
py -m pip install reportlab
```
RangeCheck itself lives at `C:\Users\sergi\Desktop\tools\RangeCheck`. If you move it,
update `RANGECHECK_DIR` at the top of `run_gig.py`.

## Try it now (no scanning, just the PDF)
```
py generate_report.py sample_full_report.json --client "Acme Coffee Roasters LLC"
```
Open the PDF in `deliverables/`. That's exactly what a paying client receives.

## Real gig flow
1. Buyer confirms authorization in writing (`CLIENT_AUTHORIZATION.md`).
2. Copy their targets into a scope file (see `RangeCheck/examples/sample-scope.yaml`).
3. `py run_gig.py --scope scope.yaml --client "Their Company LLC"`
4. Deliver the PDF from `deliverables/`.

## The one rule
Only ever scan systems the client owns or is authorized to test, inside the
agreed window. The authorization form is what keeps this legal and protects you.
Everything runs locally � no client data leaves your machine.
