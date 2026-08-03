# Fiverr Gig � copy/paste ready

This is Play 4 from your plan. It turns RangeCheck (which you already built) into
a sellable $75�$300 deliverable. Everything below is ready to paste into Fiverr.

---

## Gig title
**I will run an external vulnerability scan and deliver a professional security report**

## Category
Programming & Tech ? Cybersecurity ? Vulnerability Assessment

## Search tags
`vulnerability scan`, `security audit`, `penetration test`, `cybersecurity report`, `website security`

---

## Gig description

> **Know exactly what an attacker sees when they look at your business online.**
>
> I'm a cybersecurity analyst (Cisco Certified in Cybersecurity, (ISC)� Candidate,
> Blue Team Junior Analyst). I run a professional external vulnerability scan of
> your website or server and deliver a clear, branded PDF report you can actually
> act on � findings ranked by severity, each with a plain-English explanation, a
> CVSS score, mappings to NIST 800-53 and MITRE ATT&CK, and a specific fix.
>
> This is a **non-intrusive external assessment** � I look at what's exposed to the
> internet. No exploitation, no downtime, no risk to your systems.
>
> **You get:**
> - A multi-page PDF report (executive summary + detailed findings + remediation)
> - Every finding scored and prioritized so you fix the important things first
> - Plain-English recommendations � no jargon dumps
> - A short written summary you can forward to your team or your host
>
> **Requirement:** I only scan systems you own or are authorized to test. Before I
> start, you'll confirm authorization in writing (I send a simple one-line form).
> This keeps everything legal and above-board.
>
> Portfolio & credentials: **sergrdz.pages.dev**

---

## Packages / pricing

| | **Basic � $75** | **Standard � $150** | **Premium � $300** |
|---|---|---|---|
| External port & service scan | ? | ? | ? |
| Findings ranked by severity (CVSS) | ? | ? | ? |
| Branded PDF report | ? | ? | ? |
| NIST 800-53 + MITRE ATT&CK mapping | � | ? | ? |
| Prioritized remediation guidance | Short | Full | Full + step-by-step |
| Hosts included | 1 | up to 3 | up to 10 |
| 30-min findings walkthrough call | � | � | ? |
| Re-scan after you fix (verification) | � | � | ? |
| Delivery | 2 days | 3 days | 5 days |

Start Basic to build reviews fast (your plan: "build 5 reviews fast"), then push
buyers toward Standard/Premium.

---

## First message to every buyer (paste this)

> Thanks for ordering! Two quick things before I scan:
>
> 1. **Confirm authorization.** Please reply with the domain(s)/IP(s) you want
>    tested and this line: *"I own or am authorized to test these systems and
>    authorize this scan."* (I can only test systems you control � this keeps it legal.)
> 2. **Timing.** Any window you'd prefer I run it in?
>
> As soon as I have that, I'll get started and deliver your report within the
> package timeframe.

---

## Delivery message (paste when you deliver)

> Your external vulnerability assessment is attached. Quick summary:
>
> - **[X] findings** � [N] high, [N] medium, [N] low.
> - The most important item to address first is **[top finding title]** � details
>   and the exact fix are on page [P].
>
> The full report includes every finding with severity, a CVSS score, framework
> mappings, and a specific recommendation. Happy to answer any questions or walk
> you through it. If you fix the high-severity items, I'm glad to re-scan to verify
> (included in Premium, or a small add-on otherwise).
>
> If this was helpful, a review means a lot to a growing practice. Thank you!

---

## Your delivery workflow (behind the scenes)

1. Buyer confirms authorization ? save their message.
2. Put their target(s) in a scope file (copy `RangeCheck/examples/sample-scope.yaml`).
3. Run one command:
   ```
   py run_gig.py --scope scope.yaml --client "Their Company LLC"
   ```
   (or `--target <ip> --confirm-authorized` for a single host)
4. The finished PDF lands in `deliverables/`. Skim it, then upload to Fiverr.

**Never skip step 1.** See `CLIENT_AUTHORIZATION.md`.
