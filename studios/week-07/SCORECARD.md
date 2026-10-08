# Week 7 Studio — Blocklists Lose, Boundaries Win

---

## The tasks

### Task 1

**Asked:** `measure_coverage(payloads)` → `(blocked, total)`.

**Solution:** run every attack through the WAF and count how many it blocked.

```python
blocked = sum(1 for p in payloads if waf_block(p) is not None)
return blocked, len(payloads)
```

**Result: 4/4.** The WAF catches all four week-6 attacks.

**Why it matters:** it looks perfect, but **it's a trap**. It only shows that the
WAF recognises what we already put on its list. It says nothing about what we
didn't list.

---

### Task 2

**Asked:** `measure_bypasses(BYPASSES)` → `(through, total)`.

**Solution:** count how many attack variants the WAF did **not** block.

```python
through = sum(1 for payload, _why in bypasses if waf_block(payload) is None)
return through, len(bypasses)
```

**Result: 3/4 get through.** Same attack, written differently:

| Variant | What changed | Stopped by the WAF? |
|---|---|---|
| Compare letters instead of numbers | The rule only looks for "number = number" | passed |
| Mixed upper/lower case | The rule already ignores case | blocked |
| XSS using an image tag instead of `<script>` | The rule only looks for the word `script` | passed |
| An invisible character inside "DROP" | The word no longer matches letter by letter | passed |

**Why it matters:** each variant takes about five minutes to invent. The list of
"bad things" **never ends**, because there are endless ways to write the same
thing. A defense nobody tried to bypass **has not been evaluated**.

---

### Task 3

**Asked:** `measure_false_positives(load_benign())` → list of `(input, rule)`.

**Solution:** run all 26 legitimate requests through the WAF and keep the ones it
blocked by mistake, with the rule responsible.

```python
fps = []
for inp in benign:
    rule = waf_block(inp)
    if rule is not None:
        fps.append((inp, rule))
return fps
```

**Result: 2 of 26 innocent users blocked (7.7%).**

| Legit request blocked | Rule that fired | What the person wanted |
|---|---|---|
| `drop table tennis lessons for beginners` | SQLi DROP TABLE | Find table-tennis classes |
| `reserve the drop table at the makerspace for friday` | SQLi DROP TABLE | Book a folding table |

**Why it matters:** every false positive is a real person who couldn't use the
service: a support ticket, an hour of someone's time. A WAF that annoys customers
**gets switched off**, and a switched-off WAF protects 0%.

> **Both blades fail together.** Loosen the rules to stop bothering people and
> more attacks get through. Tighten them to catch more attacks and more people
> get blocked. **There is no sweet spot**, because you are trying to list
> everything bad. That is exactly what `test_blocklist_loses_on_both_blades`
> checks.

---

### Task 4

**Asked:** `count_injection_successes(payloads)` → `(succeeded, total)`, using
every attack and bypass as the username for `parameterized_login`.

**Solution:** try to log in with each of the 8 attacks (with a wrong password)
and count how many got in.

```python
succeeded = sum(1 for p in payloads if parameterized_login(p, "wrong"))
return succeeded, len(payloads)
```

**Result: 0/8.** No attack works.

**Why:** the parameterized login **never builds a command by pasting in the
user's text**. It only asks: "is there a user named *exactly* this, with this
password?" The attack is just treated as a weird name. No rule blocks it; it
simply **has no way** to become a command.

**The guarantee, said out loud (axis 2):**

> *"User input cannot alter query structure, for **any** input."*

The WAF could never say that. It can only say "I blocked the ones I know".

---

### Task 5

**Asked:** `bypass_leaks_canary(base_url)`. Put the WAF in front of the **real**
`/login` of `vuln-web` (the vulnerable week-6 app), send the variants the WAF
lets through, and check whether the canary leaked.

**Solution:**

```python
canary = vulnweb_canary()
for payload, _why in BYPASSES:
    if waf_block(payload) is not None:
        continue                      # the WAF stopped it: never reaches the app
    body = send_login(base_url, payload)
    if canary in body:                # sound oracle: the secret leaked, not an echo
        return True
return False
```

1. If the WAF blocks a variant, it is not sent (just like in real life).
2. If the WAF lets it through, it goes to the real login.
3. We check whether the **canary** (a secret hidden in the admin's row) appears
   in the response.

**Result: `True`.** The "compare letters" variant got past the WAF, reached the
vulnerable query, and **returned the admin's secret**.

**Why look for the canary instead of "the response changed"?** Because a changed
response, or your own text showing up on the page, might just be an echo. A
secret the attacker **did not know** showing up is undeniable proof that data was
stolen. That is a **sound oracle**.

#### The anomaly detector (`anomaly()`)

Besides the WAF, `waf.py` has a detector that flags any text with a quote or
semicolon followed by words like `select`, `drop`, `or`, `union` or `onerror`.
**It doesn't block anything.** It only asks a human to take a look. It's a
**sensor, not a wall**.

| | Result |
|---|---|
| Variants that **got past the WAF** but were still flagged | **1** (the "compare letters" one, the same one that stole the canary) |
| Variants that got past and were **not** flagged | 2 (the image XSS and the invisible-character one) |
| **Legit** users flagged by mistake | 1 of 26: the surname **`o'connor`** (a quote followed by "or" inside "c**onnor**") |

**Lesson:** detection has a cost too. Every alert is an analyst's time (week 13's
automation paradox). The detector widens the net, but it still makes mistakes and
still misses things.

---

## Scorecard

| Control | Model | Guarantee (axis 2) | Bypass (axis 4) | FP cost (axis 5) |SSS
|---|---|---|---|---|
| WAF blocklist | negative (enumerate bad) | **none** | yes — trivial variants (3/4 through) | high — 2/26 real users blocked (7.7%) |
| Parameterized queries | positive (input is data) | **yes — input can't become code** | none (0/8 succeeded) | zero |
| WAF as detection | — | none, but **visibility** | n/a | analyst load (1/26 legit users flagged; wk 13) |