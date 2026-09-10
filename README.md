# logsift

**Collapse a noisy log into the handful of things that are actually happening.**

A 200,000-line log usually contains about twenty distinct events, repeated with
different IDs, IPs and timestamps. Reading it line by line is hopeless. Grepping
for `error` gives you 40,000 hits of the same error.

`logsift` masks the variable parts of every line to produce a **template**, groups
identical templates, and ranks them by frequency.

```
$ ./logsift.py sample.log
Scanned 4,000 lines — 4,000 matched, 7 distinct patterns.

  COUNT  LEVEL  LINES            PATTERN
-------  -----  ---------------  ---------------------------------------------------
  1,357  info   2-4000           <TIMESTAMP> INFO nginx: GET <PATH> <NUM> <NUM>
  1,057  info   1-3996           <TIMESTAMP> INFO sshd: Accepted publickey for depl…
    671  debug  5-3999           <TIMESTAMP> DEBUG cache: evicted key <UUID> after …
    438  error  3-3998           <TIMESTAMP> ERROR sshd: Failed password for invali…
    210  warn   60-3991          <TIMESTAMP> WARN nginx: upstream timed out connect…
    163  info   7-3972           <TIMESTAMP> INFO cron: session opened for user bac…
    104  error  55-3910          <TIMESTAMP> ERROR postgres: deadlock detected on r…
```

Four thousand lines, seven things happening. The 438 failed SSH passwords are one
row instead of 438.

## Usage

```bash
./logsift.py app.log                 # rank every pattern
./logsift.py app.log --level error   # errors only
./logsift.py app.log --top 5         # five most frequent
cat app.log | ./logsift.py --json    # machine-readable, for piping onward
```

Python 3.9+. **No dependencies** — standard library only.

## How it works

Each line is reduced to its shape by masking the parts that change between
occurrences:

| Masked | Token |
|---|---|
| `2026-09-10T07:15:02Z`, `Sep 10 07:15:02` | `<TIMESTAMP>` |
| `3f2504e0-4f89-11d3-9a0c-0305e82c3301` | `<UUID>` |
| `192.168.1.42`, `10.0.0.1:8080` | `<IP>` |
| `00:1b:44:11:3a:b7` | `<MAC>` |
| `/var/log/nginx/access.log` | `<PATH>` |
| `4821`, `1.5s`, `12MB`, `85%` | `<NUM>` |

Lines that reduce to the same template are the same event. Count them, keep the
first and last line number, and you have a summary.

**Mask order is load-bearing.** UUIDs contain hex runs and timestamps contain
numbers, so the number mask has to run last — otherwise it shreds both before
they are ever recognised. There is a regression test pinning this.

## Two bugs worth knowing about

Both were found by running the tool on a realistic 4,000-line log rather than by
the unit tests, which is the point of doing both.

**Numbers with unit suffixes never collapsed.** The number mask was `\b\d+\b`.
That never matches `61504ms`, because `\b` requires a non-word character after the
digits and `m` is a word character. Every distinct duration, byte size and
percentage therefore became its own "unique" pattern. The 4,000-line sample
reported **2,024 distinct patterns instead of 7** — the tool was doing the exact
opposite of its job while every unit test passed. Fixed by consuming the unit
along with the number.

**Severity escalation is rarer than it looks.** A group takes the highest severity
it was ever seen at. But two lines sharing a template almost always share their
severity word too, since that word is part of the template. The escalation path
only fires when the severity marker sits inside a *masked* region — for example
`/var/log/error/…` versus `/var/log/debug/…`, which both reduce to `read <PATH>`.
The test exercises that case specifically.

## Tests

```bash
python3 -m unittest -v
```

21 tests covering mask ordering, unit suffixes, identifier digits (`ssh2` and
`utun0` are names, not measurements), level detection, grouping, line spans,
filtering, and empty input.

## License

MIT — see [LICENSE](LICENSE).
