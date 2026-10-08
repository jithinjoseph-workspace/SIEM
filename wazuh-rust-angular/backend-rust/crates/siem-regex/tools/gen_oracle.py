#!/usr/bin/env python3
"""Generate differential test cases for siem-regex against Wazuh's C os_regex.

Usage:
    python gen_oracle.py <wazuh-src-root> <harness-exe> <out.tsv> [--per-pattern N] [--fuzz N] [--seed S]

<wazuh-src-root> is the wazuh-4.x checkout (containing src/ and ruleset/).
<harness-exe> is tools/harness.c compiled against that checkout's src/os_regex:

    gcc -O1 -w -I<dir-with shared.h=shim_shared.h> -I<wazuh>/src/os_regex -o harness \
        harness.c <wazuh>/src/os_regex/{os_regex_compile,os_regex_execute,os_regex_free_pattern,\
        os_regex_maps,os_match_compile,os_match_execute,os_match_free_pattern,os_regex_match}.c -lpthread

Output rows: mode \t hex(pattern) \t hex(log) \t expected
"""
import glob
import json
import os
import random
import re
import subprocess
import sys


def hx(s: bytes) -> str:
    return s.hex()


def xml_unescape(s: str) -> str:
    return s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&apos;", "'").replace("&amp;", "&")


def ruleset_patterns(root):
    """(mode, pattern) for every OSRegex/OSMatch expression in the stock ruleset."""
    out = set()
    tag_re = re.compile(r"<(regex|prematch|match|field|srcip|user|program_name|hostname|url|id|status|action|extra_data|location|system_name|protocol|data)\b([^>]*)>(.*?)</\1>", re.S)
    for path in glob.glob(os.path.join(root, "ruleset", "**", "*.xml"), recursive=True):
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
        is_decoder = "decoders" in path.replace("\\", "/")
        for tag, attrs, body in tag_re.findall(text):
            m = re.search(r'type\s*=\s*"([^"]+)"', attrs)
            typ = m.group(1).lower() if m else None
            if typ == "pcre2":
                continue
            body = xml_unescape(body.strip())
            if not body:
                continue
            if typ == "osmatch" or (typ is None and tag == "match"):
                out.add(("M", body))
                out.add(("W", body))
            else:
                if tag in ("srcip",):
                    continue
                out.add(("R", body))
                out.add(("r", body))
    return sorted(out)


def ini_logs(root):
    logs = []
    for path in glob.glob(os.path.join(root, "ruleset", "testing", "tests", "*.ini")):
        for line in open(path, encoding="utf-8", errors="replace"):
            m = re.match(r"^log \d+ (?:pass|fail) = (.*)$", line.rstrip("\n"))
            if m:
                logs.append(m.group(1))
    return logs


def json_cases(root):
    path = os.path.join(root, "src", "unit_tests", "os_regex", "test_os_regex_execute.json")
    cases = []
    for group in json.load(open(path, encoding="utf-8")):
        for t in group["batch_test"]:
            cases.append(("R", t["pattern"], t["log"]))
            cases.append(("r", t["pattern"], t["log"]))
    return cases


ESCAPES = [r"\w", r"\d", r"\s", r"\p", r"\W", r"\D", r"\S", r"\.", r"\t", r"\$", r"\(", r"\)", r"\\", r"\|", r"\<"]
LITS = list("ab1 :-./=[]\"'xyzAB09_")


def fuzz_pattern(rng):
    parts = []
    in_group = False
    for _ in range(rng.randint(1, 9)):
        r = rng.random()
        if r < 0.45:
            e = rng.choice(ESCAPES)
            parts.append(e + rng.choice(["", "", "+", "*"]))
        elif r < 0.75:
            parts.append(rng.choice(LITS))
        elif r < 0.85 and not in_group:
            parts.append("(")
            in_group = True
        elif r < 0.95 and in_group:
            parts.append(")")
            in_group = False
        else:
            parts.append(rng.choice(LITS))
    if in_group:
        parts.append(")")
    p = "".join(parts)
    if rng.random() < 0.15:
        p = "^" + p
    if rng.random() < 0.15:
        p = p + "$"
    if rng.random() < 0.1:
        p = p + "|" + fuzz_pattern(rng)
    return p


def fuzz_log(rng):
    alpha = "ab1 2:-./=\tAB_xyz\\$|()<"
    return "".join(rng.choice(alpha) for _ in range(rng.randint(0, 24)))


def fuzz_match_pattern(rng):
    alpha = "ab1 :-.AB^$|!"
    return "".join(rng.choice(alpha) for _ in range(rng.randint(0, 8)))


def main():
    args = sys.argv[1:]
    root, harness, out = args[0], args[1], args[2]
    per_pattern = 25
    fuzz = 20000
    seed = 4147
    if "--per-pattern" in args:
        per_pattern = int(args[args.index("--per-pattern") + 1])
    if "--fuzz" in args:
        fuzz = int(args[args.index("--fuzz") + 1])
    if "--seed" in args:
        seed = int(args[args.index("--seed") + 1])
    rng = random.Random(seed)

    logs = ini_logs(root)
    cases = json_cases(root)
    for mode, pat in ruleset_patterns(root):
        for log in rng.sample(logs, min(per_pattern, len(logs))):
            cases.append((mode, pat, log))
            # Also try the tail after the first space/colon: decoders run
            # regexes on the text left after prematch.
            for sep in (": ", " "):
                if sep in log:
                    cases.append((mode, pat, log.split(sep, 1)[1]))
                    break
    for _ in range(fuzz):
        p = fuzz_pattern(rng)
        for _ in range(3):
            cases.append((rng.choice("Rr"), p, fuzz_log(rng)))
        mp = fuzz_match_pattern(rng)
        cases.append(("M", mp, fuzz_log(rng)))
        cases.append(("W", mp, fuzz_log(rng)))

    # Drop cases the C harness cannot represent (embedded NUL / newlines).
    clean = []
    for mode, p, l in cases:
        pb, lb = p.encode("utf-8"), l.encode("utf-8")
        if b"\0" in pb or b"\0" in lb or b"\n" in pb or b"\n" in lb:
            continue
        clean.append((mode, pb, lb))

    # The C code has memory-safety bugs on some inputs (e.g. `\S(\s*)$` with
    # OS_RETURN_SUBSTRING). When the harness dies, record CRASH for that case
    # and resume with the next one.
    results = []
    start = 0
    while start < len(clean):
        feed = "".join(f"{m}\t{hx(p)}\t{hx(l)}\n" for m, p, l in clean[start:])
        res = subprocess.run([harness], input=feed.encode(), stdout=subprocess.PIPE)
        got = res.stdout.decode().splitlines()
        results.extend(got)
        start += len(got)
        if res.returncode == 0:
            break
        results.append("CRASH")
        print(f"C harness crashed on: {clean[start]!r}", file=sys.stderr)
        start += 1
    assert len(results) == len(clean), (len(results), len(clean))
    with open(out, "w", newline="\n") as f:
        for (m, p, l), r in zip(clean, results):
            f.write(f"{m}\t{hx(p)}\t{hx(l)}\t{r}\n")
    print(f"wrote {len(clean)} cases to {out}")


if __name__ == "__main__":
    main()
