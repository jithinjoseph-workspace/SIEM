# provigil-agent: the full policy set (same checks as the old agent, our own text)

Written 2026-11-04. Supersedes the "Revision" section of `agent-sca-policies.md`.

## What is in `specs/sca-manifest/`

Built by the description side from the old policy files, keeping **only technical facts**: which
setting each check reads and the value it expects (the rule strings and the check condition). No
titles, descriptions, rationale, impact, remediation, references, compliance or comments were
copied. Identical checks across policies share one setting id.

- `settings.json`: list of `{id: "S0001", condition: "all"|"any"|"none", rules: [...], used_by: [policy ids]}` (996 settings).
- `policies.json`: list of `{policy, applies_to, requirements: {condition, rules}, variables, checks: ["S0001", ...]}` in check order (19 policies, 3,205 checks).

| Policy | Checks | | Policy | Checks |
|---|---|---|---|---|
| provigil_win10 | 424 | | provigil_apache24 | 30 |
| provigil_win11 | 482 | | provigil_iis10 | 41 |
| provigil_win2012 | 294 | | provigil_mysql56_community | 19 |
| provigil_win2012r2 | 291 | | provigil_mysql56_enterprise | 26 |
| provigil_win2016 | 334 | | provigil_postgresql13 | 30 |
| provigil_win2019 | 347 | | provigil_sqlserver2012 / 2014 / 2016 / 2017 | 23 each |
| provigil_win2022 | 359 | | provigil_sqlserver2019 | 22 |
| provigil_win2025 | 398 | | provigil_web_exposure | 16 |

## Part A: rule language the engine must run (`src/sca/mod.rs`)

The rule strings in the manifest are used unchanged. A rule is `[not ]<kind>:<target>[ -> <part>]...`.

- `not` in front inverts the rule's true / false; "cannot be evaluated" stays as it is.
- **Content part** (the last part of `r:` / `f:` / `d:` / `c:` rules): one or more patterns
  separated by ` && `; all must hold **on the same line** (empty segments, e.g. `&& &&`, are
  ignored). A pattern is:
  - `r:<regex>`: the line matches;
  - `!r:<regex>`: the line does not match;
  - `n:<regex with one capture group> compare <op> <number>`: the line matches and the captured
    number compares true (`<`, `<=`, `==`, `!=`, `>=`, `>`);
  - otherwise literal text: equal to the whole line / value (numbers compare as numbers, text
    ignoring case).

  The content part holds when at least one line satisfies all its patterns.
- Regexes are case-insensitive. A regex that does not compile makes the rule "cannot be
  evaluated" (logged once), never a crash.
- `r:<key>`: the key exists. `r:<key> -> <value>`: the value exists. `r:<key> -> <value> -> <content>`:
  the value's data satisfies the content part. Key roots: `HKEY_LOCAL_MACHINE`/`HKLM`,
  `HKEY_USERS`/`HKU`, `HKEY_CURRENT_USER`/`HKCU`, `HKEY_CLASSES_ROOT`/`HKCR`; 64-bit view. Data
  as text: DWORD / QWORD in decimal, strings as is, REG_MULTI_SZ as its strings joined by a space
  on one line, binary as hex. A missing key or value makes the rule false (not "cannot be evaluated").
- `f:<path>`: the file exists. `f:<path> -> <content>`: some line of the file satisfies the content part.
- `d:<dir>`: the directory exists. `d:<dir> -> <file name regex>`: a file whose name matches exists
  in the directory or its subdirectories. `d:<dir> -> <file name regex> -> <content>`: such a file
  has a line satisfying the content part.
- `p:<process name regex>`: a running process matches.
- `c:<command> -> <content>`: run the command (Windows: `cmd /C <command>`; environment variables
  such as `%systemroot%` and PowerShell's `$env:` work because the shell expands them), 30 s
  timeout, read standard output and standard error; some output line satisfies the content part.
  A command that cannot be started or times out makes the rule "cannot be evaluated"; a non-zero
  exit code with output is evaluated normally. `c:<command>` without content: the command ran and
  exited 0. The existing special kinds `c:secedit-value:` and `c:auditpol:` stay.
- **Variables**: a policy may have `variables: {"$name": "value"}`. `$name` in a rule target is
  replaced by its value before evaluation (longest name first, so `$conf-dirs` is not taken as
  `$conf`). A comma-separated value means several targets: the rule holds when it holds for any of
  them. A variable whose value is null or empty makes the rule "cannot be evaluated". `$env:` (PowerShell)
  is not a policy variable and is left alone.
- **Policy requirements** may also be written as `requirements: {condition: all|any|none, rules: [...]}`
  (besides the current all / any / none lists).
- Commands run per check; the same command string with the same variables within one scan runs
  once (cache for the scan), so a policy with dozens of `auditpol` / `secedit` checks stays fast.
- Check ids only need to be unique within a policy and across the policies that can run on the
  same machine; the built-in uniqueness test checks ids unique across all built-in policies
  (the generator below gives each policy its own range, so this holds).

## Part B: our own text per setting (`specs/sca-manifest/catalog-*.yml`)

For each setting id, written from Microsoft's / the vendor's public documentation in our own words:

```yaml
S0001:
  title: "<setting name>: <expected state>"
  description: "<what the setting controls, 1-3 sentences>"
  rationale: "<why the expected state is safer, 1-2 sentences>"
  remediation: "<how to set it: Group Policy path and/or registry value / command / config line>"
  compliance: { nist_800_53: [...], pci_dss: [...], hipaa: [...], iso_27001: [...] }
```

The writer reads only `settings.json` (the rules show the exact setting and expected value) and
`policies.json` (which systems use it). No CIS numbers, titles or wording; no "CIS".

## Part C: the generator (`specs/sca-manifest/build_policies.py`)

Joins `policies.json` + `settings.json` + the catalog into `crates/provigil-agent/src/sca/policies/<policy>.yml`
(one file per policy, checks in manifest order, ids `60000 + 1000 * <policy index> + <position>`).
Our own policy names and descriptions; requirements from the manifest, except:
- `provigil_win10`: ProductName `^Windows 10` and CurrentBuildNumber < 22000;
- `provigil_win11`: ProductName `^Windows 10|^Windows 11` and CurrentBuildNumber >= 22000
  (the old files both ran on any Windows 10 / 11);
- SQL Server policies additionally require `HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL`.

The old `provigil_win_baseline.yml` and `provigil_win_apps.yml` are removed; `BUILTIN` lists the 19 files.
