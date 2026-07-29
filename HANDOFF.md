# HANDOFF — IAM Risk Analyzer

**Repo:** https://github.com/mr7security/iam-risk-analyzer
**Audience:** Devin (autonomous engineer)
**Status:** Scaffolding complete. Core plumbing works end-to-end. All 16 security checks are stubbed and raise `NotImplementedError`. Your job is to implement them plus a few smaller gaps, with tests.

---

## 1. What this project is

A CLI tool that authenticates to Microsoft Entra ID (Azure AD) via Microsoft Graph, runs a set of IAM security-posture checks, scores the tenant 0–100, and writes a self-contained dark-theme HTML report (pentest style). Read-only against the tenant — it never writes to Entra ID.

Run shape:

```bash
python main.py --auth-method device_code --tenant-id <tid> --client-id <cid> --output report.html
```

Flow (already wired in `main.py`): authenticate → build `GraphClient` → run Critical/High/Medium/Info checks → `calculate_score` → `generate_report`.

---

## 2. Ground rules (do not break these)

1. **Do not change function signatures** of the `check_*` functions or the `run_*_checks` dispatchers.
2. **Do not rename `Finding` fields** (`utils/finding.py`). The scorer and HTML generator depend on them exactly.
3. Every check returns **exactly one `Finding`**. Three terminal states:
   - **Issue found:** populate `evidence` (non-empty), `passed=False`, `error=""`.
   - **Clean:** `passed=True`, empty `evidence`.
   - **Check errored:** set `error` to the message. (The dispatcher already wraps unexpected exceptions into an error `Finding`, but catch and annotate where you can be more specific.)
4. **Informational checks (`IN-*`) never return `passed=True`** — they are inventories and always emit a populated `Finding` (even if the list is empty, return the empty inventory with a clear description).
5. Keep everything **read-only**. No Graph write/PATCH/POST calls.
6. Use the existing `GraphClient` helpers; only add new methods to `graph/client.py` when a needed endpoint is missing. Preserve the pagination pattern (`get_all` follows `@odata.nextLink`).
7. Populate the `reference` field where a docstring gives a MITRE ATT&CK / CIS reference.

---

## 3. Architecture (what already exists and works)

```
main.py                    CLI entry point, arg parsing, orchestration — DONE
auth/authenticator.py      MSAL: client_secret + device_code DONE; certificate PFX DONE, PEM NOT done
graph/client.py            Graph wrapper: bearer auth, pagination, error handling — DONE
checks/critical.py         CR-01..04 — STUBBED (NotImplementedError)
checks/high.py             HI-01..04 — STUBBED
checks/medium.py           ME-01..04 — STUBBED
checks/informational.py    IN-01..04 — STUBBED
report/html_generator.py   Self-contained HTML report — DONE
utils/finding.py           Finding dataclass + Severity enum + SEVERITY_WEIGHT — DONE
utils/scoring.py           0–100 scoring, LOW/MEDIUM/HIGH/CRITICAL label — DONE
requirements.txt           msal, requests — DONE
```

### `Finding` contract (`utils/finding.py`)

```python
@dataclass
class Finding:
    id: str                        # "CR-01"
    title: str
    severity: Severity             # Severity.CRITICAL | HIGH | MEDIUM | INFO
    description: str               # what was found and why it matters
    evidence: list[dict]           # rows rendered as an HTML table
    recommendation: str            # remediation guidance
    reference: str = ""            # MITRE / CIS / MS Docs URL
    passed: bool = False           # True = ran, no issue
    error: str = ""                # non-empty = check failed to run
```

**Evidence shape matters:** `evidence` is a list of dicts; the report builds the table from `list(rows[0].keys())`, so **every row in a finding must share the same keys**. Nested dict/list values are rendered as pretty-printed JSON — that's fine for things like a roles list.

### Scoring (`utils/scoring.py`) — already implemented, just feed it correct findings
CRITICAL +40, HIGH +20, MEDIUM +5, INFO +0, capped at 100. Only findings with `passed=False and error==""` count. Labels: 0–25 LOW, 26–50 MEDIUM, 51–75 HIGH, 76–100 CRITICAL.

### `GraphClient` helpers available (`graph/client.py`)
`get`, `get_all` (auto-paginates), `get_tenant_info`, `get_all_users` (beta, includes `signInActivity`, `passwordPolicies`, `userType`), `get_user_auth_methods(user_id)`, `get_directory_role_assignments` (expands `principal`), `get_role_definitions`, `get_global_admin_role_id`, `get_all_groups`, `get_group_owners(group_id)`, `get_all_service_principals` (includes `passwordCredentials`, `keyCredentials`, `appRoles`), `get_sp_app_role_assignments(sp_id)`, `get_all_applications`, `get_conditional_access_policies`, `get_signin_logs`.

---

## 4. Work to do

Each check's docstring in the source already contains the intended step-by-step logic and the exact evidence-row shape. Implement to that spec. Summary and acceptance criteria below; the GitHub issues (Section 6) track these as discrete units of work — **one PR per issue**.

### 4.1 Critical checks — `checks/critical.py`
- **CR-01** >3 Global Administrators. Evidence: `{displayName, userPrincipalName, id}`.
- **CR-02** Global Admins without MFA. MFA = any auth method whose type is not `#microsoft.graph.passwordAuthenticationMethod`. Evidence: `{displayName, userPrincipalName, authMethods}`.
- **CR-03** Service Principals granted `RoleManagement.ReadWrite.Directory` (appRoleId `9e3f62cf-ca93-4e39-b65c-4b9e28a22b7a`). Evidence: `{displayName, appId, permission}`.
- **CR-04** Users with `DisablePasswordExpiration` in `passwordPolicies` **and** any directory role. Evidence: `{displayName, userPrincipalName, roles}`.

### 4.2 High checks — `checks/high.py`
- **HI-01** Users with any directory role and no MFA method (exclude guests — covered by HI-03). Reference: `https://attack.mitre.org/techniques/T1078/`.
- **HI-02** Dormant accounts: `lastSignInDateTime` older than `DORMANT_DAYS` (90) **or** null, that still hold a role. Reference: CIS M365 1.1.3.
- **HI-03** Guest users (`userType == "Guest"`) with any directory role. Reference: `T1078/004`.
- **HI-04** SP `passwordCredentials` where `endDateTime < now + 30 days` (include already-expired and expiring). Evidence: `{displayName, appId, secretHint, expiresOn, status}` where status ∈ `expired|expiring`.

### 4.3 Medium checks — `checks/medium.py`
- **ME-01** Non-privileged enabled users with only a password method. Note: can be slow — cap/sample large tenants and document the limit.
- **ME-02** Guest ratio > `GUEST_RATIO_THRESHOLD` (0.20). Single evidence row `{totalUsers, guestUsers, guestRatio}`.
- **ME-03** Security/M365 groups with exactly one owner. Only inspect groups with `securityEnabled=True` or `groupTypes` containing `Unified`; avoid an owners call for every group in huge tenants.
- **ME-04** App registrations with redirect URIs matching `SUSPICIOUS_REDIRECT_PATTERNS` (`localhost`, `127.0.0.1`, `*`, `http://`). Check `web.redirectUris` and `publicClient.redirectUris`. Reference: `T1550/001`.

### 4.4 Informational checks — `checks/informational.py` (always emit inventory)
- **IN-01** All Global Admins.
- **IN-02** SPs with Microsoft Graph permissions (`resourceDisplayName == "Microsoft Graph"`).
- **IN-03** Users with `lastSignInDateTime` > 30 days or never signed in.
- **IN-04** Conditional Access policies with state + condition/grant summary.

### 4.5 PEM certificate support — `auth/authenticator.py`
`_certificate_flow()` handles PFX; PEM raises `NotImplementedError`. Implement PEM parsing: split into private key + public certificate and pass MSAL a credential dict (`private_key` / `public_certificate` / optional `thumbprint`). Support encrypted PEM via `cert_password`. Keep the existing PFX path untouched.

### 4.6 Tests + CI (new)
No test suite or CI exists yet. Add:
- `pytest` unit tests per check using a **mocked `GraphClient`** (fixtures of canned Graph responses — no live tenant). Cover all three terminal states per check: issue found, clean, error.
- Tests for `calculate_score` (weights, cap at 100, label boundaries) and `html_generator` (renders without error given a mixed findings list; escapes evidence).
- A GitHub Actions workflow: install `requirements.txt` + dev deps, run `pytest`, run a linter (`ruff` or `flake8`) on Python 3.11.
- Add `pytest`, `ruff`, and any mocking deps to a `requirements-dev.txt`.

### 4.7 Housekeeping (small)
- Replace `YOUR_GITHUB` placeholders (README install URL + report footer link in `html_generator.py`) with `mr7security`.
- Replace `YOUR_PROFILE` in the README LinkedIn link.
- Confirm `.env.example` lists every env var `main.py` reads: `AZURE_AUTH_METHOD`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_CERT_PATH`, `AZURE_CERT_PASSWORD`.

---

## 5. Definition of done

- `python main.py --auth-method device_code --tenant-id <tid> --client-id <cid>` runs against a real/test tenant and produces a valid HTML report with no `NotImplementedError`.
- Every check returns a well-formed `Finding`; evidence rows within a finding share identical keys.
- `--checks CR-01,HI-02` filtering still works (dispatcher logic unchanged).
- `pytest` green; CI passing on Python 3.11.
- No secrets committed. No Graph write calls. Read-only maintained.

---

## 6. Suggested GitHub issues (one PR each)

1. Implement Critical checks (CR-01…CR-04)
2. Implement High checks (HI-01…HI-04)
3. Implement Medium checks (ME-01…ME-04)
4. Implement Informational checks (IN-01…IN-04)
5. PEM certificate support in `_certificate_flow()`
6. Test suite (mocked GraphClient) + `requirements-dev.txt`
7. GitHub Actions CI (pytest + lint, Python 3.11)
8. Housekeeping: replace `YOUR_GITHUB` / `YOUR_PROFILE`, verify `.env.example`

Recommended order: 1→4 in parallel-safe chunks, then 5, then 6→7 (tests depend on checks existing), 8 anytime.
