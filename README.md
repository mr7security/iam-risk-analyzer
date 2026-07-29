# IAM Risk Analyzer

> Security posture assessment tool for Microsoft Entra ID (Azure AD) — generates a professional HTML pentest-style report with findings classified by severity.

Built for red and blue team engagements. Designed to surface the IAM misconfigurations that matter most: excessive privilege, MFA gaps, dormant accounts with roles, and risky service principals.

---

## What it checks

| ID | Severity | Check |
|---|---|---|
| CR-01 | 🔴 CRITICAL | More than 3 Global Administrators |
| CR-02 | 🔴 CRITICAL | Global Admin accounts without MFA |
| CR-03 | 🔴 CRITICAL | Service Principals with RoleManagement.ReadWrite permission |
| CR-04 | 🔴 CRITICAL | Accounts with non-expiring passwords + privileged roles |
| HI-01 | 🟠 HIGH | Privileged users without MFA |
| HI-02 | 🟠 HIGH | Dormant accounts (90+ days) with active role assignments |
| HI-03 | 🟠 HIGH | Guest users with directory roles |
| HI-04 | 🟠 HIGH | Service Principal secrets expired or expiring within 30 days |
| ME-01 | 🟡 MEDIUM | Non-privileged users without MFA |
| ME-02 | 🟡 MEDIUM | Excessive guest user ratio (>20%) |
| ME-03 | 🟡 MEDIUM | Security groups with a single owner |
| ME-04 | 🟡 MEDIUM | App Registrations with suspicious redirect URIs |
| IN-01 | 🔵 INFO | Global Administrator inventory |
| IN-02 | 🔵 INFO | Service Principal Graph permissions inventory |
| IN-03 | 🔵 INFO | Users inactive for 30+ days |
| IN-04 | 🔵 INFO | Conditional Access Policy inventory |

---

## Prerequisites

- Python 3.11+
- An Azure App Registration with the permissions below (or an account that can authenticate via Device Code)

### Required Graph API Permissions (Application)

```
User.Read.All
Group.Read.All
Directory.Read.All
RoleManagement.Read.Directory
Policy.Read.All
Application.Read.All
AuditLog.Read.All
```

### Create the App Registration (az CLI)

```bash
# 1. Create the app
az ad app create --display-name "IAM-Risk-Analyzer"

# 2. Create a service principal
az ad sp create --id <app-id>

# 3. Add required permissions (repeat for each)
az ad app permission add \
  --id <app-id> \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions \
    df021288-bdef-4463-88db-98f22de89214=Role \
    5b567255-7703-4780-807c-7be8301ae99b=Role \
    7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role \
    9e3f62cf-ca93-4e39-b65c-4b9e28a22b7a=Role \
    246dd0d5-5bd0-4def-940b-0421030a5b68=Role \
    9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30=Role \
    b0afded3-3588-46d8-8b3d-9842eff778da=Role

# 4. Grant admin consent
az ad app permission admin-consent --id <app-id>

# 5. (Optional) Create a client secret
az ad app credential reset --id <app-id> --years 1
```

---

## Installation

```bash
git clone https://github.com/YOUR_GITHUB/iam-risk-analyzer
cd iam-risk-analyzer
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your credentials
```

---

## Usage

### Device Code (interactive — easiest to start)
```bash
python main.py \
  --auth-method device_code \
  --tenant-id <tenant-id> \
  --client-id <client-id> \
  --output report.html
```

### Client Secret (non-interactive / CI)
```bash
python main.py \
  --auth-method client_secret \
  --tenant-id <tenant-id> \
  --client-id <client-id> \
  --client-secret <secret> \
  --output report.html
```

### Certificate
```bash
python main.py \
  --auth-method certificate \
  --tenant-id <tenant-id> \
  --client-id <client-id> \
  --cert-path ./certs/my-cert.pfx \
  --output report.html
```

### Run specific checks only
```bash
python main.py \
  --auth-method device_code \
  --tenant-id <tenant-id> \
  --client-id <client-id> \
  --checks CR-01,CR-02,HI-01,HI-02
```

### Docker
```bash
docker build -t iam-risk-analyzer .
docker run --rm \
  -e AZURE_TENANT_ID=<tid> \
  -e AZURE_CLIENT_ID=<cid> \
  -e AZURE_CLIENT_SECRET=<secret> \
  -e AZURE_AUTH_METHOD=client_secret \
  -v $(pwd)/output:/output \
  iam-risk-analyzer --output /output/report.html
```

---

## Output

A self-contained HTML file with:
- Overall risk score (0–100)
- Executive summary table (Critical / High / Medium / Info counts)
- Per-finding detail: description, evidence table, recommendation, reference
- Print-to-PDF ready (dark theme degrades gracefully for printing)

---

## Project Structure

```
iam-risk-analyzer/
├── main.py                  # CLI entry point
├── auth/
│   └── authenticator.py     # MSAL auth — 3 methods
├── checks/
│   ├── critical.py          # CR-01 to CR-04
│   ├── high.py              # HI-01 to HI-04
│   ├── medium.py            # ME-01 to ME-04
│   └── informational.py     # IN-01 to IN-04
├── graph/
│   └── client.py            # Graph API wrapper with pagination
├── report/
│   └── html_generator.py    # Self-contained HTML report
└── utils/
    ├── finding.py           # Finding dataclass
    └── scoring.py           # Risk score calculation
```

---

## Legal Disclaimer

This tool is intended **exclusively for authorized security assessments**. Only use it against Azure tenants you own or have explicit written permission to assess. Unauthorized use may violate computer crime laws in your jurisdiction.

---

## License

MIT License — see [LICENSE](LICENSE)

---

*Part of the [MR7SECURITY](https://www.linkedin.com/in/YOUR_PROFILE) cybersecurity portfolio.*
