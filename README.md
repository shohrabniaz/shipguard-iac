# ShipGuard IaC

**Atlassian Codegeist 2026** entry — *Apps for Software Teams* + **Best Agents (Rovo)** bonus.

A Forge app that brings **verified LLM repair** of Terraform and Kubernetes security misconfigurations into Jira. Paste IaC into the issue panel (or talk to the Rovo agent). ShipGuard scans with a lightweight rule engine that runs inside Forge, asks an LLM for a fix (Groq free tier by default), and **throws the fix away** unless a verifier agrees: structural intent is preserved and a re-scan shows progress without new findings.

> Research context: this reuses the *ideas* from [EASE-Bot](https://github.com/shohrabniaz/ease-bot) / the EASE 2027 study (scanner-pass ≠ deployable). It is a **new Forge codebase**, not a wrapper of the Python Action.

## Why not Checkov inside Forge?

Forge functions are Node serverless. They cannot shell out to Checkov, Trivy, or `terraform validate`. ShipGuard therefore ships a **curated JS rule engine** (high-signal CKV-style checks) that is also the re-scan verifier. The EASE loop stays the same: scan → LLM → intent check → re-scan → accept or retry.

## Modules

| Module | What it does |
|---|---|
| `jira:issuePanel` | Paste `.tf` / YAML, Scan, Suggest verified fix |
| `rovo:agent` **ShipGuard IaC** | Chat agent with three actions |
| `action` `scan-iac` | Return findings |
| `action` `suggest-verified-fix` | Verified repair loop |
| `action` `create-finding-issue` | Open a Jira Task for human-decision findings |

## Local (no Atlassian account)

```bash
# unit tests (no network, mock LLM)
npm test

# scan / repair examples with the mock repairer
node bin/shipguard-local.js scan examples/open-ssh.tf
node bin/shipguard-local.js repair examples/risky-pod.yaml
```

Set `GROQ_API_KEY` to use the real Groq model locally instead of mock.

## Deploy on Forge (needs your Atlassian developer site)

1. Create a free developer site: https://developer.atlassian.com/cloud/
2. Create an API token: https://id.atlassian.com/manage-profile/security/api-tokens
3. On this machine (or yours):

```bash
npm install
cd static/panel && npm install && npm run build && cd ../..
forge login          # email + API token
forge register       # replaces app id in manifest.yml
forge variables set GROQ_API_KEY   # encrypted; paste your key when prompted
forge deploy
forge install        # pick your site + Jira
```

4. Create a share/install link for judges:  
   https://developer.atlassian.com/platform/forge/distribute-your-apps/#start-sharing-your-app

## Security

- Never commit API tokens or `GROQ_API_KEY`.
- The repair pipeline never puts the key into notes, findings, or Jira issue bodies.
- Human-decision findings (KMS, IAM `*`, `:latest` image, hostPath, …) are reported, not auto-edited.

## Licence

MIT © Shohrab Hossen Niaz
