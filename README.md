# agent-shield

**Audit a codebase for what an AI reverse-engineering agent can extract — before you ship it.**

AI agents now read shipped code the way a human reviewer never would: exhaustively, fast, and with perfect recall of every secret, internal endpoint and architecture hint. `agent-shield` audits your own tree the way such an agent would — secret scan, leakage scan, exposure score 0–100 with a grade, JSON output and CI exit codes — plus a `--redact` mode that writes a redacted copy of the tree.

> Pattern learned from the November 2026 trend (BLA vs REA): the counter-move to agent reverse-engineering is defense at the source — make your own code unreadable to the agent *before* it ships. `agent-shield` is the audit half of that loop: it finds what an RE agent would lift, scores the exposure, and hands you a redacted copy. It never modifies your tree in place, never phones home, and never prints a secret in full.

## Install

No dependencies. Python 3.8+.

```bash
git clone https://github.com/sina09185790374-design/agent-shield
cd agent-shield
python3 -m agent_shield audit ./my-project
```

## Usage

```bash
# Human-readable exposure report
python3 -m agent_shield audit ./my-project

# Machine-readable report for agent pipelines
python3 -m agent_shield audit ./my-project --json

# Fail the build only on critical findings
python3 -m agent_shield audit ./my-project --fail-on critical

# Also write a redacted copy (secrets replaced by ***REDACTED***)
python3 -m agent_shield audit ./my-project --redact ./my-project-redacted

# Skip vendored / generated trees
python3 -m agent_shield audit ./my-project --exclude vendor/ --exclude dist/
```

Exit codes: `0` = clean (or only findings below `--fail-on`), `1` = failing findings, `2` = usage/runtime error.

## What it finds

| Category | Examples | Severity |
|---|---|---|
| `secret` | AWS keys, GitHub PATs, OpenAI/Stripe/Slack keys, private-key blocks, JWTs, `api_key = "..."` assignments, DB connection strings with passwords | critical–medium |
| `leakage` | Internal endpoints (`localhost`, RFC1918, `.internal`), admin/debug surface, credential hints in TODO comments, architecture/service-map docs, `.env` files holding real values | high–low |

False-positive guards: placeholder values (`example`, `test`, `changeme`, …) are never flagged, git SHAs and content hashes are not mistaken for tokens, and the most specific rule wins per line (a `sk_live_...` line is one Stripe finding, not two).

## Exposure score

Weighted by severity (critical 25, high 15, medium 8, low 3), capped at 100. Grades: `A` = 0, `B` ≤ 15, `C` ≤ 40, `D` ≤ 70, `F` > 70.

## Redaction

`--redact OUTDIR` copies the tree and replaces every flagged secret value with `***REDACTED***`. The source tree is never touched; binary files are copied verbatim; plain config values (`DEBUG=false`) survive untouched. The JSON report includes a redaction manifest (`files_redacted`, `values_redacted`).

## Tests

```bash
python3 -m unittest discover -s tests -v
```

17 tests: detection (AWS/GitHub/Stripe/DB-string/internal-endpoint/credential-hint/architecture-map/`.env`), placeholder + git-SHA false-positive guards, secret masking, scoring and grade boundaries, redaction (no secrets survive, source untouched, config preserved), CLI exit codes and JSON output.

---

# agent-shield (فارسی)

**کدت را قبل از انتشار، با چشم یک ایجنتِ مهندسی معکوس بررسی کن.**

ایجنت‌های هوش مصنوعی حالا کد منتشرشده را طور دیگری می‌خوانند: کامل، سریع و با حافظهٔ بی‌نقص از هر سیکرت، اندپوینت داخلی و نقشهٔ معماری. `agent-shield` درخت کد خودت را همان‌طور که چنین ایجنتی می‌خواند بررسی می‌کند — اسکن سیکرت، اسکن نشت اطلاعات، امتیاز مواجهه ۰ تا ۱۰۰ با نمره، خروجی JSON و کد خروج مناسب CI — به‌علاوه حالت `--redact` که یک نسخهٔ سانسورشده از درخت می‌سازد.

## نصب

بدون وابستگی. پایتون ۳٫۸ به بالا.

```bash
python3 -m agent_shield audit ./my-project
```

## کاربرد

```bash
python3 -m agent_shield audit ./my-project --json        # گزارش ماشینی
python3 -m agent_shield audit ./my-project --fail-on critical
python3 -m agent_shield audit ./my-project --redact ./my-project-redacted
```

کدهای خروج: `۰` = تمیز، `۱` = یافتهٔ خطادار، `۲` = خطای استفاده/اجرا.

## چه چیزی پیدا می‌کند

- **سیکرت:** کلید AWS، توکن گیت‌هاب، کلید OpenAI/Stripe/Slack، بلاک کلید خصوصی، JWT، انتساب‌هایی مثل `api_key = "..."` و رشتهٔ اتصال دیتابیس با پسورد.
- **نشت اطلاعات:** اندپوینت‌های داخلی (`localhost`، آی‌پی خصوصی، `.internal`)، سطح admin/debug، اشاره به پسورد در کامنت‌های TODO، اسناد نقشهٔ معماری/سرویس، و فایل `.env` با مقدار واقعی.

مقدارهای نمونه (`example`، `test`، `changeme` و…) هرگز فلگ نمی‌شوند؛ هش گیت با توکن اشتباه گرفته نمی‌شود؛ و سیکرت‌ها در خروجی هیچ‌وقت کامل چاپ نمی‌شوند.

## License

MIT — see [LICENSE](LICENSE).
