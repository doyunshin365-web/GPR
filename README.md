# GPR (Generic Phishing Rules)

English | [한국어](README.ko.md)

A Chrome extension that detects phishing pages in real time using custom, YARA-style rules.

## Features

- Rule-based detection over page text/domain (YARA-like syntax)
- Rules are plain JSON files — add or edit rules without touching the code
- Domains listed in `rules/whitelists.json` are always `safe`, skipping rule evaluation entirely
- Three-tier verdict: `safe` / `suspect` / `threat`
- On `threat`, a warning toast appears in the bottom-right of the page even if the popup is never opened

## How it works

```
manifest.json
  └─ content_scripts (injected into every page, at document_idle)
      1. engine/parser.js     → parses condition strings into an AST
      2. engine/evaluator.js  → evaluates the AST against the current page context (text, domain)
      3. engine/ruleLoader.js → fetches every rule listed in rules/index.json and evaluates them
      4. content.js           → checks rules/whitelists.json first (match → immediate safe)
                                 otherwise combines the evaluation results into a state,
                                 responds to the popup + shows the toast
```

`popup.js` sends a `GPR_GET_STATUS` message to the content script in the active tab to fetch and display the scan result.

## Rule syntax

Each rule is one JSON file inside the `rules/` directory.

### Rule file structure

```json
{
  "name": "PayPal_Login_Clone",
  "author": "doyun",
  "description": "Detects phishing sites impersonating the PayPal login page",
  "conditions": {
    "eq": [
      "match text \"paypal\" AND (match text \"payment\" OR match text \"authentication\")",
      "match text \"your account has been limited\"",
      "match text \"verify your identity\""
    ],
    "except": [
      "match domain \"paypal.com\"",
      "match domain \"paypal.me\"",
      "match domain \"paypal-official-support.com\""
    ]
  },
  "detect": 2
}
```

| Field | Description |
|---|---|
| `name` | Rule name. Shown as the matched rule when detected |
| `author` | Author (display only, no effect on logic) |
| `description` | Rule description (display only, no effect on logic) |
| `conditions.eq` | Array of condition strings. Each true condition adds +1 to the score |
| `conditions.except` | Array of condition strings. If any is true, this rule is forced to safe (evaluation skipped) |
| `detect` | Detection threshold. How many `eq` conditions must be true to count as detected |

### Condition string syntax

Each condition is a single expression string following this grammar:

```
match <type> "<value>"
```

- `<type>` — `text` or `domain`
  - `match text "paypal"` — true if the page body text (`document.body.innerText`) contains `paypal` (case-insensitive, substring match)
  - `match domain "paypal.com"` — true if the current domain (`location.hostname`) **exactly equals** `paypal.com` (case-insensitive)
- `<value>` — a double-quoted string. Use `\"` to escape a literal quote inside it

Expressions can be combined with `AND` / `OR` / `()` (case-insensitive, e.g. `and` also works).

```
match text "paypal" AND (match text "payment" OR match text "authentication")
```

- Precedence: `AND` binds tighter than `OR`. `A OR B AND C` parses as `A OR (B AND C)`.
- Use parentheses to make precedence explicit.

### Verdict logic

The current domain is checked against the [whitelist](#whitelist) first. If it matches, rule evaluation is skipped entirely and the verdict is immediately `safe`.

Otherwise, for each rule:

1. If any `except` condition is true → the rule is forced to **safe** (evaluation skipped, no score computed)
2. Otherwise, each `eq` condition is evaluated and the count of true conditions becomes the `score`
3. `score >= detect` → **detected**

After evaluating every rule, the content script derives one overall state:

| Condition | Final state |
|---|---|
| At least one rule has `detected: true` (`score >= detect`) | `threat` |
| No rule was detected, but at least one has `score > 0` | `suspect` |
| Every rule has `score === 0`, or was skipped via `except` | `safe` |

On a `threat` verdict, a warning toast is shown in the bottom-right of the page even without opening the popup.

### Registering a rule

1. Add a new JSON file under `rules/` (e.g. `rules/my_rule.json`)
2. Add the filename to the `rules/index.json` array

```json
["test_paypal.json", "my_rule.json"]
```

## Whitelist

List domain strings in `rules/whitelists.json` to always mark those domains `safe`, skipping rule evaluation entirely. Use this to exempt legitimate sites that trigger false positives.

```json
["paypal.com", "example.com"]
```

- Matching follows the same semantics as `match domain`: **exact match**, case-insensitive.
- Subdomains are not automatically covered. To also exempt `www.paypal.com`, add it separately.
- Do not add it to `rules/index.json` — it's a global whitelist, not a rule, and is always loaded regardless of `index.json`.
- To exempt a domain from just one specific rule (rather than globally), add a domain condition to that rule's `conditions.except` instead.

## Testing

The rule engine can be tested standalone with Node.js.

```bash
node run_test.js <path to rule.json> <text> <domain>

# Example: classified as phishing
node run_test.js rules/test_paypal.json "paypal payment your account has been limited verify your identity" paypal-secure-login.net

# Example: safe because the domain matches an except condition
node run_test.js rules/test_paypal.json "paypal" paypal.com
```

## Installation (developer mode)

1. Go to `chrome://extensions`
2. Enable **Developer mode** in the top-right corner
3. Click **Load unpacked** → select this project folder
