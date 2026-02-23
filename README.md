# Mekarge Access Token Validaton Tool (CLI)

A standalone Python CLI tool that validates **Access Tokens** obtained from Mekarge A3.

The tool can validate **Access Tokens** signed by RS256 using discovery via `.well-known/openid-configuration`.

The tool makes standard claim validation (`iss`, `exp`) as well as some optional checks such as:
  * 'aud'
  * `scope`

## Requirements

* Python 3.x

## Installation

```bash
python -m venv .venv
```

Activate (macOS / Linux):

```bash
source .venv/bin/activate
```

Activate (Windows):

```bash
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

### Get help

```bash
python app/main.py -h
```

### Basic validation

```bash
python app/main.py \
  --issuer-path "$A3_ISSUER_PATH" \
  --token "$ACCESS_TOKEN"
```

### Validate with Resource URN (audience)

```bash
python app/main.py \
  --issuer-path "$A3_ISSUER_PATH" \
  --token "$ACCESS_TOKEN" \
  --aud 'urn:resource1'
```

### Validate with Scope

```bash
python app/main.py \
  --issuer-path "$A3_ISSUER_PATH" \
  --token "$ACCESS_TOKEN" \
  --scope 'read:items'
```

### Validate using token file

```bash
python app/main.py \
  --issuer-path "$A3_ISSUER_PATH" \
  --token-file token.txt
```

### Validate using `stdin`

```bash
echo "$ACCESS_TOKEN" | python app/main.py \
  --issuer-path "$A3_ISSUER_PATH"
```

## Exit codes

| Code | Meaning       |
| ---- | ------------- |
| 0    | Token valid   |
| 1    | Token invalid |

## License

MIT

