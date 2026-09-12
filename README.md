# GPR (Generic Phishing Rules)

커스텀 YARA 스타일 규칙으로 브라우저에서 실시간으로 피싱 페이지를 탐지하는 Chrome 확장 프로그램입니다.

## 특징

- 페이지 텍스트/도메인을 기준으로 한 룰 기반 탐지 (YARA와 유사한 문법)
- 룰은 JSON 파일로 정의 — 코드 수정 없이 룰 추가/수정 가능
- `safe` / `suspect` / `threat` 3단계 판정
- `threat` 감지 시 팝업을 열지 않아도 페이지 우하단에 경고 토스트 표시

## 동작 원리

```
manifest.json
  └─ content_scripts (모든 페이지에 주입, document_idle 시점)
      1. engine/parser.js     → 조건 문자열을 파싱해 AST 생성
      2. engine/evaluator.js  → AST를 현재 페이지 컨텍스트(text, domain)로 평가
      3. engine/ruleLoader.js → rules/index.json에 등록된 룰들을 fetch, 전부 평가
      4. content.js           → 평가 결과를 종합해 상태(state) 결정, popup에 응답 + 토스트 표시
```

`popup.js`는 활성 탭의 content script에 `GPR_GET_STATUS` 메시지를 보내 스캔 결과를 받아 표시합니다.

## 룰 문법

룰은 `rules/` 디렉토리 안의 JSON 파일 하나당 하나씩 정의합니다.

### 룰 파일 구조

```json
{
  "name": "PayPal_Login_Clone",
  "author": "doyun",
  "description": "PayPal 로그인 페이지를 위장한 피싱 사이트 탐지",
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

| 필드 | 설명 |
|---|---|
| `name` | 룰 이름. 탐지 시 룰 이름으로 노출됨 |
| `author` | 작성자 (표시용, 로직에 영향 없음) |
| `description` | 룰 설명 (표시용, 로직에 영향 없음) |
| `conditions.eq` | 조건 문자열 배열. 각 조건이 참이면 +1점 |
| `conditions.except` | 조건 문자열 배열. 하나라도 참이면 이 룰은 무조건 안전 처리 (검사 스킵) |
| `detect` | 탐지 임계값. `eq` 조건 중 몇 개 이상 만족해야 탐지로 볼지 |

### 조건 문자열 문법

각 조건은 아래 문법을 따르는 하나의 표현식(문자열)입니다.

```
match <type> "<value>"
```

- `<type>` — `text` 또는 `domain`
  - `match text "paypal"` — 페이지 본문 텍스트(`document.body.innerText`)에 `paypal`이 포함되어 있으면 참 (대소문자 무시, 부분 일치)
  - `match domain "paypal.com"` — 현재 접속 도메인(`location.hostname`)이 `paypal.com`과 **완전히 일치**하면 참 (대소문자 무시)
- `<value>` — 큰따옴표로 감싼 문자열. `\"` 로 내부에 큰따옴표 이스케이프 가능

표현식은 `AND` / `OR` / `()` 로 조합할 수 있습니다 (대소문자 무관, 예: `and`도 허용).

```
match text "paypal" AND (match text "payment" OR match text "authentication")
```

- 우선순위: `AND`가 `OR`보다 높습니다. `A OR B AND C`는 `A OR (B AND C)`로 해석됩니다.
- 괄호로 우선순위를 명시적으로 지정할 수 있습니다.

### 판정 로직

각 룰에 대해:

1. `except` 조건 중 하나라도 참이면 → 이 룰은 **안전** 처리 (검사 스킵, score 계산 안 함)
2. 아니면 `eq` 조건들을 각각 평가해서 참인 개수를 `score`로 계산
3. `score >= detect` → **탐지(detected)**

여러 룰을 모두 평가한 뒤, content script가 종합 상태를 결정합니다:

| 조건 | 최종 상태 |
|---|---|
| 하나 이상의 룰이 `detected: true` (`score >= detect`) | `threat` |
| 어떤 룰도 탐지되지 않았지만, `score > 0`인 룰이 하나라도 있음 | `suspect` |
| 모든 룰이 `score === 0`이거나 `except`로 스킵됨 | `safe` |

`threat` 판정을 받으면 팝업을 열지 않아도 페이지 우하단에 경고 토스트가 표시됩니다.

### 룰 등록하기

1. `rules/` 디렉토리에 새 JSON 파일 작성 (예: `rules/my_rule.json`)
2. `rules/index.json` 배열에 파일명 추가

```json
["test_paypal.json", "my_rule.json"]
```

## 테스트

Node.js로 룰 로직만 단독 테스트할 수 있습니다.

```bash
node run_test.js <rule.json 경로> <text> <domain>

# 예: 피싱 페이지로 판정되는 경우
node run_test.js rules/test_paypal.json "paypal payment your account has been limited verify your identity" paypal-secure-login.net

# 예: except 도메인이라 안전 처리되는 경우
node run_test.js rules/test_paypal.json "paypal" paypal.com
```

## 설치 (개발자 모드)

1. `chrome://extensions` 접속
2. 우측 상단 **개발자 모드** 활성화
3. **압축해제된 확장 프로그램을 로드합니다** 클릭 → 이 프로젝트 폴더 선택
