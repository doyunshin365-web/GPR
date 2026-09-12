/**
 * 사용법:
 *   node run_test.js <rule.json 경로> <text> <domain>
 * 예:
 *   node run_test.js rules/test_paypal.json "paypal payment authentication your account has been limited verify your identity" paypal-secure-login.net
 *   node run_test.js rules/test_paypal.json "paypal" paypal.com
 */

const fs = require("fs");
const path = require("path");
// 엔진 로드 (parser -> evaluator -> ruleLoader 순서)
require("./engine/parser.js");
require("./engine/evaluator.js");
const PhishRule = require("./engine/ruleLoader.js");

const [, , rulePath, text, domain] = process.argv;

if (!rulePath || !text || !domain) {
  console.error("사용법: node run_test.js <rule.json> <text> <domain>");
  process.exit(1);
}

const rule = JSON.parse(fs.readFileSync(path.resolve(rulePath), "utf-8"));
const context = { text, domain };

const result = PhishRule.evaluateRule(rule, context);

console.log(`룰: ${rule.name}`);
console.log(`도메인: ${domain}`);
console.log("----------------------------------------");
if (result.matchedExcept) {
  console.log(`[EXCEPT 매치] "${result.matchedExcept}" → 검사 스킵, 안전 처리`);
} else {
  console.log("eq 조건:");
  result.details.eq.forEach(({ cond, result: r }) =>
    console.log(`  [${r ? "+1" : " 0"}] ${cond}`)
  );
  console.log("----------------------------------------");
  console.log(`스코어: ${result.score} / 임계값: ${result.threshold}`);
}
console.log(`결과: ${result.detected ? "🚨 피싱 탐지" : "✅ 안전"}`);
