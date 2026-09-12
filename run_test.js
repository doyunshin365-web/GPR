/**
 * 사용법:
 *   node run_test.js <rule.json 경로> <test.html 경로> <domain>
 * 예:
 *   node run_test.js rules/test_paypal.json tests/test_paypal.html paypal-secure-login.net
 *   node run_test.js rules/test_paypal.json tests/test_paypal.html paypal.com
 */

const fs = require("fs");
const path = require("path");
const { JSDOM } = require("jsdom");
const { evaluateRule } = require("./engine/evaluator.js");

const [, , rulePath, htmlPath, domain] = process.argv;

if (!rulePath || !htmlPath || !domain) {
  console.error("사용법: node run_test.js <rule.json> <test.html> <domain>");
  process.exit(1);
}

const rule = JSON.parse(fs.readFileSync(path.resolve(rulePath), "utf-8"));
const html = fs.readFileSync(path.resolve(htmlPath), "utf-8");

const dom = new JSDOM(html);
const renderedText = dom.window.document.body.textContent || "";

const context = { text: renderedText, domain };

const result = evaluateRule(rule, context);

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
