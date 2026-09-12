(function (global) {
  /**
   * @param {string} rulesBaseUrl - 예: "rules/" (익스텐션이면 chrome.runtime.getURL("rules/"))
   * @param {object} context - { text, domain }
   * @returns {Promise<Array<{rule: object, result: object}>>}
   */
  async function evaluateAllRules(rulesBaseUrl, context) {
    const indexRes = await fetch(rulesBaseUrl + "index.json");
    if (!indexRes.ok) {
      throw new Error(`index.json을 불러오지 못했습니다: ${indexRes.status}`);
    }
    const fileNames = await indexRes.json();

    const results = [];
    for (const fileName of fileNames) {
      const res = await fetch(rulesBaseUrl + fileName);
      if (!res.ok) {
        console.warn(`룰 파일 로드 실패: ${fileName} (${res.status})`);
        continue;
      }
      const rule = await res.json();
      const result = global.PhishRule.evaluateRule(rule, context);
      results.push({ rule, result });
    }
    return results;
  }

  global.PhishRule = global.PhishRule || {};
  global.PhishRule.evaluateAllRules = evaluateAllRules;
})(typeof window !== "undefined" ? window : globalThis);