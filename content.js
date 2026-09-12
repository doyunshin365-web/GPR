/**
 * GPR content.js
 * manifest.json에서 parser.js -> evaluator.js -> ruleLoader.js 다음에 로드됨.
 * 실제 웹페이지 컨텍스트 안에서 실행되며 document/location에 접근 가능.
 */

(function () {
  // 스캔 결과를 저장해뒀다가 popup.js가 물어보면 즉시 응답
  let lastResult = {
    state: "idle",
    ruleCount: 0,
    threatName: null,
  };

  function determineState(evalResults) {
    const detected = evalResults.filter((r) => r.result.detected);
    if (detected.length === 0) {
      return { state: "safe", threatName: null };
    }
    // 여러 룰이 걸렸으면 스코어 제일 높은 걸 대표로
    const top = detected.reduce((a, b) =>
      b.result.score > a.result.score ? b : a
    );
    // 임계값을 얼마나 넘었는지에 따라 suspect/threat 구분 (여유 있게 넘으면 threat)
    const overBy = top.result.score - top.result.threshold;
    const state = overBy >= 2 ? "threat" : "suspect";
    return { state, threatName: top.rule.name };
  }

  async function runScan() {
    try {
      const context = PhishRule.getCurrentPageContext();
      const rulesUrl = chrome.runtime.getURL("rules/");
      const evalResults = await PhishRule.evaluateAllRules(rulesUrl, context);

      const { state, threatName } = determineState(evalResults);

      lastResult = {
        state,
        ruleCount: evalResults.length,
        threatName,
      };
    } catch (err) {
      console.error("GPR: 스캔 중 오류", err);
      lastResult = { state: "idle", ruleCount: 0, threatName: null };
    }
  }

  // 팝업(popup.js)이 물어보면 저장해둔 결과 응답
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "GPR_GET_STATUS") {
      sendResponse(lastResult);
    }
    return true; // 비동기 응답 여지를 위해 true 반환
  });

  runScan();
})();