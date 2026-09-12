/**
 * GPR content.js
 * manifest.json에서 parser.js -> evaluator.js -> ruleLoader.js 다음에 로드됨.
 * 실제 웹페이지 컨텍스트 안에서 실행되며 document/location에 접근 가능.
 */

(function () {
  // 스캔 결과를 저장해뒀다가 popup.js가 물어보면 즉시 응답
  let scanning = true; // runScan()이 끝나기 전이면 true
  let lastResult = {
    state: "idle",
    ruleCount: 0,
    threatName: null,
  };

  // 스코어 제일 높은 룰을 대표로 골라줌
  function topByScore(list) {
    return list.reduce((a, b) => (b.result.score > a.result.score ? b : a));
  }

  /**
   * except 매치   → 해당 룰은 검사 스킵 (score가 null이라 자연히 제외됨)
   * score >= detect → threat
   * 0 < score < detect → suspect
   * score 가 전부 0  → safe
   */
  function determineState(evalResults) {
    const detected = evalResults.filter((r) => r.result.detected);
    if (detected.length > 0) {
      const top = topByScore(detected);
      return { state: "threat", threatName: top.rule.name };
    }

    // detect에는 못 미쳐도 조건이 하나라도 맞았으면 suspect
    const partial = evalResults.filter((r) => r.result.score > 0);
    if (partial.length > 0) {
      const top = topByScore(partial);
      return { state: "suspect", threatName: top.rule.name };
    }

    return { state: "safe", threatName: null };
  }

  // ---------- 화이트리스트 ----------

  /**
   * rules/whitelists.json — 도메인 문자열 배열.
   * 여기 있는 도메인이면 룰 평가 없이 바로 safe로 확정한다.
   * (match domain 조건과 동일하게 완전 일치, 대소문자 무시. 서브도메인은 별도로 등록해야 함)
   */
  async function loadWhitelist(rulesUrl) {
    try {
      const res = await fetch(rulesUrl + "whitelists.json");
      if (!res.ok) return [];
      const list = await res.json();
      if (!Array.isArray(list)) return [];
      return list.map((d) => String(d).toLowerCase());
    } catch (err) {
      console.warn("GPR: whitelists.json 로드 실패", err);
      return [];
    }
  }

  function isWhitelisted(domain, whitelist) {
    return whitelist.includes(String(domain).toLowerCase());
  }

  // ---------- 위협 감지 시 페이지 우하단에 경고 토스트 ----------

  const TOAST_ID = "__gpr_threat_toast__";

  function showThreatToast(threatName) {
    if (document.getElementById(TOAST_ID)) return; // 이미 띄워있으면 스킵

    const host = document.createElement("div");
    host.id = TOAST_ID;
    // 페이지 CSS의 영향을 안 받도록 host를 초기화하고 위치만 지정
    host.style.cssText =
      "all: initial; position: fixed; right: 20px; bottom: 20px; z-index: 2147483647;";

    // closed shadow root — 피싱 페이지 스크립트가 내부를 건드리지 못하게
    const shadow = host.attachShadow({ mode: "closed" });
    shadow.innerHTML = `
      <style>
        .toast {
          display: flex;
          align-items: flex-start;
          gap: 12px;
          box-sizing: border-box;
          width: 320px;
          padding: 14px 16px;
          border-radius: 12px;
          border: 1px solid #3a2020;
          background: #1b1b1f;
          box-shadow: 0 8px 28px rgba(0, 0, 0, 0.45);
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
          opacity: 0;
          transform: translateY(12px);
          transition: opacity 220ms ease, transform 220ms ease;
        }
        .toast.show { opacity: 1; transform: translateY(0); }
        .icon { width: 36px; height: 36px; flex: 0 0 36px; }
        .body { flex: 1 1 auto; min-width: 0; }
        .title {
          margin: 0 0 4px;
          font-size: 14px;
          font-weight: 700;
          color: #ff5c5c;
        }
        .desc {
          margin: 0;
          font-size: 12px;
          line-height: 1.5;
          color: #c9c9d1;
        }
        .rule {
          display: block;
          margin-top: 6px;
          font-size: 11px;
          color: #8d8d99;
          word-break: break-all;
        }
        .close {
          flex: 0 0 auto;
          margin: -4px -6px 0 0;
          padding: 4px 6px;
          border: 0;
          border-radius: 6px;
          background: transparent;
          color: #8d8d99;
          font-size: 16px;
          line-height: 1;
          cursor: pointer;
        }
        .close:hover { background: #2a2a30; color: #f2f2f5; }
      </style>
      <div class="toast" role="alert">
        <img class="icon" alt="">
        <div class="body">
          <p class="title">Threat Detected</p>
          <p class="desc">This site may pose a security risk. Avoid entering sensitive information.</p>
          <span class="rule"></span>
        </div>
        <button class="close" aria-label="Close">&times;</button>
      </div>
    `;

    shadow.querySelector(".icon").src = chrome.runtime.getURL(
      "asset/gpr-icons/png/alert.png"
    );
    // 룰 이름은 textContent로만 — 룰 제작자가 넣은 문자열이 HTML로 해석되면 안 됨
    if (threatName) {
      shadow.querySelector(".rule").textContent = `Matched rule: ${threatName}`;
    }

    const toast = shadow.querySelector(".toast");
    shadow.querySelector(".close").addEventListener("click", () => host.remove());

    (document.body || document.documentElement).appendChild(host);
    // 다음 프레임에 클래스를 붙여야 슬라이드인 트랜지션이 먹음
    requestAnimationFrame(() => toast.classList.add("show"));
  }

  async function runScan() {
    scanning = true;
    try {
      const context = PhishRule.getCurrentPageContext();
      const rulesUrl = chrome.runtime.getURL("rules/");

      const whitelist = await loadWhitelist(rulesUrl);
      if (isWhitelisted(context.domain, whitelist)) {
        lastResult = { state: "safe", ruleCount: 0, threatName: null };
        console.log("[GPR] 화이트리스트 도메인 - 검사 스킵", context.domain);
        return;
      }

      const evalResults = await PhishRule.evaluateAllRules(rulesUrl, context);

      const { state, threatName } = determineState(evalResults);

      lastResult = {
        state,
        ruleCount: evalResults.length,
        threatName,
      };
      console.log("[GPR] 스캔 완료", lastResult);

      // 팝업을 안 열어도 보이도록 페이지 위에 직접 경고
      if (state === "threat") {
        showThreatToast(threatName);
      }
    } catch (err) {
      console.error("GPR: 스캔 중 오류", err);
      lastResult = { state: "idle", ruleCount: 0, threatName: null };
    } finally {
      scanning = false;
    }
  }

  // 팝업(popup.js)이 물어보면 저장해둔 결과 응답
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "GPR_GET_STATUS") {
      sendResponse({ ...lastResult, scanning });
    }
    return true; // 비동기 응답 여지를 위해 true 반환
  });

  runScan();
})();