/**
 * GPR popup.js
 *
 * 흐름:
 *   1. 현재 탭의 content script(evaluator.js가 돌고 있는)에 스캔 결과를 요청
 *   2. 응답으로 { state, ruleCount, threatName? } 받음
 *      state: "idle" | "safe" | "suspect" | "threat"
 *   3. 상태에 맞는 아이콘/문구로 UI 갱신 (아이콘은 디졸브 크로스페이드로 전환)
 *
 * content.js 쪽에서는 아래 형태로 응답해주면 됩니다:
 *   chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
 *     if (msg.type === "GPR_GET_STATUS") {
 *       sendResponse({ state: "threat", ruleCount: 12, threatName: "PayPal_Login_Clone" });
 *     }
 *   });
 */

const ICON_BASE = "./asset/gpr-icons/png/";
const VERSION = "1.0.0";

const STATE_CONFIG = {
  idle: {
    icon: "idle.png",
    title: "Scanning...",
    subtitle: "Analyzing this site for potential security threats.",
    className: "idle",
  },
  safe: {
    icon: "safe.png",
    title: "Site is Safe",
    subtitle: "No security threats were detected on this site.",
    className: "safe",
  },
  suspect: {
    icon: "suspect.png",
    title: "Suspicious Activity",
    subtitle: "Potential security risks were detected. Proceed with caution.",
    className: "suspect",
  },
  threat: {
    icon: "alert.png",
    title: "Threat Detected",
    subtitle: "This site may pose a security risk. Avoid entering sensitive information.",
    className: "threat",
  },
};

const iconEl = document.querySelector(".icon");
const statusEl = document.querySelector(".status");
const titleEl = statusEl.querySelector(".title");
const subtitleEl = statusEl.querySelector(".subtitle");
const ruleCntEl = document.querySelector("#rule_cnt");
const versionEl = document.querySelector("#v");

let currentState = null;

/**
 * 아이콘을 디졸브(크로스페이드)로 전환한다.
 * 같은 <img> 하나로 opacity 0 → src 교체 → opacity 1 순서로 처리.
 */
function crossfadeIcon(newSrc, duration = 220) {
  if (iconEl.getAttribute("src") === newSrc) return;

  iconEl.style.transition = `opacity ${duration}ms ease`;
  iconEl.style.opacity = "0";

  window.setTimeout(() => {
    iconEl.src = newSrc;
    // 다음 프레임에 opacity 복구해야 트랜지션이 제대로 먹힘
    requestAnimationFrame(() => {
      iconEl.style.opacity = "1";
    });
  }, duration);
}

/**
 * 상태(state)에 맞춰 팝업 UI 전체를 갱신
 */
function applyState(state) {
  const config = STATE_CONFIG[state];
  if (!config) {
    console.warn(`알 수 없는 상태: ${state}`);
    return;
  }
  if (state === currentState) return;
  currentState = state;

  crossfadeIcon(ICON_BASE + config.icon);

  // 텍스트도 아이콘 페이드와 타이밍 맞춰서 살짝 같이 전환
  statusEl.style.transition = "opacity 180ms ease";
  statusEl.style.opacity = "0";

  window.setTimeout(() => {
    titleEl.textContent = config.title;
    subtitleEl.textContent = config.subtitle;

    statusEl.classList.remove("safe", "suspect", "threat");
    if (config.className !== "idle") {
      statusEl.classList.add(config.className);
    }

    statusEl.style.opacity = "1";
  }, 180);
}

function updateOverview(ruleCount) {
  ruleCntEl.textContent = String(ruleCount ?? 0);
  versionEl.textContent = VERSION;
}

/**
 * 현재 활성 탭의 content script에 스캔 상태를 요청
 */
const POLL_INTERVAL_MS = 150;
const POLL_MAX_TRIES = 40; // 최대 ~6초까지 스캔 완료를 기다림

function requestScanStatus(triesLeft = POLL_MAX_TRIES) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab || !tab.id) return;

    chrome.tabs.sendMessage(tab.id, { type: "GPR_GET_STATUS" }, (response) => {
      if (chrome.runtime.lastError) {
        // content script가 아직 응답 안 하거나 로드 안 된 페이지(chrome:// 등)
        console.warn("GPR: 상태 조회 실패 —", chrome.runtime.lastError.message);
        applyState("idle");
        updateOverview(0);
        return;
      }
      if (!response) {
        applyState("idle");
        updateOverview(0);
        return;
      }
      // 아직 스캔 중이면 idle을 확정짓지 말고 잠깐 뒤에 다시 물어본다
      if (response.scanning && triesLeft > 0) {
        window.setTimeout(() => requestScanStatus(triesLeft - 1), POLL_INTERVAL_MS);
        return;
      }
      applyState(response.state || "idle");
      updateOverview(response.ruleCount);
    });
  });
}

// ---------- 초기화 ----------

document.addEventListener("DOMContentLoaded", () => {
  applyState("idle");
  updateOverview(0);
  requestScanStatus();
});