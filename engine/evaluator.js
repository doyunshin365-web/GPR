(function (global) {
  const { parseCondition } = global.PhishRule;

  function evaluateAst(node, context) {
    switch (node.type) {
      case "AND":
        return evaluateAst(node.left, context) && evaluateAst(node.right, context);
      case "OR":
        return evaluateAst(node.left, context) || evaluateAst(node.right, context);
      case "MATCH":
        if (node.matchType === "text") {
          return context.text.toLowerCase().includes(node.value.toLowerCase());
        }
        if (node.matchType === "domain") {
          return context.domain.toLowerCase() === node.value.toLowerCase();
        }
        throw new Error(`알 수 없는 matchType: ${node.matchType}`);
      default:
        throw new Error(`알 수 없는 AST 노드 타입: ${node.type}`);
    }
  }

  function evaluateConditionString(conditionStr, context) {
    const ast = parseCondition(conditionStr);
    return evaluateAst(ast, context);
  }

  /**
   * @param {object} rule - 룰 JSON 객체
   * @param {object} context - { text, domain }
   */
  function evaluateRule(rule, context) {
    const { eq = [], except = [] } = rule.conditions || {};

    for (const cond of except) {
      if (evaluateConditionString(cond, context)) {
        return {
          detected: false,
          safe: true,
          score: null,
          threshold: rule.detect,
          matchedExcept: cond,
          details: { eq: [] },
        };
      }
    }

    let score = 0;
    const eqDetails = eq.map((cond) => {
      const result = evaluateConditionString(cond, context);
      if (result) score += 1;
      return { cond, result };
    });

    const detected = score >= rule.detect;

    return {
      detected,
      safe: !detected,
      score,
      threshold: rule.detect,
      matchedExcept: null,
      details: { eq: eqDetails },
    };
  }

  /**
   * 현재 페이지에서 바로 context를 뽑아주는 헬퍼
   * (실제 익스텐션에서 이걸로 document/location 접근)
   */
  function getCurrentPageContext() {
    return {
      text: document.body.innerText || "",
      domain: location.hostname,
    };
  }

  global.PhishRule.evaluateAst = evaluateAst;
  global.PhishRule.evaluateConditionString = evaluateConditionString;
  global.PhishRule.evaluateRule = evaluateRule;
  global.PhishRule.getCurrentPageContext = getCurrentPageContext;
})(typeof window !== "undefined" ? window : globalThis);