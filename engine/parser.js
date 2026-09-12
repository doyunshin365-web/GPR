(function (global) {
  const TokenType = {
    MATCH: "MATCH",
    TYPE: "TYPE",
    STRING: "STRING",
    AND: "AND",
    OR: "OR",
    LPAREN: "LPAREN",
    RPAREN: "RPAREN",
    EOF: "EOF",
  };

  function tokenize(input) {
    const tokens = [];
    let i = 0;
    const isWhitespace = (ch) => /\s/.test(ch);
    const isWordChar = (ch) => /[A-Za-z_]/.test(ch);

    while (i < input.length) {
      const ch = input[i];

      if (isWhitespace(ch)) {
        i++;
        continue;
      }
      if (ch === "(") {
        tokens.push({ type: TokenType.LPAREN, value: "(" });
        i++;
        continue;
      }
      if (ch === ")") {
        tokens.push({ type: TokenType.RPAREN, value: ")" });
        i++;
        continue;
      }
      if (ch === '"') {
        let j = i + 1;
        let str = "";
        while (j < input.length && input[j] !== '"') {
          if (input[j] === "\\" && input[j + 1] === '"') {
            str += '"';
            j += 2;
          } else {
            str += input[j];
            j++;
          }
        }
        if (j >= input.length) {
          throw new SyntaxError(`문자열이 닫히지 않았습니다 (위치 ${i})`);
        }
        tokens.push({ type: TokenType.STRING, value: str });
        i = j + 1;
        continue;
      }
      if (isWordChar(ch)) {
        let j = i;
        while (j < input.length && isWordChar(input[j])) j++;
        const word = input.slice(i, j);
        const upper = word.toUpperCase();

        if (upper === "AND") {
          tokens.push({ type: TokenType.AND, value: word });
        } else if (upper === "OR") {
          tokens.push({ type: TokenType.OR, value: word });
        } else if (word.toLowerCase() === "match") {
          tokens.push({ type: TokenType.MATCH, value: word });
        } else if (word.toLowerCase() === "text" || word.toLowerCase() === "domain") {
          tokens.push({ type: TokenType.TYPE, value: word.toLowerCase() });
        } else {
          throw new SyntaxError(`알 수 없는 키워드: "${word}" (위치 ${i})`);
        }
        i = j;
        continue;
      }
      throw new SyntaxError(`알 수 없는 문자: "${ch}" (위치 ${i})`);
    }
    tokens.push({ type: TokenType.EOF, value: null });
    return tokens;
  }

  class Parser {
    constructor(tokens) {
      this.tokens = tokens;
      this.pos = 0;
    }
    peek() {
      return this.tokens[this.pos];
    }
    advance() {
      return this.tokens[this.pos++];
    }
    expect(type) {
      const token = this.peek();
      if (token.type !== type) {
        throw new SyntaxError(
          `예상한 토큰: ${type}, 실제: ${token.type} (${JSON.stringify(token.value)})`
        );
      }
      return this.advance();
    }
    parseExpression() {
      let node = this.parseAndExpr();
      while (this.peek().type === TokenType.OR) {
        this.advance();
        const right = this.parseAndExpr();
        node = { type: "OR", left: node, right };
      }
      return node;
    }
    parseAndExpr() {
      let node = this.parseTerm();
      while (this.peek().type === TokenType.AND) {
        this.advance();
        const right = this.parseTerm();
        node = { type: "AND", left: node, right };
      }
      return node;
    }
    parseTerm() {
      const token = this.peek();
      if (token.type === TokenType.LPAREN) {
        this.advance();
        const node = this.parseExpression();
        this.expect(TokenType.RPAREN);
        return node;
      }
      if (token.type === TokenType.MATCH) {
        return this.parseMatchExpr();
      }
      throw new SyntaxError(
        `예상치 못한 토큰: ${token.type} (${JSON.stringify(token.value)})`
      );
    }
    parseMatchExpr() {
      this.expect(TokenType.MATCH);
      const typeToken = this.expect(TokenType.TYPE);
      const strToken = this.expect(TokenType.STRING);
      return { type: "MATCH", matchType: typeToken.value, value: strToken.value };
    }
    parse() {
      const ast = this.parseExpression();
      this.expect(TokenType.EOF);
      return ast;
    }
  }

  function parseCondition(conditionStr) {
    const tokens = tokenize(conditionStr);
    const parser = new Parser(tokens);
    return parser.parse();
  }

  // 브라우저 전역에 네임스페이스로 노출
  global.PhishRule = global.PhishRule || {};
  global.PhishRule.parseCondition = parseCondition;
  global.PhishRule.tokenize = tokenize;
})(typeof window !== "undefined" ? window : globalThis);
// Node.js 지원
if (typeof module !== 'undefined' && module.exports) {
  module.exports = global.PhishRule;
}
