"""
search/boolean_eval.py — Boolean expression parser and evaluator for log search.

Supports: AND, OR, NOT, XOR with unlimited nested parentheses.

Operator precedence (high → low):
    NOT  >  AND  >  XOR  >  OR

Grammar (EBNF):
    expr     → or_expr
    or_expr  → xor_expr  ( "OR"  xor_expr  )*
    xor_expr → and_expr  ( "XOR" and_expr  )*
    and_expr → not_expr  ( "AND" not_expr  )*
    not_expr → "NOT" not_expr | primary          ← right-associative
    primary  → "(" expr ")" | IDENT

IDENT may contain alphanumerics plus: . - _ : / \\ (covers IPs, hashes, paths,
usernames).  Quoted strings (single or double quotes) are also valid IDENTs — the
quotes are stripped so multi-word phrases can be expressed as a single token:
    (A AND "error 404") OR NOT "connection refused"

Usage in log search:
    Each IDENT is a search keyword evaluated as:
        True  if the keyword appears (case-insensitive) in the raw log line
        False otherwise
    Build the per-line environment from all variables in the expression:

        env  = {kw: kw.lower() in line.lower() for kw in extract_variables(expr)}
        hit  = eval_expr(expr, env)

Public API:
    eval_expr(expr, variables)  → bool
    parse_expr(expr)            → AST node (opaque; pass to eval_node)
    eval_node(node, variables)  → bool
    extract_variables(expr)     → list[str]  (order of first appearance, no dups)
    is_boolean_query(expr)      → bool  (True if expr contains any operator token)
"""

from __future__ import annotations

from typing import Any, Dict, List, NamedTuple


# ---------------------------------------------------------------------------
# Token type constants
# ---------------------------------------------------------------------------

class TT:  # noqa: N801 (keep as-is for brevity)
    AND    = "AND"
    OR     = "OR"
    NOT    = "NOT"
    XOR    = "XOR"
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    IDENT  = "IDENT"
    EOF    = "EOF"


_KEYWORDS: frozenset[str] = frozenset({"AND", "OR", "NOT", "XOR"})

# Characters allowed inside an unquoted identifier token (beyond alphanumerics).
_IDENT_EXTRA = frozenset("._-:/\\@#%=+~!")


class Token(NamedTuple):
    type:  str
    value: str   # raw text from the source expression


# ---------------------------------------------------------------------------
# Lexer
# ---------------------------------------------------------------------------

def _tokenize(expr: str) -> List[Token]:
    """
    Tokenise *expr* into a flat list of ``Token`` objects.

    Rules
    -----
    - Whitespace is skipped.
    - ``(`` and ``)`` become LPAREN / RPAREN.
    - ``"…"`` and ``'…'`` become a single IDENT whose value is the
      (unquoted) content inside the delimiters.
    - Any other non-whitespace, non-paren run is read greedily; if its
      upper-cased form is a keyword (AND/OR/NOT/XOR) it becomes that
      keyword token, otherwise IDENT.

    Raises
    ------
    ValueError on unclosed quoted strings or unexpected characters.
    """
    tokens: List[Token] = []
    i = 0
    n = len(expr)

    while i < n:
        ch = expr[i]

        # ── whitespace ────────────────────────────────────────────────────
        if ch.isspace():
            i += 1
            continue

        # ── parentheses ───────────────────────────────────────────────────
        if ch == "(":
            tokens.append(Token(TT.LPAREN, "("))
            i += 1
            continue

        if ch == ")":
            tokens.append(Token(TT.RPAREN, ")"))
            i += 1
            continue

        # ── quoted string ─────────────────────────────────────────────────
        if ch in ('"', "'"):
            quote = ch
            j = i + 1
            while j < n and expr[j] != quote:
                j += 1
            if j >= n:
                raise ValueError(
                    f"Unclosed quoted string starting at position {i}: "
                    f"{expr[i:]!r}"
                )
            content = expr[i + 1 : j]
            tokens.append(Token(TT.IDENT, content))
            i = j + 1  # skip closing quote
            continue

        # ── identifier / keyword ──────────────────────────────────────────
        if ch.isalnum() or ch in _IDENT_EXTRA:
            j = i
            while j < n and (expr[j].isalnum() or expr[j] in _IDENT_EXTRA):
                j += 1
            word   = expr[i:j]
            upper  = word.upper()
            tok_t  = upper if upper in _KEYWORDS else TT.IDENT
            tokens.append(Token(tok_t, word))
            i = j
            continue

        raise ValueError(
            f"Unexpected character {ch!r} at position {i} in expression: "
            f"{expr!r}"
        )

    tokens.append(Token(TT.EOF, ""))
    return tokens


# ---------------------------------------------------------------------------
# Recursive-descent parser
# ---------------------------------------------------------------------------

class _Parser:
    """
    Recursive-descent parser that converts a token list into an AST.

    AST node forms
    --------------
    ("VAR",  name)          → leaf: evaluate variable *name* from env
    ("NOT",  child)         → unary NOT
    ("AND",  left, right)
    ("XOR",  left, right)
    ("OR",   left, right)
    """

    __slots__ = ("_tokens", "_pos")

    def __init__(self, tokens: List[Token]) -> None:
        self._tokens = tokens
        self._pos    = 0

    # ── token helpers ────────────────────────────────────────────────────────

    def _peek(self) -> Token:
        return self._tokens[self._pos]

    def _consume(self, expected_type: str | None = None) -> Token:
        tok = self._tokens[self._pos]
        if expected_type is not None and tok.type != expected_type:
            raise ValueError(
                f"Syntax error: expected {expected_type!r} "
                f"but found {tok.type!r} ({tok.value!r}) "
                f"at token position {self._pos}."
            )
        self._pos += 1
        return tok

    # ── grammar rules ────────────────────────────────────────────────────────

    def parse(self) -> Any:
        """Parse the full expression; verify no trailing tokens."""
        node = self._or_expr()
        tok  = self._peek()
        if tok.type != TT.EOF:
            raise ValueError(
                f"Syntax error: unexpected token {tok.value!r} "
                f"after end of expression."
            )
        return node

    def _or_expr(self) -> Any:
        """or_expr → xor_expr ( "OR" xor_expr )* """
        left = self._xor_expr()
        while self._peek().type == TT.OR:
            self._consume(TT.OR)
            right = self._xor_expr()
            left  = ("OR", left, right)
        return left

    def _xor_expr(self) -> Any:
        """xor_expr → and_expr ( "XOR" and_expr )* """
        left = self._and_expr()
        while self._peek().type == TT.XOR:
            self._consume(TT.XOR)
            right = self._and_expr()
            left  = ("XOR", left, right)
        return left

    def _and_expr(self) -> Any:
        """and_expr → not_expr ( "AND" not_expr )* """
        left = self._not_expr()
        while self._peek().type == TT.AND:
            self._consume(TT.AND)
            right = self._not_expr()
            left  = ("AND", left, right)
        return left

    def _not_expr(self) -> Any:
        """not_expr → "NOT" not_expr | primary   (right-associative)"""
        if self._peek().type == TT.NOT:
            self._consume(TT.NOT)
            return ("NOT", self._not_expr())   # right-recursive for NOT NOT NOT…
        return self._primary()

    def _primary(self) -> Any:
        """primary → "(" expr ")" | IDENT"""
        tok = self._peek()

        if tok.type == TT.LPAREN:
            self._consume(TT.LPAREN)
            node = self._or_expr()          # recurse from the top
            if self._peek().type != TT.RPAREN:
                raise ValueError(
                    f"Syntax error: expected ')' to close '(' "
                    f"but found {self._peek().value!r}."
                )
            self._consume(TT.RPAREN)
            return node

        if tok.type == TT.IDENT:
            self._consume(TT.IDENT)
            return ("VAR", tok.value)

        # Anything else at this point is a syntax error
        raise ValueError(
            f"Syntax error: expected a variable name or '(' "
            f"but found {tok.type!r} ({tok.value!r})."
        )


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

def eval_node(node: Any, variables: Dict[str, bool]) -> bool:
    """
    Recursively evaluate an AST *node* against the *variables* mapping.

    Parameters
    ----------
    node      : An AST node returned by ``parse_expr``.
    variables : A ``{name: bool}`` mapping for every variable in the tree.
                Variable look-up is **case-insensitive** — the key is
                normalised to lower-case before look-up, so the dict may
                store keys in any case.

    Returns
    -------
    bool result of the sub-expression rooted at *node*.

    Raises
    ------
    ValueError if a variable name is not present in *variables*.
    """
    op = node[0]

    if op == "VAR":
        name     = node[1]
        name_lc  = name.lower()
        # Case-insensitive look-up: try exact first, then lower-cased
        if name in variables:
            return bool(variables[name])
        if name_lc in variables:
            return bool(variables[name_lc])
        # Build a lower-cased shadow for the final attempt
        lc_map = {k.lower(): v for k, v in variables.items()}
        if name_lc in lc_map:
            return bool(lc_map[name_lc])
        raise ValueError(
            f"Undefined variable {name!r}. "
            f"Available: {sorted(variables.keys())}"
        )

    if op == "NOT":
        return not eval_node(node[1], variables)

    # Binary operators
    left  = eval_node(node[1], variables)
    right = eval_node(node[2], variables)

    if op == "AND":
        return left and right
    if op == "OR":
        return left or right
    if op == "XOR":
        return left ^ right         # True iff exactly one operand is True

    raise AssertionError(f"Unknown AST operator {op!r}")  # should never happen


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_expr(expr: str) -> Any:
    """
    Parse *expr* into an AST.

    Returns an opaque tree suitable for ``eval_node``.
    Raises ``ValueError`` on any syntax error.
    """
    tokens = _tokenize(expr)
    return _Parser(tokens).parse()


def eval_expr(expr: str, variables: Dict[str, bool]) -> bool:
    """
    Parse and evaluate a boolean expression string in one step.

    Parameters
    ----------
    expr      : Expression string, e.g. ``"(A AND B) OR (NOT C XOR D)"``.
    variables : ``{name: bool}`` mapping for every variable referenced in
                *expr*.  Variable names are matched case-insensitively.

    Returns
    -------
    bool result.

    Raises
    ------
    ValueError on syntax errors or undefined variables.

    Examples
    --------
    >>> eval_expr("(A AND B) OR (NOT C XOR D)",
    ...           {"A": True, "B": False, "C": True, "D": True})
    False

    >>> eval_expr("error AND NOT warning", {"error": True, "warning": False})
    True

    >>> eval_expr("(ssh OR rdp) AND NOT internal",
    ...           {"ssh": True, "rdp": False, "internal": False})
    True
    """
    ast = parse_expr(expr)
    return eval_node(ast, variables)


def extract_variables(expr: str) -> List[str]:
    """
    Return all IDENT token values referenced in *expr*, in first-appearance
    order, without duplicates.

    Useful for building the per-line variable environment:

        keywords = extract_variables(expr)
        env = {kw: kw.lower() in line.lower() for kw in keywords}
        hit = eval_expr(expr, env)

    Raises ``ValueError`` on tokenisation errors.
    """
    tokens  = _tokenize(expr)
    seen:   list[str] = []
    unique: set[str]  = set()
    for tok in tokens:
        if tok.type == TT.IDENT and tok.value not in unique:
            seen.append(tok.value)
            unique.add(tok.value)
    return seen


def is_boolean_query(expr: str) -> bool:
    """
    Return ``True`` if *expr* contains at least one boolean operator token
    (AND / OR / NOT / XOR).

    Used to decide whether to engage the boolean engine or fall back to plain
    substring matching.  Returns ``False`` on tokenisation errors so the caller
    can gracefully degrade to simple search.
    """
    try:
        tokens = _tokenize(expr)
        return any(t.type in (TT.AND, TT.OR, TT.NOT, TT.XOR) for t in tokens)
    except ValueError:
        return False


def line_matches(expr: str, line: str) -> tuple[bool, list[str]]:
    """
    Evaluate *expr* against a single raw log *line*.

    Each variable in the expression is tested as a case-insensitive substring
    of *line*.  Returns ``(matched: bool, hit_keywords: list[str])`` where
    *hit_keywords* is the subset of variables that were found in the line
    (useful for highlighting).

    Raises ``ValueError`` on parse errors (propagated from ``parse_expr``).
    """
    keywords = extract_variables(expr)
    line_lc  = line.lower()
    env      = {kw: kw.lower() in line_lc for kw in keywords}
    matched  = eval_node(parse_expr(expr), env)
    hit_kws  = [kw for kw, present in env.items() if present]
    return matched, hit_kws
