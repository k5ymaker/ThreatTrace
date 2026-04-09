"""
tests/test_boolean_eval.py — Tests for search.boolean_eval

Run with:
    pytest tests/test_boolean_eval.py -v

Covers
------
- Individual operators: AND, OR, NOT, XOR
- Operator precedence (NOT > AND > XOR > OR)
- Nested / deeply nested parentheses
- Quoted-string identifiers
- extract_variables (order + deduplication)
- is_boolean_query detection
- line_matches helper (end-to-end log line evaluation)
- Error paths: syntax errors, undefined variables, unclosed parens/quotes
- Edge cases: double-NOT, all-False env, single-variable expr
- The canonical example from the spec
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from search.boolean_eval import (
    TT,
    _tokenize,
    eval_expr,
    eval_node,
    extract_variables,
    is_boolean_query,
    line_matches,
    parse_expr,
)


# ===========================================================================
# Helpers
# ===========================================================================

def ev(expr: str, **kwargs: bool) -> bool:
    """Shorthand: eval_expr(expr, {name: value, …})."""
    return eval_expr(expr, kwargs)


# ===========================================================================
# 1. Tokeniser
# ===========================================================================

class TestTokenizer:

    def test_keywords_are_recognised(self):
        tokens = _tokenize("A AND B OR C XOR D NOT E")
        types  = [t.type for t in tokens]
        assert types == [
            TT.IDENT, TT.AND, TT.IDENT,
            TT.OR,
            TT.IDENT, TT.XOR, TT.IDENT,
            TT.NOT,   TT.IDENT,
            TT.EOF,
        ]

    def test_keywords_are_case_insensitive_in_tokeniser(self):
        tokens = _tokenize("a and b or c xor d not e")
        types  = [t.type for t in tokens if t.type != TT.EOF]
        assert TT.AND in types
        assert TT.OR  in types
        assert TT.XOR in types
        assert TT.NOT in types

    def test_parentheses_tokenised(self):
        tokens = _tokenize("(A)")
        assert tokens[0].type == TT.LPAREN
        assert tokens[1].type == TT.IDENT
        assert tokens[2].type == TT.RPAREN

    def test_ident_with_dots_and_dashes(self):
        """IP addresses, domain names, hashes must be a single IDENT."""
        tokens = _tokenize("192.168.1.1 AND server-01.example.com")
        idents = [t for t in tokens if t.type == TT.IDENT]
        assert idents[0].value == "192.168.1.1"
        assert idents[1].value == "server-01.example.com"

    def test_double_quoted_ident(self):
        tokens = _tokenize('"error 404"')
        assert tokens[0].type  == TT.IDENT
        assert tokens[0].value == "error 404"

    def test_single_quoted_ident(self):
        tokens = _tokenize("'connection refused'")
        assert tokens[0].type  == TT.IDENT
        assert tokens[0].value == "connection refused"

    def test_unclosed_quote_raises(self):
        with pytest.raises(ValueError, match="Unclosed quoted string"):
            _tokenize('"no closing quote')

    def test_unexpected_char_raises(self):
        with pytest.raises(ValueError, match="Unexpected character"):
            _tokenize("A AND B $ C")

    def test_eof_always_appended(self):
        tokens = _tokenize("A")
        assert tokens[-1].type == TT.EOF

    def test_empty_expression_gives_only_eof(self):
        tokens = _tokenize("   ")
        assert len(tokens) == 1
        assert tokens[0].type == TT.EOF


# ===========================================================================
# 2. Individual operators
# ===========================================================================

class TestAndOperator:

    def test_true_and_true(self):
        assert ev("A AND B", A=True, B=True) is True

    def test_true_and_false(self):
        assert ev("A AND B", A=True, B=False) is False

    def test_false_and_true(self):
        assert ev("A AND B", A=False, B=True) is False

    def test_false_and_false(self):
        assert ev("A AND B", A=False, B=False) is False

    def test_three_way_and_all_true(self):
        assert ev("A AND B AND C", A=True, B=True, C=True) is True

    def test_three_way_and_one_false(self):
        assert ev("A AND B AND C", A=True, B=False, C=True) is False


class TestOrOperator:

    def test_true_or_true(self):
        assert ev("A OR B", A=True, B=True) is True

    def test_true_or_false(self):
        assert ev("A OR B", A=True, B=False) is True

    def test_false_or_true(self):
        assert ev("A OR B", A=False, B=True) is True

    def test_false_or_false(self):
        assert ev("A OR B", A=False, B=False) is False

    def test_three_way_or_all_false(self):
        assert ev("A OR B OR C", A=False, B=False, C=False) is False

    def test_three_way_or_one_true(self):
        assert ev("A OR B OR C", A=False, B=True, C=False) is True


class TestNotOperator:

    def test_not_true_is_false(self):
        assert ev("NOT A", A=True) is False

    def test_not_false_is_true(self):
        assert ev("NOT A", A=False) is True

    def test_double_not_restores_value_true(self):
        assert ev("NOT NOT A", A=True) is True

    def test_double_not_restores_value_false(self):
        assert ev("NOT NOT A", A=False) is False

    def test_triple_not(self):
        assert ev("NOT NOT NOT A", A=True) is False

    def test_not_on_grouped_expr(self):
        # NOT (A AND B) when A=True, B=True → NOT True → False
        assert ev("NOT (A AND B)", A=True, B=True) is False
        # NOT (A AND B) when A=True, B=False → NOT False → True
        assert ev("NOT (A AND B)", A=True, B=False) is True


class TestXorOperator:

    def test_xor_true_true_is_false(self):
        assert ev("A XOR B", A=True, B=True) is False

    def test_xor_true_false_is_true(self):
        assert ev("A XOR B", A=True, B=False) is True

    def test_xor_false_true_is_true(self):
        assert ev("A XOR B", A=False, B=True) is True

    def test_xor_false_false_is_false(self):
        assert ev("A XOR B", A=False, B=False) is False

    def test_xor_three_way_left_associative(self):
        # (True XOR True) XOR True = False XOR True = True
        assert ev("A XOR B XOR C", A=True, B=True, C=True) is True

    def test_xor_all_false(self):
        assert ev("A XOR B XOR C", A=False, B=False, C=False) is False


# ===========================================================================
# 3. Operator precedence  (NOT > AND > XOR > OR)
# ===========================================================================

class TestPrecedence:

    def test_not_binds_tighter_than_and(self):
        # NOT A AND B  →  (NOT A) AND B
        assert ev("NOT A AND B", A=False, B=True) is True   # (T) AND T  = T
        assert ev("NOT A AND B", A=True,  B=True) is False  # (F) AND T  = F

    def test_and_binds_tighter_than_or(self):
        # A OR B AND C  →  A OR (B AND C)
        assert ev("A OR B AND C", A=False, B=True, C=True)  is True
        assert ev("A OR B AND C", A=False, B=True, C=False) is False
        assert ev("A OR B AND C", A=True,  B=False, C=False) is True

    def test_and_binds_tighter_than_xor(self):
        # A XOR B AND C  →  A XOR (B AND C)
        assert ev("A XOR B AND C", A=True,  B=True,  C=True)  is False  # T XOR T = F
        assert ev("A XOR B AND C", A=True,  B=True,  C=False) is True   # T XOR F = T
        assert ev("A XOR B AND C", A=False, B=False, C=True)  is False  # F XOR F = F

    def test_xor_binds_tighter_than_or(self):
        # A OR B XOR C  →  A OR (B XOR C)
        assert ev("A OR B XOR C", A=False, B=True, C=False) is True   # F OR T = T
        assert ev("A OR B XOR C", A=False, B=True, C=True)  is False  # F OR F = F
        assert ev("A OR B XOR C", A=True,  B=True, C=True)  is True   # T OR F = T

    def test_not_and_xor_or_combined(self):
        # NOT A AND B XOR C OR D  →  ((NOT A) AND B) XOR C  OR  D
        # With A=T, B=T, C=T, D=F:
        #   NOT A = F;  F AND T = F;  F XOR T = T;  T OR F = T
        assert ev("NOT A AND B XOR C OR D",
                  A=True, B=True, C=True, D=False) is True
        # With A=F, B=T, C=T, D=F:
        #   NOT A = T;  T AND T = T;  T XOR T = F;  F OR F = F
        assert ev("NOT A AND B XOR C OR D",
                  A=False, B=True, C=True, D=False) is False


# ===========================================================================
# 4. Parentheses / grouping
# ===========================================================================

class TestParentheses:

    def test_simple_grouping_changes_semantics(self):
        # Without parens: A OR B AND C  →  A OR (B AND C)
        # With parens:    (A OR B) AND C
        assert ev("(A OR B) AND C", A=False, B=True, C=True)  is True
        assert ev("(A OR B) AND C", A=False, B=False, C=True) is False
        # plain  A OR (B AND C) with same values:
        assert ev("A OR B AND C",   A=False, B=True, C=True)  is True
        assert ev("A OR B AND C",   A=False, B=False, C=True) is False

    def test_double_nested_parens(self):
        assert ev("((A AND B))", A=True, B=True)  is True
        assert ev("((A AND B))", A=True, B=False) is False

    def test_deeply_nested_parens(self):
        # ((((A OR B)))) still works
        assert ev("((((A OR B))))", A=False, B=True) is True

    def test_paren_overrides_and_before_or(self):
        # (A OR B) AND C  vs  A OR B AND C
        # Both evaluate to the same with A=T,B=F,C=T, but differ with A=T,B=F,C=F
        assert ev("(A OR B) AND C", A=True, B=False, C=False) is False
        assert ev("A OR B AND C",   A=True, B=False, C=False) is True   # A short-circuits

    def test_complex_nested_group(self):
        # (A AND (B OR C)) XOR D
        assert ev("(A AND (B OR C)) XOR D", A=True,  B=False, C=True,  D=False) is True
        assert ev("(A AND (B OR C)) XOR D", A=True,  B=False, C=True,  D=True)  is False
        assert ev("(A AND (B OR C)) XOR D", A=False, B=True,  C=True,  D=True)  is True


# ===========================================================================
# 5. The canonical spec example
# ===========================================================================

class TestSpecExample:

    def test_spec_example_correct_evaluation(self):
        """
        Task expression: "(A AND B) OR (NOT C XOR D)"
        vars: A=True, B=False, C=True, D=True

        Step-by-step with precedence NOT > AND > XOR > OR:
          Left  : (A AND B)       = True AND False         = False
          Right : (NOT C XOR D)   NOT binds first:
                    NOT C         = NOT True               = False
                    False XOR D   = False XOR True         = True
          Result: False OR True                            = True

        Note: the task spec lists "result → False", which is inconsistent
        with the stated precedence rules (NOT > AND > XOR > OR).  Our engine
        strictly follows the declared precedence and therefore returns True.
        """
        result = eval_expr(
            "(A AND B) OR (NOT C XOR D)",
            {"A": True, "B": False, "C": True, "D": True},
        )
        assert result is True   # correct result per stated precedence

    def test_spec_example_step_by_step(self):
        """Verify each sub-expression in isolation."""
        # Left branch
        assert ev("A AND B",     A=True,  B=False) is False    # False
        # Right branch — NOT binds tighter than XOR
        assert ev("NOT C",       C=True)           is False    # NOT True = False
        assert ev("NOT C XOR D", C=True,  D=True)  is True     # False XOR True = T
        # Whole expression
        assert ev("(A AND B) OR (NOT C XOR D)",
                  A=True, B=False, C=True, D=True) is True

    def test_spec_example_when_right_side_also_false(self):
        """When D=False the right group also evaluates to False → whole expr False."""
        # NOT C XOR D where C=True, D=False: False XOR False = False
        assert ev("(A AND B) OR (NOT C XOR D)",
                  A=True, B=False, C=True, D=False) is False

    def test_spec_vars_all_false_result(self):
        """All variables False — verify the correct computed result."""
        # (A AND B)   = False AND False = False
        # (NOT C XOR D) = NOT False XOR False = True XOR False = True
        # False OR True = True
        assert ev("(A AND B) OR (NOT C XOR D)",
                  A=False, B=False, C=False, D=False) is True

    def test_spec_vars_left_true_short_circuits_or(self):
        """When A AND B is True the whole OR is True regardless of right side."""
        assert ev("(A AND B) OR (NOT C XOR D)",
                  A=True, B=True, C=True, D=True) is True


# ===========================================================================
# 6. Mixed real-world log-search expressions
# ===========================================================================

class TestLogSearchExpressions:

    def test_error_and_not_warning(self):
        assert ev("error AND NOT warning", error=True, warning=False) is True
        assert ev("error AND NOT warning", error=True, warning=True)  is False
        assert ev("error AND NOT warning", error=False, warning=False) is False

    def test_ip_or_hostname(self):
        assert ev("ip OR hostname", ip=True, hostname=False) is True
        assert ev("ip OR hostname", ip=False, hostname=False) is False

    def test_ssh_rdp_and_not_internal(self):
        assert ev("(ssh OR rdp) AND NOT internal",
                  ssh=True, rdp=False, internal=False) is True
        assert ev("(ssh OR rdp) AND NOT internal",
                  ssh=True, rdp=False, internal=True)  is False
        assert ev("(ssh OR rdp) AND NOT internal",
                  ssh=False, rdp=False, internal=False) is False

    def test_brute_force_detection_pattern(self):
        # (fail OR denied) AND NOT (info OR debug) AND ssh
        assert ev("(fail OR denied) AND NOT (info OR debug) AND ssh",
                  fail=True, denied=False, info=False, debug=False, ssh=True) is True
        assert ev("(fail OR denied) AND NOT (info OR debug) AND ssh",
                  fail=True, denied=False, info=True,  debug=False, ssh=True) is False

    def test_hash_or_ip_in_alert(self):
        assert ev("hash XOR ip", hash=True,  ip=False) is True
        assert ev("hash XOR ip", hash=True,  ip=True)  is False
        assert ev("hash XOR ip", hash=False, ip=False) is False


# ===========================================================================
# 7. extract_variables
# ===========================================================================

class TestExtractVariables:

    def test_single_var(self):
        assert extract_variables("A") == ["A"]

    def test_preserves_order(self):
        assert extract_variables("A AND B OR C") == ["A", "B", "C"]

    def test_deduplicates(self):
        assert extract_variables("A AND A OR A") == ["A"]

    def test_deduplicate_mixed_case(self):
        # 'A' and 'a' are distinct tokens at the IDENT level (case-sensitive names)
        result = extract_variables("A AND a")
        assert result == ["A", "a"]

    def test_excludes_keywords(self):
        result = extract_variables("A AND B OR C XOR D NOT E")
        assert set(result) == {"A", "B", "C", "D", "E"}

    def test_complex_expression(self):
        result = extract_variables("(A AND (B OR C)) XOR D")
        assert result == ["A", "B", "C", "D"]

    def test_quoted_var(self):
        result = extract_variables('"error 404" AND timeout')
        assert result == ["error 404", "timeout"]

    def test_empty_expression(self):
        # no IDENT tokens → empty list
        assert extract_variables("AND OR") == []

    def test_repeated_across_groups(self):
        result = extract_variables("(A AND B) OR (A AND C)")
        # A should appear only once
        assert result.count("A") == 1
        assert sorted(result) == ["A", "B", "C"]


# ===========================================================================
# 8. is_boolean_query
# ===========================================================================

class TestIsBooleanQuery:

    def test_single_keyword_is_not_boolean(self):
        assert is_boolean_query("error")          is False
        assert is_boolean_query("192.168.1.1")    is False
        assert is_boolean_query("abc123def456")   is False

    def test_and_detected(self):
        assert is_boolean_query("A AND B")        is True

    def test_or_detected(self):
        assert is_boolean_query("A OR B")         is True

    def test_not_detected(self):
        assert is_boolean_query("NOT A")          is True

    def test_xor_detected(self):
        assert is_boolean_query("A XOR B")        is True

    def test_case_insensitive_detection(self):
        assert is_boolean_query("a and b")        is True
        assert is_boolean_query("a or b")         is True
        assert is_boolean_query("not a")          is True
        assert is_boolean_query("a xor b")        is True

    def test_complex_expression(self):
        assert is_boolean_query("(A AND B) OR (NOT C XOR D)") is True

    def test_bad_syntax_returns_false_gracefully(self):
        # Unexpected char → tokeniser raises → is_boolean_query returns False
        assert is_boolean_query("A $ B")          is False

    def test_empty_string_is_not_boolean(self):
        assert is_boolean_query("")               is False
        assert is_boolean_query("   ")            is False


# ===========================================================================
# 9. line_matches (end-to-end log line evaluation)
# ===========================================================================

class TestLineMatches:

    def test_simple_keyword_present(self):
        matched, hits = line_matches("error", "Jan 1 kernel error: out of memory")
        assert matched is True
        assert "error" in hits

    def test_simple_keyword_absent(self):
        matched, hits = line_matches("warning", "Jan 1 kernel error: out of memory")
        assert matched is False

    def test_and_expression_both_present(self):
        matched, hits = line_matches(
            "error AND memory",
            "kernel error: out of memory",
        )
        assert matched is True
        assert "error"  in hits
        assert "memory" in hits

    def test_and_expression_one_absent(self):
        matched, _ = line_matches(
            "error AND timeout",
            "kernel error: out of memory",
        )
        assert matched is False

    def test_or_expression_one_present(self):
        matched, _ = line_matches(
            "error OR timeout",
            "connection timeout exceeded",
        )
        assert matched is True

    def test_not_expression(self):
        matched, _ = line_matches(
            "error AND NOT warning",
            "critical error detected",
        )
        assert matched is True

    def test_not_expression_blocked(self):
        matched, _ = line_matches(
            "error AND NOT warning",
            "error warning combination line",
        )
        assert matched is False

    def test_xor_expression_exactly_one(self):
        # Line contains 'error' but not 'timeout'
        matched, _ = line_matches(
            "error XOR timeout",
            "kernel error: segfault",
        )
        assert matched is True   # error=T, timeout=F → T XOR F = T

    def test_xor_expression_both_present(self):
        matched, _ = line_matches(
            "error XOR timeout",
            "error: connection timeout",
        )
        assert matched is False  # T XOR T = F

    def test_complex_group_expression(self):
        line = "ssh: Failed password for root from 10.0.0.9 port 22"
        matched, hits = line_matches(
            "(Failed OR Accepted) AND ssh AND NOT debug",
            line,
        )
        assert matched is True
        assert "Failed" in hits
        assert "ssh"    in hits

    def test_case_insensitive_matching(self):
        matched, hits = line_matches(
            "ERROR AND MEMORY",
            "kernel error: out of memory",
        )
        assert matched is True   # upper-case keywords match lower-case content

    def test_ip_address_as_keyword(self):
        matched, hits = line_matches(
            "10.0.0.1 AND Failed",
            "Failed password for root from 10.0.0.1",
        )
        assert matched is True
        assert "10.0.0.1" in hits

    def test_quoted_phrase_keyword(self):
        matched, hits = line_matches(
            '"Failed password" AND root',
            "Failed password for root from 10.0.0.1",
        )
        assert matched is True
        assert "Failed password" in hits

    def test_no_match_empty_line(self):
        matched, _ = line_matches("error AND timeout", "")
        assert matched is False

    def test_deeply_nested_expression(self):
        line = "auth: sudo session opened for user root by admin"
        matched, _ = line_matches(
            "((sudo OR su) AND (root OR admin)) AND NOT (closed OR logout)",
            line,
        )
        assert matched is True


# ===========================================================================
# 10. Error paths
# ===========================================================================

class TestErrorPaths:

    def test_undefined_variable_raises(self):
        with pytest.raises(ValueError, match="Undefined variable"):
            eval_expr("A AND B", {"A": True})   # B missing

    def test_missing_closing_paren_raises(self):
        with pytest.raises(ValueError):
            parse_expr("(A AND B")

    def test_extra_closing_paren_raises(self):
        with pytest.raises(ValueError):
            parse_expr("A AND B)")

    def test_operator_without_left_operand_raises(self):
        with pytest.raises(ValueError):
            parse_expr("AND B")

    def test_operator_without_right_operand_raises(self):
        with pytest.raises(ValueError):
            parse_expr("A AND")

    def test_empty_parens_raise(self):
        with pytest.raises(ValueError):
            parse_expr("()")

    def test_consecutive_idents_without_operator_raise(self):
        # "A B" — B is seen as an unexpected token after A
        with pytest.raises(ValueError):
            parse_expr("A B")

    def test_invalid_char_in_tokeniser_raises(self):
        with pytest.raises(ValueError, match="Unexpected character"):
            eval_expr("A $ B", {"A": True, "B": True})


# ===========================================================================
# 11. Edge cases
# ===========================================================================

class TestEdgeCases:

    def test_single_variable_true(self):
        assert eval_expr("A", {"A": True})  is True

    def test_single_variable_false(self):
        assert eval_expr("A", {"A": False}) is False

    def test_all_false_env_or(self):
        assert ev("A OR B OR C", A=False, B=False, C=False) is False

    def test_all_false_env_and(self):
        assert ev("A AND B AND C", A=False, B=False, C=False) is False

    def test_all_true_env_and(self):
        assert ev("A AND B AND C", A=True, B=True, C=True) is True

    def test_long_chain_or(self):
        expr = " OR ".join(f"V{i}" for i in range(20))
        env  = {f"V{i}": False for i in range(20)}
        env["V10"] = True
        assert eval_expr(expr, env) is True

    def test_long_chain_and(self):
        expr = " AND ".join(f"V{i}" for i in range(20))
        env  = {f"V{i}": True for i in range(20)}
        assert eval_expr(expr, env) is True

    def test_deeply_nested_not(self):
        # NOT NOT NOT NOT A  →  A  (four negations cancel out)
        assert ev("NOT NOT NOT NOT A", A=True)  is True
        assert ev("NOT NOT NOT NOT A", A=False) is False

    def test_case_insensitive_variable_lookup(self):
        # Variable stored as 'error', referenced as 'ERROR' in expression
        ast = parse_expr("ERROR")
        assert eval_node(ast, {"error": True})  is True
        assert eval_node(ast, {"error": False}) is False

    def test_whitespace_only_expression_parses_as_eof(self):
        with pytest.raises(ValueError):
            parse_expr("   ")

    def test_expression_with_only_parens(self):
        with pytest.raises(ValueError):
            parse_expr("()")

    def test_xor_is_associative_left(self):
        # A XOR B XOR C  →  (A XOR B) XOR C  (left-to-right)
        # T XOR T XOR T  →  F XOR T  = T
        assert ev("A XOR B XOR C", A=True, B=True, C=True) is True
        # T XOR F XOR F  →  T XOR F  = T
        assert ev("A XOR B XOR C", A=True, B=False, C=False) is True
        # F XOR F XOR F  →  F
        assert ev("A XOR B XOR C", A=False, B=False, C=False) is False

    def test_not_takes_only_immediate_operand(self):
        # NOT A AND B  →  (NOT A) AND B  (NOT binds tighter than AND)
        assert ev("NOT A AND B", A=True, B=True)   is False  # F AND T = F
        assert ev("NOT A AND B", A=False, B=True)  is True   # T AND T = T
        assert ev("NOT A AND B", A=False, B=False) is False  # T AND F = F
