from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression
from sigma.types import SigmaCompareExpression, SigmaRegularExpression, SigmaRegularExpressionFlag, SpecialChars, SigmaString, SigmaCIDRExpression
# from sigma.pipelines.jsonata import # TODO: add pipeline imports or delete this line
import sigma
import re
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Optional, Union


class JSONataBackend(TextQueryBackend):
    """jsonata backend."""
    # TODO: change the token definitions according to the syntax. Delete these not supported by your backend.
    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name : ClassVar[str] = "jsonata backend"
    formats : Dict[str, str] = {
        "default": "Plain jsonata queries",
        
    }
    requires_pipeline : bool = False            # TODO: does the backend requires that a processing pipeline is provided? This information can be used by user interface programs like Sigma CLI to warn users about inappropriate usage of the backend.

    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder

    # Generated query tokens
    token_separator : str = " "     # separator inserted between all boolean operators
    or_token : ClassVar[str] = "or"
    and_token : ClassVar[str] = "and"
    not_token : ClassVar[str] = "NOT"
    eq_token : ClassVar[str] = " = "  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting
    field_quote : ClassVar[str] = "\""                               # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern : ClassVar[Pattern] = re.compile("^\\w+$")   # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation : ClassVar[bool] = True            # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).

    ### Escaping
    field_escape : ClassVar[str] = ""               # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote : ClassVar[bool] = True        # Escape quote string defined in field_quote
    field_escape_pattern : ClassVar[Pattern] = re.compile("\\s")   # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote       : ClassVar[str] = '\"'     # string quoting character (added as escaping character)
    escape_char     : ClassVar[str] = "\\"    # Escaping character for special characrers inside string
    wildcard_multi  : ClassVar[str] = "*"     # Character used as multi-character wildcard
    wildcard_single : ClassVar[str] = "*"     # Character used as single-character wildcard
    add_escaped     : ClassVar[str] = "\\"    # Characters quoted in addition to wildcards and string quote
    filter_chars    : ClassVar[str] = ""      # Characters filtered
    bool_values     : ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression : ClassVar[str] = "$match({field}, /^{value}/)"
    endswith_expression   : ClassVar[str] = "$match({field}, /{value}$/)"
    contains_expression   : ClassVar[str] = "$contains({field}, {value})"
    wildcard_match_expression: ClassVar[str] = "$match({field}, /{value}/)"  # Special expression if wildcards can't be matched with the eq_token operator

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression : ClassVar[str] = "$match({field}, /{regex}/)"
    re_escape_char : ClassVar[str] = "\\"               # Character used for escaping in regular expressions
    re_escape : ClassVar[Tuple[str]] = ()               # List of strings that are escaped
    re_escape_escape_char : bool = True                 # If True, the escape character is also escaped
    re_flag_prefix : bool = True                        # If True, the flags are prepended as (?x) group at the beginning of the regular expression, e.g. (?i). If this is not supported by the target, it should be set to False.
    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.
    re_flags : Dict[SigmaRegularExpressionFlag, str] = {
        SigmaRegularExpressionFlag.IGNORECASE: "i",
        SigmaRegularExpressionFlag.MULTILINE : "m",
        SigmaRegularExpressionFlag.DOTALL    : "s",
    }

    # Case sensitive string matching expression. String is quoted/escaped like a normal string.
    # Placeholders {field} and {value} are replaced with field name and quoted/escaped string.
    case_sensitive_match_expression : ClassVar[str] = "{field} casematch {value}"
    # Case sensitive string matching operators similar to standard string matching. If not provided,
    # case_sensitive_match_expression is used.
    case_sensitive_startswith_expression : ClassVar[str] = "{field} casematch_startswith {value}"
    case_sensitive_endswith_expression   : ClassVar[str] = "{field} casematch_endswith {value}"
    case_sensitive_contains_expression   : ClassVar[str] = "{field} casematch_contains {value}"

    # CIDR expressions: define CIDR matching if backend has native support. Else pySigma expands
    # CIDR values into string wildcard matches.
    cidr_expression : ClassVar[Optional[str]] = "$match({field}, /{network}\\..*/)"  # CIDR expression query as format string with placeholders {field}, {value}, {network}, {prefixlen}, and {netmask}.

    # Numeric comparison operators
    compare_op_expression : ClassVar[str] = "{field} {operator} {value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    # Expression for comparing two event fields
    field_equals_field_expression : ClassVar[Optional[str]] = None  # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item
    field_equals_field_escaping_quoting : Tuple[bool, bool] = (True, True)   # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be implemented in the convert_condition_field_eq_field_escape_and_quote method.

    # Null/None expressions
    field_null_expression : ClassVar[str] = "{field} = null"          # Expression for field has null value as format string with {field} placeholder for field name

    # Field existence condition expressions.
    field_exists_expression : ClassVar[str] = "$exists({field})"             # Expression for field existence as format string with {field} placeholder for field name
    field_not_exists_expression : ClassVar[str] = "$not($exists({field}))"      # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in : ClassVar[bool] = True                     # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = True                    # Convert AND as in-expression
    in_expressions_allow_wildcards : ClassVar[bool] = True       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression : ClassVar[str] = "{field} {op} [{list}]"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator : ClassVar[str] = "in"               # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    and_in_operator : ClassVar[str] = "contains-all"    # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator : ClassVar[str] = ", "               # List element separator

    # Value not bound to a field
    unbound_value_str_expression : ClassVar[str] = '**.* "{value}"'   # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression : ClassVar[str] = '{value}'     # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_re_expression : ClassVar[str] = '_=~{value}'   # Expression for regular expression not bound to a field as format string with placeholder {value} and {flag_x} as described for re_expression

    # Query finalization: appending and concatenating deferred query part
    deferred_start : ClassVar[str] = "\n| "               # String used as separator between main query and deferred parts
    deferred_separator : ClassVar[str] = "\n| "           # String used to join multiple deferred query parts
    deferred_only_query : ClassVar[str] = "*"            # String used as query if final query only contains deferred expression

    # Correlations
    # TODO: delete everything to the correlation end marker if correlations aren't implemented
    correlation_methods: ClassVar[Dict[str, str]] = {
        "default": "Test correlation method",
    }
    default_correlation_method: ClassVar[str] = "default"
    default_correlation_query: ClassVar[str] = {"default": "{search}\n{aggregate}\n{condition}"}
    temporal_correlation_query: ClassVar[str] = {"default": "{search}\n\n{aggregate}\n\n{condition}"}

    correlation_search_single_rule_expression: ClassVar[str] = "{query}"
    correlation_search_multi_rule_expression: ClassVar[str] = "{queries}"
    correlation_search_multi_rule_query_expression: ClassVar[
        str
    ] = 'subsearch (( {query} | set event_type="{ruleid}"{normalization} ))'
    correlation_search_multi_rule_query_expression_joiner: ClassVar[str] = "\n"

    correlation_search_field_normalization_expression: ClassVar[str] = " | set {alias}={field}"
    correlation_search_field_normalization_expression_joiner: ClassVar[str] = ""

    event_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| aggregate window={timespan} count() as event_count{groupby}"
    }
    value_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| aggregate window={timespan} value_count({field}) as value_count{groupby}"
    }
    temporal_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| temporal window={timespan} eventtypes={referenced_rules}{groupby}"
    }
    temporal_ordered_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| temporal ordered=true window={timespan} eventtypes={referenced_rules}{groupby}"
    }

    timespan_mapping: ClassVar[Dict[str, str]] = {
        "m": "min",
    }
    referenced_rules_expression: ClassVar[Dict[str, str]] = {"default": "{ruleid}"}
    referenced_rules_expression_joiner: ClassVar[Dict[str, str]] = {"default": ","}

    groupby_expression: ClassVar[Dict[str, str]] = {"default": " by {fields}"}
    groupby_field_expression: ClassVar[Dict[str, str]] = {"default": "{field}"}
    groupby_field_expression_joiner: ClassVar[Dict[str, str]] = {"default": ", "}

    event_count_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "| where event_count {op} {count}"
    }
    value_count_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "| where value_count {op} {count}"
    }
    temporal_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "| where eventtype_count {op} {count}"
    }
    temporal_ordered_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "| where eventtype_count {op} {count} and eventtype_order={referenced_rules}"
    }
    ### Correlation end ###

    # TODO: implement custom methods for query elements not covered by the default backend base.
    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    def escape_and_quote_field(self, field_name: str) -> str:
        new_field_name = super().escape_and_quote_field(field_name)

        # Check if field_escape_pattern in field_name
        if self.field_escape_pattern.search(field_name):
            new_field_name = '$.' + new_field_name

        return new_field_name

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        try:
            if (  # Check conditions for usage of 'startswith' operator
                self.startswith_expression
                is not None  # 'startswith' operator is defined in backend
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)  # String ends with wildcard
                and (
                    self.startswith_expression_allow_special
                    or not cond.value[:-1].contains_special()
                )  # Remainder of string doesn't contains special characters or it's allowed
            ):
                expr = (
                    self.startswith_expression
                )  # If all conditions are fulfilled, use 'startswith' operator instead of equal token
                value = cond.value[:-1]
            elif (  # Same as above but for 'endswith' operator: string starts with wildcard and doesn't contains further special characters
                self.endswith_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and (
                    self.endswith_expression_allow_special or not cond.value[1:].contains_special()
                )
            ):
                expr = self.endswith_expression
                value = cond.value[1:]
            elif (  # contains: string starts and ends with wildcard
                self.contains_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and (
                    self.contains_expression_allow_special
                    or not cond.value[1:-1].contains_special()
                )
            ):
                expr = self.contains_expression
                value = cond.value[1:-1]
            elif (  # wildcard match expression: string contains wildcard
                self.wildcard_match_expression is not None and cond.value.contains_special()
            ):
                expr = self.wildcard_match_expression
                value = cond.value.to_regex(self.add_escaped_re)
            else:
                expr = self.eq_expression
                value = cond.value
            return expr.format(
                field=self.escape_and_quote_field(cond.field),
                value=self.convert_value_str(value, state),
                regex=self.convert_value_re(value.to_regex(self.add_escaped_re), state),
                backend=self,
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError(
                "Field equals string value expressions with strings are not supported by the backend."
            )

    def convert_condition_field_eq_val_cidr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field matches CIDR value expressions."""
        cidr: SigmaCIDRExpression = cond.value
        if self.cidr_expression is not None:
            return self.cidr_expression.format(
                field=self.escape_and_quote_field(cond.field),
                value=str(cidr.network),
                network=cidr.network.network_address,
                prefixlen=cidr.network.prefixlen,
                netmask=cidr.network.netmask,
            )
        else:
            expanded = cidr.expand()
            expanded_cond = ConditionOR(
                [
                    ConditionFieldEqualsValueExpression(cond.field, SigmaString(network))
                    for network in expanded
                ],
                cond.source,
            )
            return self.convert_condition(expanded_cond, state)