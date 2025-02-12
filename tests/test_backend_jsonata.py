import pytest
from sigma.collection import SigmaCollection
from sigma.backends.jsonata import JSONataBackend

@pytest.fixture
def jsonata_backend():
    return JSONataBackend()

def test_jsonata_and_expression(jsonata_backend : JSONataBackend):
    assert jsonata_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ['fieldA = \"valueA\" and fieldB = \"valueB\"']

def test_jsonata_or_expression(jsonata_backend : JSONataBackend):
    assert jsonata_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ['fieldA = \"valueA\" or fieldB = \"valueB\"']

def test_jsonata_and_or_expression(jsonata_backend : JSONataBackend):
    assert jsonata_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ['(fieldA in [\"valueA1\", \"valueA2\"]) and (fieldB in [\"valueB1\", \"valueB2\"])']

def test_jsonata_or_and_expression(jsonata_backend : JSONataBackend):
    assert jsonata_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == ['fieldA = "valueA1" and fieldB = "valueB1" or fieldA = "valueA2" and fieldB = "valueB2"']

def test_jsonata_in_expression(jsonata_backend : JSONataBackend):
    assert jsonata_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['fieldA in [\"valueA\", \"valueB\"] or $match(fieldA, /valueC.*/)']

def test_jsonata_regex_query(jsonata_backend : JSONataBackend):
    assert jsonata_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ['$match(fieldA, /foo.*bar/) and fieldB = "foo"']

def test_jsonata_cidr_query(jsonata_backend : JSONataBackend):
    assert jsonata_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['$match(field, /192\\.168\\..*/)']

def test_jsonata_field_name_with_whitespace(jsonata_backend : JSONataBackend):
    assert jsonata_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """)
    ) == ['$."field name" = \"value\"']

def test_jsonata_with_contains(jsonata_backend : JSONataBackend):
    assert jsonata_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name|contains: value
                condition: sel
        """)
    ) == ['$contains($."field name", "value")']

# TODO: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
# implemented with custom code, deferred expressions etc.


