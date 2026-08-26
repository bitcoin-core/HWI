#! /usr/bin/env python3

import unittest

from typing import List, Optional, Set, Type


_test_selectors: Optional[List[str]] = None
_matched_selectors: Set[str] = set()


def set_test_selectors(selectors: Optional[List[str]]) -> None:
    """Select device tests by method name."""
    global _test_selectors, _matched_selectors
    _test_selectors = selectors or None
    _matched_selectors = set()


def get_test_case_names(testclass: Type[unittest.TestCase]) -> List[str]:
    """Return the selected test methods from ``testclass``."""
    testnames = list(unittest.TestLoader().getTestCaseNames(testclass))
    if _test_selectors is None:
        return testnames

    selected = []
    for testname in testnames:
        if testname in _test_selectors:
            _matched_selectors.add(testname)
            selected.append(testname)
    return selected


def get_unmatched_test_selectors() -> List[str]:
    """Return selectors that did not match any constructed device suite."""
    if _test_selectors is None:
        return []
    return [selector for selector in _test_selectors if selector not in _matched_selectors]


class TestTestSelector(unittest.TestCase):
    class FirstTests(unittest.TestCase):
        def test_alpha(self) -> None:
            pass

        def test_shared(self) -> None:
            pass

    class SecondTests(unittest.TestCase):
        def test_beta(self) -> None:
            pass

        def test_shared(self) -> None:
            pass

    def tearDown(self) -> None:
        set_test_selectors(None)

    def test_no_selectors(self) -> None:
        set_test_selectors(None)
        self.assertEqual(
            get_test_case_names(self.FirstTests),
            ["test_alpha", "test_shared"],
        )

    def test_method_selector(self) -> None:
        set_test_selectors(["test_shared"])
        self.assertEqual(get_test_case_names(self.FirstTests), ["test_shared"])
        self.assertEqual(get_test_case_names(self.SecondTests), ["test_shared"])
        self.assertEqual(get_unmatched_test_selectors(), [])

    def test_selector_list_and_unmatched(self) -> None:
        set_test_selectors(["test_alpha", "test_beta", "test_missing"])
        self.assertEqual(get_test_case_names(self.FirstTests), ["test_alpha"])
        self.assertEqual(get_test_case_names(self.SecondTests), ["test_beta"])
        self.assertEqual(get_unmatched_test_selectors(), ["test_missing"])
