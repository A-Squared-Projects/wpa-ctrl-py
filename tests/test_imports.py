## @package tests.test_imports
#
# Guards on what this package imports.
#
# Both of these exist for the benefit of whoever packages this. OpenEmbedded
# splits the standard library across several packages, so a distribution's
# RDEPENDS is derived from the import list - and an import that a scan cannot
# see produces a package that works in every virtualenv and fails on a device,
# at whatever moment the hidden import is first reached.
#
# @file test_imports.py

import ast
import os
import unittest
from unittest import TestCase

PACKAGE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "wpa_ctrl")

## The standard library modules this package uses. Changing this set changes
#  what a distribution has to depend on, so it is spelled out rather than
#  discovered: on OpenEmbedded these map to python3-logging (logging),
#  python3-io (socket, select) and python3-core (the rest)
EXPECTED_STDLIB_IMPORTS = {
    "logging",
    "os",
    "select",
    "socket",
    "stat",
    "time",
    "typing",
    }


def setUpModule():
    print(__name__ + " set up")

def tearDownModule():
    print(__name__ + " tear down")
    print()


def _sources():
    for name in sorted(os.listdir(PACKAGE)):
        if name.endswith(".py"):
            path = os.path.join(PACKAGE, name)
            with open(path) as handle:
                yield name, ast.parse(handle.read())


class TestImports(TestCase):

    ## An import inside a function is invisible to anything that reads
    #  imports, a packager's scan included
    def test_every_import_is_at_module_scope(self):
        nested = []
        for name, tree in _sources():
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                         ast.ClassDef)):
                    continue
                for inner in ast.walk(node):
                    if isinstance(inner, (ast.Import, ast.ImportFrom)):
                        nested.append(f"{name}:{inner.lineno} in {node.name}()")
        self.assertEqual(nested, [],
                         "imports must be at module scope so the dependency "
                         "list stays scannable")

    ## A new standard library import changes what a distribution package has
    #  to depend on. Making that a test failure means it is noticed here
    #  rather than as an ImportError on a device
    def test_stdlib_imports_are_the_expected_set(self):
        imported = set()
        for _name, tree in _sources():
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".")[0]
                                    for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    # level > 0 is a relative import, i.e. our own modules
                    if node.level == 0 and node.module:
                        imported.add(node.module.split(".")[0])
        self.assertEqual(imported, EXPECTED_STDLIB_IMPORTS,
                         "the packaging dependency list needs updating to "
                         "match; see EXPECTED_STDLIB_IMPORTS")

    ## Third-party dependencies would have to be declared in pyproject and
    #  then packaged for the target; there are none, and that is a feature
    def test_no_third_party_imports(self):
        import sys
        for name in EXPECTED_STDLIB_IMPORTS:
            self.assertIn(name, sys.stdlib_module_names,
                          f"{name} is not part of the standard library")


if __name__ == '__main__':
    unittest.main()
