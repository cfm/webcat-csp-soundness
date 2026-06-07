#!/usr/bin/env python3
"""
# `webcat-csp-soundness`

CLI utility to find counterexamples for---

    WEBCAT.valid() ⇒ ¬Browser.loads_unverified()

---aka witnesses of---

    WEBCAT.valid() ∧ Browser.loads_unverified()

---i.e., a CSP that WEBCAT accepts as conformant whose real (browser)
interpretation still permits loading an asset that wasn't registered in the
site's manifest.

## Satisfiability

    >>> from z3 import Solver, sat
    >>> from policy import WEBCAT, Browser, Directive, default_src, script_src, style_src
    >>> solver = Solver()
    >>> solver.add(WEBCAT().valid())
    >>> solver.add(Directive.is_absent(default_src))
    >>> solver.add(Directive.is_absent(script_src))
    >>> solver.add(Directive.is_absent(style_src))
    >>> solver.add(Browser().loads_unverified())
    >>> solver.check() == sat
    True

## A concrete witness

    >>> from utils import pretty_effective
    >>> browser = Browser()
    >>> print(pretty_effective(solver.model(), {
    ...     "script-src": browser.script_src,
    ...     "style-src": browser.style_src,
    ... }))
    [script-src = present({⊤}),
     style-src = present({⊤})]
"""

import argparse
from z3 import Solver, sat, unsat

from policy import Browser, WEBCAT
from utils import pretty_model


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Find CSPs valid under WEBCAT that load unverified assets."
    )
    parser.add_argument(
        "--show-query",
        action="store_true",
        help="Print the Z3 query before solving.",
    )
    args = parser.parse_args()
    solver = Solver()

    solver.add(WEBCAT().valid())
    solver.add(Browser().loads_unverified())

    if args.show_query:
        print(f"--> Query: {solver}")

    result = solver.check()
    if result == unsat:
        print("<-- No violating policies found.")
        return 0  # Unsat is our goal: WEBCAT.valid() is sound!

    elif result == sat:
        model = solver.model()
        print("<-- Violating policy found:")
        print(pretty_model(model))
        return 1

    else:
        print("<-- Query timed out.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
