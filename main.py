#!/usr/bin/env python3
"""
CLI utility to find counterexamples for---

    WEBCAT.valid() ⇒ ¬Browser.allows_unsafe()

---aka examples of:

    WEBCAT.valid() ∧ Browser.allows_unsafe()
"""

import argparse
from z3 import Solver, sat, unsat

from policy import Browser, WEBCAT
from utils import pretty_model


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Find CSPs valid under WEBCAT that allow unsafe code execution."
    )
    parser.add_argument(
        "--show-query",
        action="store_true",
        help="Print the Z3 query before solving.",
    )
    args = parser.parse_args()
    solver = Solver()

    solver.add(WEBCAT().valid())
    solver.add(Browser().allows_unsafe())

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
