#!/usr/bin/env python3
"""
CLI utility to find counterexamples for---

    Policy.valid() ⇒ ¬EffectivePolicy.allows(obj)

---aka examples of:

    Policy.valid() ∧ EffectivePolicy.allows(obj)
"""

import argparse
from z3 import Const, Or, Solver, sat, unsat

from policy import Policy, EffectivePolicy, SerializedSource, TOP, WASM_UNSAFE_EVAL


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

    p = Policy().valid()
    solver.add(p)

    obj = Const("obj", SerializedSource)
    # FIXME: clarify how to represent safe versus unsafe executions
    solver.add(Or(obj == TOP, obj == WASM_UNSAFE_EVAL))

    ep = EffectivePolicy().allows(obj)
    solver.add(ep)

    if args.show_query:
        print(f"--> Query: {solver}")

    result = solver.check()
    if result == unsat:
        print("<-- No violating policies found.")
        return 0  # Unsat is our goal: Policy.valid() is sound!

    elif result == sat:
        model = solver.model()
        print("<-- Violating policy found:")
        print(model)
        return 1

    else:
        print("<-- Query timed out.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
