#!/usr/bin/env python3
"""
CLI utility to find counterexamples for---

    Policy.accepted(p) ⇒ ¬EffectivePolicy.executes(p, c)

---aka instances of:

    Policy.accepted(p) ∧ EffectivePolicy.executes(p, c)
"""

import argparse
from z3 import Const, Solver, sat

from policy import Policy, EffectivePolicy, SerializedSourceList

default_src = Const("default-src", SerializedSourceList)
object_src = Const("object-src", SerializedSourceList)

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Find a counterexample of accept(P) ⇒ ¬executes(P, c)."
    )
    parser.add_argument(
        "--show-query",
        action="store_true",
        help="Print the Z3 query before solving.",
    )
    args = parser.parse_args()
    solver = Solver()

    p = Policy(default_src, object_src).valid()
    c = None  # TODO
    ep = EffectivePolicy(default_src, object_src).executes(c)
    solver.add(p)
    solver.add(ep)
    if args.show_query:
        print(p)
        print(ep)

    result = solver.check()
    if result == sat:
        model = solver.model()
        print("Violating policy found:")
        print(model[default_src], model[object_src])
        return 1

    print("No violating policies found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
