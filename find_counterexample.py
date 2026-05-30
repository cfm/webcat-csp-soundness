#!/usr/bin/env python3
"""
CLI utility to find counterexamples for---

    Policy.valid() ⇒ ¬EffectivePolicy.executes(obj)

---aka examples of:

    Policy.valid() ∧ EffectivePolicy.executes(obj)
"""

import argparse
from z3 import Const, Solver, sat

from policy import Policy, EffectivePolicy, SerializedSourceList, TOP

default_src = Const("default-src", SerializedSourceList)
object_src = Const("object-src", SerializedSourceList)
script_src = Const("script-src", SerializedSourceList)

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

    p = Policy(default_src, object_src, script_src).valid()
    obj = TOP  # since other values in the `SerializedSourceList` lattice are explicitly allowed
    ep = EffectivePolicy(default_src, object_src, script_src).executes(obj)
    solver.add(p)
    solver.add(ep)
    if args.show_query:
        print(f"--> Policy.valid(): {p}")
        print(f"--> EffectivePolicy.executes({obj}): {ep}")

    result = solver.check()
    if result == sat:
        model = solver.model()
        print(f"<-- Violating policy found for {obj}:")
        print(model)
        return 1

    print("<-- No violating policies found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
