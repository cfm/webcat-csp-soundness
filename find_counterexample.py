#!/usr/bin/env python3
"""CLI utility to find counterexamples for accept(P) ⇒ ¬executes(P, c)."""

import argparse
from z3 import Bool, Implies, Not, Solver, sat


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

    accept_p = Bool("accept(P)")
    executes_p_c = Bool("executes(P,c)")

    implication = Implies(accept_p, Not(executes_p_c))
    counterexample_query = Not(implication)

    if args.show_query:
        print(f"Query: {counterexample_query}")

    solver = Solver()
    solver.add(counterexample_query)

    result = solver.check()
    if result == sat:
        model = solver.model()
        print("Counterexample found:")
        print(f"  accept(P) = {model.eval(accept_p, model_completion=True)}")
        print(f"  executes(P,c) = {model.eval(executes_p_c, model_completion=True)}")
        return 0

    print("No counterexample found.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
