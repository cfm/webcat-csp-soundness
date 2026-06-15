#!/usr/bin/env python3
"""
# `webcat-csp-soundness`

> [!NOTE]
> This tool was a project for ["Computer-Aided Reasoning for Software"][cars] at
> the University of Washington in spring 2026.  It remains a prototype and has
> not yet been validated for real-world use.

CLI utility to find differential counterexamples for—

    WEBCAT.valid() ⇒ ¬Browser.loads_unverified()

—aka witnesses of—

    WEBCAT.valid() ∧ Browser.loads_unverified()

—i.e., a CSP that WEBCAT's [specification][webcat-csp] accepts as conformant
whose real (browser) interpretation according to [Content Security Policy Level
3][csp] still permits loading an asset that wasn't registered in the site's
manifest.

[cars]: https://courses.cs.washington.edu/courses/csep590b/26sp/
[csp]: https://www.w3.org/TR/CSP3/
[webcat-csp]: https://docs.webcat.tech/developers/CSP.html


## Running

Preferably in a virtual environment:

```bash
pip3 install -r requirements.txt
python3 main.py
```

This command will yield *some* witness.  If you'd like to reproduce exactly the
witness described below, run the tests:

```bash
python3 -m doctest -v main.py
```

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

Pinning the directives WEBCAT requires finds a differential counterexample:

    >>> from policy import (
    ...     only, Source, NONE, SELF,
    ...     object_src, frame_src, child_src, worker_src, script_src_elem, style_src_elem,
    ... )
    >>> present = Directive.constructor(1)
    >>> none_, self_ = present(only(NONE, Source)), present(only(SELF, Source))
    >>> solver.add(object_src == none_, frame_src == self_, child_src == self_, worker_src == self_)
    >>> solver.add(Directive.is_absent(script_src_elem), Directive.is_absent(style_src_elem))
    >>> solver.check() == sat
    True
    >>> model = solver.model()

The omitted script/style directives have inherited the absent default's
allow-all:

    >>> from utils import pretty_effective
    >>> browser = Browser()
    >>> print(pretty_effective(model, {
    ...     "script-src": browser.script_src,
    ...     "style-src": browser.style_src,
    ... }))
    [script-src = present({⊤}),
     style-src = present({⊤})]

That is, a server could send the following `Content-Security-Policy` header, and
the page would have the following gaps:

    >>> print(csp_report(model))
    Content-Security-Policy: object-src 'none'; frame-src 'self'; child-src 'self'; worker-src 'self'
    WEBCAT.valid():             yes
    Browser.loads_unverified(): {script-src, script-src-elem, style-src, style-src-elem}
"""

import argparse
from z3 import Solver, is_true, sat, unsat

from policy import DIRECTIVES, Browser, WEBCAT, permits_unverified
from utils import csp_header, pretty_model


def csp_report(model) -> str:
    browser = Browser()
    loaders = {
        "script-src": browser.script_src,
        "script-src-elem": browser.script_src_elem,
        "style-src": browser.style_src,
        "style-src-elem": browser.style_src_elem,
        "object-src": browser.object_src,
        "frame-src": browser.frame_src,
        "child-src": browser.child_src,
        "worker-src": browser.worker_src,
    }
    admits = [
        name
        for name, effective in loaders.items()
        if is_true(model.eval(permits_unverified(effective), model_completion=True))
    ]
    accepts = is_true(model.eval(WEBCAT().valid(), model_completion=True))
    verdict = ", ".join(admits) if admits else ""
    return (
        f"{csp_header(model, DIRECTIVES)}\n"
        f"{'WEBCAT.valid():':<27} {'yes' if accepts else 'no'}\n"
        f"{'Browser.loads_unverified():':<27} {{{verdict}}}"
    )


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
        print(f"==> Query: {solver}")

    result = solver.check()
    if result == unsat:
        print("<== No violating policies found.")
        return 0  # Unsat is our goal: WEBCAT.valid() is sound!

    elif result == sat:
        model = solver.model()
        print("<== Violating policy found:")
        print(f"<-- {pretty_model(model)}")
        print(f"<-- {csp_report(model)}")
        return 1

    else:
        print("<== Query timed out.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
