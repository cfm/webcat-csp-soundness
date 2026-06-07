<!-- Generated from main.py's module docstring by `make readme`; edit the docstring, not this file. -->

# `webcat-csp-soundness`

CLI utility to find counterexamples for—

    WEBCAT.valid() ⇒ ¬Browser.loads_unverified()

—aka witnesses of—

    WEBCAT.valid() ∧ Browser.loads_unverified()

—i.e., a CSP that WEBCAT's [specification][webcat-csp] accepts as conformant
whose real (browser) interpretation according to [Content Security Policy Level
3][csp] still permits loading an asset that wasn't registered in the site's
manifest.

[csp]: https://www.w3.org/TR/CSP3/
[webcat-csp]: https://docs.webcat.tech/developers/CSP.html

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