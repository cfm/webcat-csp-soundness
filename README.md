<!-- Generated from main.py's module docstring by `make readme`; edit the docstring, not this file. -->

# `webcat-csp-soundness`

CLI utility to find differential counterexamples for—

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