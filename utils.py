"""
These are utility functions that I asked Claude to generate and (in contrast to
the rest of this project) have *not* inspected or tested carefully.  Consider
them development and debugging aids, and take them with a grain of salt.
"""

from z3 import (
    ArraySortRef,
    BoolSort,
    DatatypeSortRef,
    IsMember,
    is_app,
    is_expr,
    is_true,
)


def pretty_model(model) -> str:
    # Only the constants (arity 0); skip Z3's internal accessor/array helpers.
    decls = [d for d in model.decls() if d.arity() == 0]
    lines = [f"{d.name()} = {format_value(model, model[d])}" for d in decls]
    return "[" + ",\n ".join(lines) + "]"


def pretty_effective(model, directives) -> str:
    """Render selected directives' *effective* (post-fallback) values, e.g.

        [script-src = present({⊤}),
         style-src = present({⊤})]

    `directives` maps each display name to its effective `Sources` expression
    (typically a `Browser` property). A resolved directive is never absent — an
    omitted one inherits its fallback — so each value is shown as `present(…)`."""
    lines = []
    for name, expression in directives.items():
        sources = format_value(model, model.eval(expression, model_completion=True))
        lines.append(f"{name} = present({sources})")
    return "[" + ",\n ".join(lines) + "]"


def set_members(model, value) -> list[str]:
    """Names of the enum members present in a Z3 set value (Array(enum, Bool))."""
    domain = value.sort().domain()
    return [
        domain.constructor(i).name()
        for i in range(domain.num_constructors())
        if is_true(
            model.eval(
                IsMember(domain.constructor(i)(), value),
                model_completion=True,
            )
        )
    ]


def format_value(model, value) -> str:
    """Render a model value, collapsing sets to just their members."""
    if not is_expr(value):
        return str(value)
    sort = value.sort()
    # A Z3 set is Array(domain, Bool). We can only list its members when the
    # domain is a finite (enum) sort; otherwise fall back to Z3's own repr.
    if (
        isinstance(sort, ArraySortRef)
        and sort.range() == BoolSort(sort.ctx)
        and isinstance(sort.domain(), DatatypeSortRef)
    ):
        return "{" + ", ".join(set_members(model, value)) + "}"
    # An algebraic datatype value, e.g. `absent` or `present({...})`: show the
    # constructor name and recursively format its arguments (sets included).
    if isinstance(sort, DatatypeSortRef) and is_app(value):
        name = value.decl().name()
        if value.num_args() == 0:
            return name
        args = ", ".join(
            format_value(model, value.arg(i)) for i in range(value.num_args())
        )
        return f"{name}({args})"
    return str(value)


def _csp_token(source: str) -> str:
    # `⊤` models "any source not enumerated"; render it as the CSP wildcard.
    return "*" if source == "⊤" else f"'{source.replace('_', '-')}'"


def csp_header(model, directives) -> str:
    """Render a model's *present* directives as a `Content-Security-Policy`
    header value. Absent directives are omitted, as they would be in a real
    header. `directives` is a sequence of directive constants, in header order."""
    parts = []
    for directive in directives:
        value = model.eval(directive, model_completion=True)
        if value.decl().name() == "absent":
            continue
        tokens = [_csp_token(source) for source in set_members(model, value.arg(0))]
        parts.append(" ".join([directive.decl().name(), *tokens]))
    return "Content-Security-Policy: " + "; ".join(parts)
