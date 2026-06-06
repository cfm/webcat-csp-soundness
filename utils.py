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
        domain = sort.domain()
        members = [
            str(domain.constructor(i)())
            for i in range(domain.num_constructors())
            if is_true(
                model.eval(
                    IsMember(domain.constructor(i)(), value),
                    model_completion=True,
                )
            )
        ]
        return "{" + ", ".join(members) + "}"
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
