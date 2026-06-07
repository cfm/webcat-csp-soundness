from typing import cast
from z3 import (
    And,
    ArrayRef,
    Const,
    Datatype,
    DatatypeSortRef,
    EmptySet,
    EnumSort,
    ExprRef,
    If,
    Implies,
    IsMember,
    IsSubset,
    Not,
    Or,
    SetAdd,
    SetDel,
    SetSort,
)


# https://www.w3.org/TR/CSP3/#grammardef-serialized-source-list
Source, (NONE, SELF, WASM_UNSAFE_EVAL, TOP) = EnumSort(
    "source", ["none", "self", "wasm_unsafe_eval", "⊤"]
)
UNVERIFIED_SOURCES = (TOP, WASM_UNSAFE_EVAL)
REAL_SOURCES = (SELF, WASM_UNSAFE_EVAL, TOP)  # `Source / {NONE}`; see `is_none()`

Sources = SetSort(Source)
Directive = Datatype("directive")
Directive.declare("absent")
Directive.declare("present", ("sources", Sources))
Directive = Directive.create()

# NB. Here and below, CSP directives are listed in the order in which WEBCAT
# documents them (https://docs.webcat.tech/developers/CSP.html).
default_src = Const("default-src", Directive)
script_src = Const("script-src", Directive)
script_src_elem = Const("script-src-elem", Directive)
style_src = Const("style-src", Directive)
style_src_elem = Const("style-src-elem", Directive)
object_src = Const("object-src", Directive)
frame_src = Const("frame-src", Directive)
child_src = Const("child-src", Directive)
worker_src = Const("worker-src", Directive)


def only(e: ExprRef, s: DatatypeSortRef) -> ArrayRef:
    """Return a set of sort `s` containing only the element `e`."""
    return SetAdd(EmptySet(s), e)


def srcs(directive: ExprRef) -> ArrayRef:
    """Sources of `directive`, or ∅ when absent (keeps the accessor total)."""
    return cast(
        ArrayRef,
        If(
            Directive.is_absent(directive),  # pyright: ignore[reportAttributeAccessIssue]
            EmptySet(Source),
            Directive.sources(directive),  # pyright: ignore[reportAttributeAccessIssue]
        ),
    )


def permits(permission: ExprRef, source: ExprRef) -> ExprRef:
    return IsMember(source, permission)


def permits_unverified(permission: ExprRef) -> ExprRef:
    return cast(
        ExprRef, Or(*(permits(permission, source) for source in UNVERIFIED_SOURCES))
    )


def normalize(sources: ArrayRef) -> ArrayRef:
    # Per freedomofpress/webcat#99 only {NONE} means none; {NONE, SELF} means
    # SELF.
    return SetDel(sources, NONE)


def restricted_to(directive: ExprRef, *allowed: ExprRef) -> ExprRef:
    permitted = EmptySet(Source)
    for source in allowed:
        permitted = SetAdd(permitted, source)
    return cast(ExprRef, IsSubset(srcs(directive), permitted))


def is_none(directive: ExprRef) -> ExprRef:
    """
    Checking `normalize() == ∅` can cause the query to return unknown.  It's
    equivalent and faster to check for membership in `REAL_SOURCES` as defined
    above.
    """
    return cast(
        ExprRef,
        And(
            Directive.is_present(directive),  # pyright: ignore[reportAttributeAccessIssue]
            *(Not(permits(srcs(directive), source)) for source in REAL_SOURCES),
        ),
    )


def resolve(*directives: ExprRef, fallback: ExprRef) -> ExprRef:
    effective = fallback
    for directive in reversed(directives):
        effective = cast(
            ExprRef,
            If(
                Directive.is_absent(directive),  # pyright: ignore[reportAttributeAccessIssue]
                effective,
                normalize(Directive.sources(directive)),  # pyright: ignore[reportAttributeAccessIssue]
            ),
        )
    return effective


class Browser:
    @property
    def default_src(self) -> ExprRef:
        return resolve(default_src, fallback=only(TOP, Source))

    @property
    def script_src(self) -> ExprRef:
        return resolve(script_src, fallback=self.default_src)

    @property
    def script_src_elem(self) -> ExprRef:
        return resolve(script_src_elem, fallback=self.script_src)

    @property
    def style_src(self) -> ExprRef:
        return resolve(style_src, fallback=self.default_src)

    @property
    def style_src_elem(self) -> ExprRef:
        return resolve(style_src_elem, fallback=self.style_src)

    @property
    def object_src(self) -> ExprRef:
        return resolve(object_src, fallback=self.default_src)

    @property
    def frame_src(self) -> ExprRef:
        return resolve(frame_src, fallback=self.child_src)

    @property
    def child_src(self) -> ExprRef:
        return resolve(child_src, fallback=self.default_src)

    @property
    def worker_src(self) -> ExprRef:
        # "If this directive is absent, the user agent will first look for the
        # `child-src`` directive, then the `script-src` directive, then finally for
        # the `default-src` directive, when governing worker execution."
        # (https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/worker-src)
        return resolve(worker_src, child_src, script_src, fallback=self.default_src)

    def loads_unverified(self) -> ExprRef:
        return cast(
            ExprRef,
            Or(
                permits_unverified(self.script_src),
                permits_unverified(self.script_src_elem),
                permits_unverified(self.style_src),
                permits_unverified(self.style_src_elem),
                permits_unverified(self.object_src),
                permits_unverified(self.frame_src),
                permits_unverified(self.child_src),
                permits_unverified(self.worker_src),
            ),
        )


class WEBCAT:
    @property
    def default_src_valid(self) -> ExprRef:
        # https://docs.webcat.tech/developers/CSP.html#default-src
        return restricted_to(default_src, SELF, NONE)

    @property
    def script_src_valid(self) -> ExprRef:
        # https://docs.webcat.tech/developers/CSP.html#script-src-script-src-elem
        # TODO: sha256-/sha384-/sha512-xxx hash sources
        return restricted_to(script_src, NONE, SELF, WASM_UNSAFE_EVAL)

    @property
    def script_src_elem_valid(self) -> ExprRef:
        # https://docs.webcat.tech/developers/CSP.html#script-src-script-src-elem
        # TODO: sha256-/sha384-/sha512-xxx hash sources
        return restricted_to(script_src_elem, NONE, SELF, WASM_UNSAFE_EVAL)

    @property
    def style_src_valid(self) -> ExprRef:
        # https://docs.webcat.tech/developers/CSP.html#style-src-style-src-elem
        # TODO: sha256-/sha384-/sha512-xxx hash sources
        # TODO: unsafe-{inline,hashes}
        return restricted_to(style_src, NONE, SELF)

    @property
    def style_src_elem_valid(self) -> ExprRef:
        # https://docs.webcat.tech/developers/CSP.html#style-src-style-src-elem
        # TODO: sha256-/sha384-/sha512-xxx hash sources
        # TODO: unsafe-{inline,hashes}
        return restricted_to(style_src_elem, NONE, SELF)

    @property
    def object_src_valid(self) -> ExprRef:
        # https://docs.webcat.tech/developers/CSP.html#object-src
        return cast(
            ExprRef,
            And(
                restricted_to(object_src, NONE),
                Implies(Not(is_none(default_src)), is_none(object_src)),
            ),
        )

    @property
    def frame_src_valid(self) -> ExprRef:
        # https://docs.webcat.tech/developers/CSP.html#frame-src-child-src
        # TODO: blob
        # TODO: data
        # TODO: external
        return restricted_to(frame_src, NONE, SELF)

    @property
    def child_src_valid(self) -> ExprRef:
        # https://docs.webcat.tech/developers/CSP.html#frame-src-child-src
        # TODO: blob
        # TODO: data
        # TODO: external
        return restricted_to(child_src, NONE, SELF)

    @property
    def worker_src_valid(self) -> ExprRef:
        # https://docs.webcat.tech/developers/CSP.html#worker-src
        return cast(
            ExprRef,
            And(
                restricted_to(worker_src, NONE, SELF),
                Implies(
                    Not(is_none(default_src)),
                    Directive.is_present(worker_src),  # pyright: ignore[reportAttributeAccessIssue]
                ),
            ),
        )

    def valid(self) -> ExprRef:
        return cast(
            ExprRef,
            And(
                # "Either one of the two must be set if `default-src` is not
                # `none`, otherwise it can be omitted."
                Implies(
                    Not(is_none(default_src)),
                    Or(
                        Directive.is_present(frame_src),  # pyright: ignore[reportAttributeAccessIssue]
                        Directive.is_present(child_src),  # pyright: ignore[reportAttributeAccessIssue]
                    ),
                ),
                self.default_src_valid,
                self.script_src_valid,
                self.script_src_elem_valid,
                self.style_src_valid,
                self.style_src_elem_valid,
                self.object_src_valid,
                self.frame_src_valid,
                self.child_src_valid,
                self.worker_src_valid,
            ),
        )
