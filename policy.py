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
Sources = SetSort(Source)

Directive = Datatype("directive")
Directive.declare("absent")
Directive.declare("present", ("sources", Sources))
Directive = Directive.create()

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


def unsafe(permission: ExprRef) -> ExprRef:
    # FIXME: clarify how to represent safe versus unsafe executions
    return cast(
        ExprRef, Or(permits(permission, TOP), permits(permission, WASM_UNSAFE_EVAL))
    )


def normalize(sources: ArrayRef) -> ArrayRef:
    # FIXME: webcat#99
    return SetDel(sources, NONE)


def restricted_to(directive: ExprRef, *allowed: ExprRef) -> ExprRef:
    permitted = EmptySet(Source)
    for source in allowed:
        permitted = SetAdd(permitted, source)
    return cast(ExprRef, IsSubset(srcs(directive), permitted))


def is_none(directive: ExprRef) -> ExprRef:
    return cast(
        ExprRef,
        And(
            Directive.is_present(directive),  # pyright: ignore[reportAttributeAccessIssue]
            normalize(srcs(directive)) == EmptySet(Source),
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
        return resolve(worker_src, child_src, script_src, fallback=self.default_src)

    def allows_unsafe(self) -> ExprRef:
        return cast(
            ExprRef,
            Or(
                unsafe(self.script_src),
                unsafe(self.script_src_elem),
                unsafe(self.style_src),
                unsafe(self.style_src_elem),
                unsafe(self.object_src),
                unsafe(self.frame_src),
                unsafe(self.child_src),
                unsafe(self.worker_src),
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
