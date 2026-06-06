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
    IsMember,
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
object_src = Const("object-src", Directive)
script_src = Const("script-src", Directive)


def only(e: ExprRef, s: DatatypeSortRef) -> ArrayRef:
    """Return a set of sort `s` containing only the element `e`."""
    return SetAdd(EmptySet(s), e)


def srcs(directive: ExprRef) -> ExprRef:
    """Sources of `directive`, or ∅ when absent (keeps the accessor total)."""
    return cast(
        ExprRef,
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


def resolve(directive: ExprRef, fallback: ExprRef) -> ExprRef:
    return cast(
        ExprRef,
        If(
            Directive.is_absent(directive),  # pyright: ignore[reportAttributeAccessIssue]
            fallback,
            normalize(Directive.sources(directive)),  # pyright: ignore[reportAttributeAccessIssue]
        ),
    )


class Browser:
    @property
    def default(self) -> ExprRef:
        return resolve(default_src, only(TOP, Source))

    @property
    def object(self) -> ExprRef:
        return resolve(object_src, self.default)

    @property
    def script(self) -> ExprRef:
        return resolve(script_src, self.default)

    def allows_unsafe(self) -> ExprRef:
        return cast(ExprRef, Or(unsafe(self.object), unsafe(self.script)))


class WEBCAT:
    @property
    def default_valid(self) -> ExprRef:
        # https://docs.webcat.tech/developers/CSP.html#default-src
        return cast(
            ExprRef,
            Or(
                Directive.is_absent(default_src),  # pyright: ignore[reportAttributeAccessIssue]
                IsMember(SELF, srcs(default_src)),
                IsMember(NONE, srcs(default_src)),
            ),
        )

    @property
    def object_valid(self) -> ExprRef:
        # https://docs.webcat.tech/developers/CSP.html#object-src
        return cast(
            ExprRef,
            Or(
                IsMember(NONE, srcs(object_src)),
                And(
                    Directive.is_absent(object_src),  # pyright: ignore[reportAttributeAccessIssue]
                    IsMember(NONE, srcs(default_src)),
                ),
            ),
        )

    @property
    def script_valid(self) -> ExprRef:
        # https://docs.webcat.tech/developers/CSP.html#script-src-script-src-elem
        # TODO: sha256-/sha384-/sha512-xxx hash sources
        return cast(
            ExprRef,
            Or(
                Directive.is_absent(script_src),  # pyright: ignore[reportAttributeAccessIssue]
                IsMember(NONE, srcs(script_src)),
                IsMember(SELF, srcs(script_src)),
                IsMember(WASM_UNSAFE_EVAL, srcs(script_src)),
            ),
        )

    def valid(self) -> ExprRef:
        return cast(
            ExprRef, And(self.default_valid, self.object_valid, self.script_valid)
        )
