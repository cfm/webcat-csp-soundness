from typing import cast

from z3 import (
    And,
    ArrayRef,
    Const,
    DatatypeSortRef,
    Implies,
    ExprRef,
    Or,
    EmptySet,
    EnumSort,
    If,
    IsMember,
    SetAdd,
    SetSort,
)


# https://www.w3.org/TR/CSP3/#grammardef-serialized-source-list
# - ⊤: any value not specifically enumerated
# - ⊥: absent; resolve via fallback
SerializedSource, (NONE, SELF, WASM_UNSAFE_EVAL, TOP, BOT) = EnumSort(
    "serialized-source-list", ["none", "self", "wasm_unsafe_eval", "⊤", "⊥"]
)
SerializedSourceList = SetSort(SerializedSource)

default_src = Const("default-src", SerializedSourceList)
object_src = Const("object-src", SerializedSourceList)
script_src = Const("script-src", SerializedSourceList)


def only(e: ExprRef, s: DatatypeSortRef) -> ArrayRef:
    """Return a set of sort `s` containing only the element `e`"""
    return SetAdd(EmptySet(s), e)


class Policy:
    # TODO: `'self' 'none'` (freedomofpress/webcat#99)
    _default_src = default_src

    _object_src = object_src

    # TODO:
    # - sha256-xxx
    # - sha384-xxx
    # - sha512-xxx
    # FIXME: `'self' 'wasm-unsafe-eval`'
    _script_src = script_src

    def well_formed(self, directive):
        """⊥ CAN NOT coexist with any other values."""
        return Implies(
            IsMember(BOT, directive), directive == only(BOT, SerializedSource)
        )

    @property
    def default_src(self) -> ExprRef:
        return self._default_src

    @property
    def default_src_valid(self):
        # https://docs.webcat.tech/developers/CSP.html#default-src
        return Or(
            IsMember(BOT, self.default_src),  # absent
            IsMember(SELF, self.default_src),
            IsMember(NONE, self.default_src),
        )

    @property
    def object_src(self) -> ExprRef:
        return self._object_src

    @property
    def object_src_valid(self):
        # https://docs.webcat.tech/developers/CSP.html#object-src
        return Or(
            IsMember(NONE, self.object_src),
            And(
                IsMember(BOT, self.object_src),  # absent
                IsMember(NONE, self.default_src),
            ),
        )

    @property
    def script_src(self) -> ExprRef:
        return self._script_src

    @property
    def script_src_valid(self):
        # https://docs.webcat.tech/developers/CSP.html#script-src-script-src-elem
        return Or(
            IsMember(BOT, self.script_src),  # absent
            IsMember(NONE, self.script_src),
            IsMember(SELF, self.script_src),
            IsMember(WASM_UNSAFE_EVAL, self.script_src),
        )

    def valid(self):
        return And(
            self.well_formed(self.default_src),
            self.default_src_valid,
            self.well_formed(self.object_src),
            self.object_src_valid,
            self.well_formed(self.script_src),
            self.script_src_valid,
        )


class EffectivePolicy(Policy):
    @property
    def default_src(self) -> ExprRef:
        return cast(
            ExprRef,
            If(
                self._default_src == only(BOT, SerializedSource),
                only(TOP, SerializedSource),
                self._default_src,
            ),
        )

    @property
    def object_src(self) -> ExprRef:
        return cast(
            ExprRef,
            If(
                self._object_src == only(BOT, SerializedSource),
                self.default_src,
                self._object_src,
            ),
        )

    @property
    def script_src(self) -> ExprRef:
        return cast(
            ExprRef,
            If(
                self._script_src == only(BOT, SerializedSource),
                self.default_src,
                self._script_src,
            ),
        )

    def allows(self, obj):
        return Or(
            IsMember(obj, self.object_src),
            IsMember(obj, self.script_src),
        )
