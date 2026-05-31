from typing import cast

from z3 import And, Const, ExprRef, Or, EnumSort, If


# https://www.w3.org/TR/CSP3/#grammardef-serialized-source-list
# - ⊤: any value not specifically enumerated
# - ⊥: absent; resolve via fallback
SerializedSourceList, (NONE, SELF, WASM_UNSAFE_EVAL, TOP, BOT) = EnumSort(
    "serialized-source-list", ["none", "self", "wasm_unsafe_eval", "⊤", "⊥"]
)

default_src = Const("default-src", SerializedSourceList)
object_src = Const("object-src", SerializedSourceList)
script_src = Const("script-src", SerializedSourceList)


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

    @property
    def default_src(self) -> ExprRef:
        return self._default_src

    @property
    def default_src_valid(self):
        # https://docs.webcat.tech/developers/CSP.html#default-src
        return Or(self.default_src == SELF, self.default_src == NONE)

    @property
    def object_src(self) -> ExprRef:
        return self._object_src

    @property
    def object_src_valid(self):
        # https://docs.webcat.tech/developers/CSP.html#object-src
        return Or(
            self.object_src == NONE,
            And(self.object_src == BOT, self.default_src == NONE),
        )

    @property
    def script_src(self) -> ExprRef:
        return self._script_src

    @property
    def script_src_valid(self):
        # https://docs.webcat.tech/developers/CSP.html#script-src-script-src-elem
        return Or(
            self.script_src == SELF,
            self.script_src == NONE,
            self.script_src == WASM_UNSAFE_EVAL,
        )

    def valid(self):
        return And(
            self.default_src_valid,
            self.object_src_valid,
            self.script_src_valid,
        )


class EffectivePolicy(Policy):
    @property
    def default_src(self) -> ExprRef:
        return cast(ExprRef, If(self._default_src == BOT, TOP, self._default_src))

    @property
    def object_src(self) -> ExprRef:
        return cast(
            ExprRef, If(self._object_src == BOT, self.default_src, self._object_src)
        )

    @property
    def script_src(self) -> ExprRef:
        return cast(
            ExprRef, If(self._script_src == BOT, self.default_src, self._script_src)
        )

    def allows(self, obj):
        return Or(
            self.object_src == obj,
            self.script_src == obj,
        )
