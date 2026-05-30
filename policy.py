from z3 import And, Or, EnumSort, If


# https://www.w3.org/TR/CSP3/#grammardef-serialized-source-list
# - ⊤: any value not specifically enumerated
# - ⊥: absent; resolve via fallback
SerializedSourceList, (NONE, SELF, WASM_UNSAFE_EVAL, TOP, BOT) = EnumSort(
    "serialized-source-list", ["none", "self", "wasm_unsafe_eval", "⊤", "⊥"]
)


class Policy:
    def __init__(self, default_src=BOT, object_src=BOT, script_src=BOT):
        # TODO: `'self' 'none'` (freedomofpress/webcat#99)
        self._default_src = default_src

        self._object_src = object_src

        # TODO:
        # - sha256-xxx
        # - sha384-xxx
        # - sha512-xxx
        # FIXME: `'self' 'wasm-unsafe-eval`'
        self._script_src = script_src

    @property
    def default_src(self):
        return self._default_src

    @property
    def default_src_valid(self):
        # https://docs.webcat.tech/developers/CSP.html#default-src
        return Or(self.default_src == SELF, self.default_src == NONE)

    @property
    def object_src(self):
        return self._object_src

    @property
    def object_src_valid(self):
        # https://docs.webcat.tech/developers/CSP.html#object-src
        return Or(
            self.object_src == NONE,
            And(self.object_src == BOT, self.default_src == NONE),
        )

    @property
    def script_src(self):
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
    def default_src(self):
        return If(self._default_src == BOT, TOP, self._default_src)

    @property
    def object_src(self):
        return If(self._object_src == BOT, self.default_src, self._object_src)

    @property
    def script_src(self):
        return If(self._script_src == BOT, self.default_src, self._script_src)

    def executes(self, c):
        return Or(
            self.object_src == TOP,
            self.script_src == WASM_UNSAFE_EVAL,
            self.script_src == TOP,
        )
