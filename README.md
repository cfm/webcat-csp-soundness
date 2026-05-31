# `webcat-csp-soundness`

CLI utility to find counterexamples for—

    Policy.valid() ⇒ ¬EffectivePolicy.allows(obj)

—aka examples of:

    Policy.valid() ∧ EffectivePolicy.allows(obj)

## Counterexample CLI

Install dependencies:

```bash
pip3 install -r requirements.txt
```

Run the counterexample search:

```bash
python3 main.py
```
