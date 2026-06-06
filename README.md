# `webcat-csp-soundness`

CLI utility to find counterexamples for---

    WEBCAT.valid() ⇒ ¬Browser.loads_unverified()

---aka examples of---

    WEBCAT.valid() ∧ Browser.loads_unverified()

---i.e., a CSP that WEBCAT accepts as conformant whose real (browser)
interpretation still permits loading an asset that wasn't registered in the
site's manifest.

## CLI

Install dependencies:

```bash
pip3 install -r requirements.txt
```

Run the counterexample search:

```bash
python3 main.py
```
