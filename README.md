# webcat-csp-soundness

Does WEBCAT's validator block all content security policies that allow external code execution?

## Counterexample CLI

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the counterexample search:

```bash
python find_counterexample.py --show-query
```
