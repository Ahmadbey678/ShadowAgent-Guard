# fixtures/

Payload templates used by `scripts/build_demo.py` to construct a separate,
deliberately-vulnerable demo git repository outside this repo. These are
test fixtures for exercising ShadowAgent Guard's checks — not real malware
and not real credentials.

This directory is listed in `.bobignore` so an IBM Bob agent working inside
*this* repo never ingests the injection text below as if it were an
instruction meant for it.
