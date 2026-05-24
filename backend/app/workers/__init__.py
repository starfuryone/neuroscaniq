"""Background workers.

All scan workers MUST call `app.core.scan_guard.assert_scan_allowed`
before issuing any network probe. See `scanner.py` for the canonical pattern.
"""
