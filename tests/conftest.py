"""
Stub out C-extension packages that can't be installed without system libraries
(python-ldap requires openldap-dev + gcc). Tests that use these modules must
mock them explicitly; this conftest only makes them importable.
"""
import sys
from unittest.mock import MagicMock

# Stub python-ldap and its sub-modules before any test file imports them
for mod in ('ldap', 'ldap.filter', 'ldap.ldapobject', 'ldap.dn'):
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()

# Provide escape_filter_chars as a simple passthrough if not already present
import ldap.filter  # noqa: E402  (now guaranteed importable)
if not callable(getattr(ldap.filter, 'escape_filter_chars', None)):
    ldap.filter.escape_filter_chars = lambda s, escape_mode=0: s
