"""
AERIS HTML Sanitizer
======================
All user-controlled values that appear in unsafe_allow_html=True blocks
MUST pass through safe_html() before being interpolated into HTML strings.

This prevents XSS attacks where domain names or other user input
could contain HTML tags or JavaScript that would execute in the analyst's browser.
"""
import html
import re
from typing import Any


def safe_html(value: Any) -> str:
    """
    Escape a value for safe insertion into an HTML string.
    Converts all HTML special characters to entities.
    
    Usage:
        st.markdown(f'<div>{safe_html(user_domain)}</div>', unsafe_allow_html=True)
    """
    if value is None:
        return ''
    return html.escape(str(value), quote=True)


def safe_url(value: str) -> str:
    """
    Sanitize a URL for use in href/src attributes.
    Only allows http:// and https:// schemes.
    """
    value = str(value).strip()
    if not re.match(r'^https?://', value, re.IGNORECASE):
        return '#'
    return html.escape(value, quote=True)


def safe_monospace(value: Any, max_len: int = 200) -> str:
    """
    Escape and truncate a value for display in a monospace code context.
    """
    escaped = safe_html(value)
    if len(escaped) > max_len:
        escaped = escaped[:max_len] + '...'
    return escaped


def strip_html(value: str) -> str:
    """
    Remove all HTML tags from a string. For display contexts
    where HTML is not wanted at all.
    """
    return re.sub(r'<[^>]+>', '', str(value))
