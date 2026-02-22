# utils/helpers.py

def safe_getattr(obj, attr, default=None):
    """
    Safely get attribute from pyshark packet layer
    without crashing the pipeline.
    """
    try:
        return getattr(obj, attr)
    except:
        return default


def normalize_string(value):
    """
    Normalize strings for comparison (protocols, user agents).
    """
    if not value:
        return ""
    return str(value).strip().lower()