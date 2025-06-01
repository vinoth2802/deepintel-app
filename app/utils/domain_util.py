from datetime import datetime

import os
import sys


def domain_tld(domain):
    """Extracts the top-level domain (TLD) from a given domain name."""

    # This function attempts to parse the domain using the `tld` library. If the library is not available,
    try:
        from tld import parse_tld
    except ImportError:
        # Fallback to a simple split method if the library is not available

        ctld = ['org', 'com', 'net', 'gov', 'edu', 'co', 'mil', 'nom', 'ac', 'info', 'biz', 'ne']

        # Split the domain into parts
        d = domain.rsplit('.', 3)

        # Handle cases based on the number of parts in the domain
        if len(d) < 2:
            return '', d[0], ''
        if len(d) == 2:
            return '', d[0], d[1]
        if len(d) > 2:
            if d[-2] in ctld:
                return '.'.join(d[:-3]), d[-3], '.'.join(d[-2:])
            else:
                return '.'.join(d[:-2]), d[-2], d[-1]
        return None
    else:
        d = parse_tld(domain, fix_protocol=True)[::-1]
        if d[1:] == d[:-1] and None in d:
            d = tuple(domain.rsplit('.', 2))
            d = ('',) * (3 - len(d)) + d
        return d


def _debug(msg):
    if 'DEBUG' in os.environ:
        if isinstance(msg, Exception):
            print('{}:{} {}'.format(__file__, msg.__traceback__.tb_lineno, str(msg)), file=sys.stderr, flush=True)
        else:
            print(str(msg), file=sys.stderr, flush=True)



def convert_dates_to_strings(data):
    """Recursively convert datetime objects to string format (ISO)."""
    if isinstance(data, dict):
        return {key: convert_dates_to_strings(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_dates_to_strings(item) for item in data]
    elif isinstance(data, datetime):
        return data.isoformat()  # Convert datetime to ISO format string
    else:
        return data  # Return the data as-is if it's not a datetime

def convert_strings_to_dates(data):
    """Recursively convert ISO date strings back to datetime objects."""
    if isinstance(data, dict):
        return {key: convert_strings_to_dates(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_strings_to_dates(item) for item in data]
    elif isinstance(data, str):
        # Attempt to convert strings to datetime objects if they follow the ISO format
        try:
            # Check if the string follows ISO format and try to convert
            return datetime.fromisoformat(data)
        except (ValueError, TypeError):
            return data  # Return the string if it can't be converted
    else:
        return data  # Return the data as-is if it's not a string