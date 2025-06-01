from typing import Any, Dict

# --- Permutation Class ---
# Stores results for a single domain permutation. Behaves like a dictionary
# but allows attribute-style access (e.g., p.domain instead of p['domain'])
# and defines specific hashing/comparison for use in sets and sorting.

class Permutation(dict):
    """
    Represents a single domain permutation result.

    Acts as a dictionary holding permutation data ('fuzzer', 'domain', etc.)
    but allows attribute-style access and defines custom hashing/comparison.
    """
    # Allow accessing dictionary keys via attribute access (e.g., perm.domain)
    def __getattr__(self, item: str) -> Any:
       try:
          return self[item]
       except KeyError:
          # Raise AttributeError for missing attributes, consistent with standard objects
          raise AttributeError(f"'{type(self).__name__}' object has no attribute '{item}'") from None

    # Allow setting dictionary items via attribute access (e.g., perm.notes = '...')
    __setattr__ = dict.__setitem__

    def __init__(self, **kwargs: Any):
       """
       Initialize the Permutation object.

       Args:
          fuzzer (str): Name of the fuzzer that generated this permutation. Defaults to ''.
          domain (str): The generated domain name string. Defaults to ''.
          **kwargs: Any additional data associated with the permutation (e.g., DNS records).
       """
       super().__init__() # Initialize the underlying dictionary
       # Ensure 'fuzzer' and 'domain' keys always exist
       self['fuzzer'] = kwargs.pop('fuzzer', '')
       self['domain'] = kwargs.pop('domain', '')
       # Add any other provided key-value pairs
       self.update(kwargs)

    def __hash__(self) -> int:
       """Hash based solely on the domain string for uniqueness in sets."""
       return hash(self.get('domain', '')) # Use .get for safety, though domain should exist

    def __eq__(self, other: object) -> bool:
       """Equality based solely on the domain string."""
       if not isinstance(other, dict): # Can compare with dicts or Permutation instances
             return NotImplemented
       return self.get('domain', '') == other.get('domain', '')

    def __lt__(self, other: 'Permutation') -> bool:
       """Comparison for sorting: primarily by fuzzer, secondarily by domain/DNS."""
       if not isinstance(other, Permutation):
             return NotImplemented

       # 1. Sort by fuzzer name
       if self.fuzzer != other.fuzzer:
             return self.fuzzer < other.fuzzer

       # 2. If fuzzers are the same, sort by domain (potentially prefixed with DNS A record)
       # Use is_registered() for clarity, though it checks length internally
       self_registered = self.is_registered()
       other_registered = other.is_registered()

       if self_registered and other_registered:
             # If both seem registered (have extra data), try sorting by first A record + domain
             self_a_rec = self.get('dns_a', [''])[0] if self.get('dns_a') else ''
             other_a_rec = other.get('dns_a', [''])[0] if other.get('dns_a') else ''
             return (self_a_rec + self.domain) < (other_a_rec + other.domain)
       else:
             # Otherwise (if one or both lack extra data), sort just by domain name
             return self.domain < other.domain

    def is_registered(self) -> bool:
       """
       Infers registration status based on presence of extra data.

       Returns True if the object has more than the default 2 keys ('fuzzer', 'domain'),
       implying that DNS lookup or other data enrichment likely occurred.
       """
       return len(self) > 2

    def copy(self) -> 'Permutation':
       """Return a shallow copy of this Permutation object."""
       # Pass current items as kwargs to the constructor
       return Permutation(**self)

    def __repr__(self) -> str:
        """Provide a helpful representation."""
        # Show fuzzer and domain prominently, then other items
        core_items = f"fuzzer='{self.fuzzer}', domain='{self.domain}'"
        other_items = ", ".join(f"{k}='{v}'" for k, v in self.items() if k not in ('fuzzer', 'domain'))
        items_str = core_items + (f", {other_items}" if other_items else "")
        return f"{type(self).__name__}({items_str})"