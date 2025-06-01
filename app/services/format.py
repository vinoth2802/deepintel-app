import json


class Format:
    def __init__(self, domains=[]):
        self.domains = domains

    def json(self, indent=2, sort_keys=True):
        # Convert set to list before serializing
        if isinstance(self.domains, set):
            self.domains = list(self.domains)

        return json.dumps(self.domains, indent=indent, sort_keys=sort_keys)

    def csv(self):
        """
        Converts the domain data to a CSV string.
        """
        cols = ['fuzzer', 'domain']

        # Dynamically add other keys (columns) found in the domain data
        for domain in self.domains:
            for k in domain.keys() - cols:
                cols.append(k)

        # Sort the columns alphabetically after the 'domain' column
        cols = cols[:2] + sorted(cols[2:])

        # Initialize CSV with header row
        csv = [','.join(cols)]

        # Create a row for each domain
        for domain in self.domains:
            row = []
            for val in [domain.get(c, '') for c in cols]:
                if isinstance(val, str):
                    if ',' in val:
                        row.append('"{}"'.format(val))  # Wrap strings with commas in quotes
                    else:
                        row.append(val)
                elif isinstance(val, list):
                    row.append(';'.join(val))  # Join list items with semicolon
                elif isinstance(val, int):
                    row.append(str(val))  # Convert integers to string
            csv.append(','.join(row))

        return '\n'.join(csv)
