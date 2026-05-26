r"""
Advanced search query parser for Cygor.

Supports field-specific queries, boolean operators, and regex patterns.

Syntax Examples:
    ip:192.168.1.0/24           - CIDR notation
    port:22                      - Specific port
    port:80-443                  - Port range
    service:ssh                  - Service name
    banner:"OpenSSH"             - Banner text (quoted)
    os:Windows                   - OS detection
    script:ssl-cert              - Script name
    ip:192.168.1.1 AND port:22   - Boolean AND
    service:http OR service:https - Boolean OR
    NOT port:22                  - Boolean NOT
    banner:/Apache.*2\.4/        - Regex pattern
"""

import re
import ipaddress
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class QueryOperator(Enum):
    AND = "AND"
    OR = "OR"
    NOT = "NOT"


class SearchField(Enum):
    IP = "ip"
    PORT = "port"
    SERVICE = "service"
    BANNER = "banner"
    OS = "os"
    SCRIPT = "script"
    HOSTNAME = "hostname"
    PROTOCOL = "protocol"
    STATUS_CODE = "status"


@dataclass
class QueryTerm:
    """Represents a single search term."""
    field: Optional[SearchField]
    value: str
    is_regex: bool = False
    is_negated: bool = False
    operator_before: Optional[QueryOperator] = None


@dataclass
class PortRange:
    """Represents a port range."""
    min_port: int
    max_port: int


class SearchQueryParser:
    """Parse advanced search queries into structured terms."""

    # Regex patterns
    FIELD_PATTERN = re.compile(r'(\w+):')
    QUOTED_PATTERN = re.compile(r'"([^"]*)"')
    REGEX_PATTERN = re.compile(r'/([^/]+)/')
    CIDR_PATTERN = re.compile(r'(\d{1,3}\.){3}\d{1,3}/\d{1,2}')
    PORT_RANGE_PATTERN = re.compile(r'(\d+)-(\d+)')

    def __init__(self, query: str):
        self.raw_query = query.strip()
        self.terms: List[QueryTerm] = []
        self.port_range: Optional[PortRange] = None

    def parse(self) -> List[QueryTerm]:
        """Parse the query string into structured terms."""
        if not self.raw_query:
            return []

        # Tokenize the query
        tokens = self._tokenize(self.raw_query)

        # Process tokens into terms
        current_operator = None
        is_negated = False

        i = 0
        while i < len(tokens):
            token = tokens[i]

            # Check for operators
            if token.upper() in ["AND", "OR"]:
                current_operator = QueryOperator[token.upper()]
                i += 1
                continue
            elif token.upper() == "NOT":
                is_negated = True
                i += 1
                continue

            # Parse field:value terms
            if ':' in token:
                field_str, value = token.split(':', 1)
                field = self._parse_field(field_str)

                if field:
                    # Handle special field types
                    if field == SearchField.PORT:
                        self._parse_port_value(value)

                    # Check if value is regex
                    is_regex = value.startswith('/') and value.endswith('/')
                    if is_regex:
                        value = value[1:-1]  # Strip regex markers

                    # Remove quotes
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]

                    term = QueryTerm(
                        field=field,
                        value=value,
                        is_regex=is_regex,
                        is_negated=is_negated,
                        operator_before=current_operator
                    )
                    self.terms.append(term)
                else:
                    # Not a valid field, treat as general search
                    term = QueryTerm(
                        field=None,
                        value=token,
                        is_negated=is_negated,
                        operator_before=current_operator
                    )
                    self.terms.append(term)
            else:
                # General search term
                # Remove quotes if present
                value = token
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]

                term = QueryTerm(
                    field=None,
                    value=value,
                    is_negated=is_negated,
                    operator_before=current_operator
                )
                self.terms.append(term)

            # Reset for next term
            current_operator = QueryOperator.AND if current_operator is None else None
            is_negated = False
            i += 1

        return self.terms

    def _tokenize(self, query: str) -> List[str]:
        """Tokenize the query string, preserving quoted strings and field:value pairs."""
        tokens = []
        current_token = ""
        in_quotes = False
        in_regex = False

        i = 0
        while i < len(query):
            char = query[i]

            if char == '"' and not in_regex:
                in_quotes = not in_quotes
                current_token += char
            elif char == '/' and (i == 0 or query[i-1] == ' ' or query[i-1] == ':'):
                in_regex = not in_regex
                current_token += char
            elif char == ' ' and not in_quotes and not in_regex:
                if current_token:
                    tokens.append(current_token)
                    current_token = ""
            else:
                current_token += char

            i += 1

        if current_token:
            tokens.append(current_token)

        return tokens

    def _parse_field(self, field_str: str) -> Optional[SearchField]:
        """Parse a field string into a SearchField enum."""
        try:
            return SearchField(field_str.lower())
        except ValueError:
            return None

    def _parse_port_value(self, value: str):
        """Parse port value, handling ranges."""
        # Check for port range
        match = self.PORT_RANGE_PATTERN.match(value)
        if match:
            min_port = int(match.group(1))
            max_port = int(match.group(2))
            self.port_range = PortRange(min_port=min_port, max_port=max_port)
        else:
            # Single port
            try:
                port = int(value)
                self.port_range = PortRange(min_port=port, max_port=port)
            except ValueError:
                pass

    def get_filters(self) -> Dict[str, Any]:
        """Convert parsed terms into filter dictionary."""
        filters = {
            'terms': [],
            'ip_addresses': [],
            'cidr_ranges': [],
            'ports': [],
            'port_ranges': [],
            'services': [],
            'banners': [],
            'os_filters': [],
            'scripts': [],
            'hostnames': [],
            'protocols': [],
            'status_codes': [],
            'regex_patterns': []
        }

        for term in self.terms:
            if term.field == SearchField.IP:
                # Check if it's a CIDR
                if '/' in term.value:
                    try:
                        network = ipaddress.ip_network(term.value, strict=False)
                        filters['cidr_ranges'].append({
                            'network': network,
                            'negated': term.is_negated
                        })
                    except ValueError:
                        pass
                else:
                    filters['ip_addresses'].append({
                        'value': term.value,
                        'negated': term.is_negated
                    })

            elif term.field == SearchField.PORT:
                if term.is_regex:
                    filters['regex_patterns'].append({
                        'field': 'port',
                        'pattern': term.value,
                        'negated': term.is_negated
                    })
                else:
                    # Check for range in value
                    if '-' in term.value:
                        parts = term.value.split('-')
                        try:
                            filters['port_ranges'].append({
                                'min': int(parts[0]),
                                'max': int(parts[1]),
                                'negated': term.is_negated
                            })
                        except ValueError:
                            pass
                    else:
                        try:
                            filters['ports'].append({
                                'value': int(term.value),
                                'negated': term.is_negated
                            })
                        except ValueError:
                            pass

            elif term.field == SearchField.SERVICE:
                filters['services'].append({
                    'value': term.value,
                    'regex': term.is_regex,
                    'negated': term.is_negated
                })

            elif term.field == SearchField.BANNER:
                filters['banners'].append({
                    'value': term.value,
                    'regex': term.is_regex,
                    'negated': term.is_negated
                })

            elif term.field == SearchField.OS:
                filters['os_filters'].append({
                    'value': term.value,
                    'regex': term.is_regex,
                    'negated': term.is_negated
                })

            elif term.field == SearchField.SCRIPT:
                filters['scripts'].append({
                    'value': term.value,
                    'regex': term.is_regex,
                    'negated': term.is_negated
                })

            elif term.field == SearchField.HOSTNAME:
                filters['hostnames'].append({
                    'value': term.value,
                    'regex': term.is_regex,
                    'negated': term.is_negated
                })

            elif term.field == SearchField.PROTOCOL:
                filters['protocols'].append({
                    'value': term.value,
                    'negated': term.is_negated
                })

            elif term.field == SearchField.STATUS_CODE:
                try:
                    filters['status_codes'].append({
                        'value': int(term.value),
                        'negated': term.is_negated
                    })
                except ValueError:
                    pass

            else:
                # General term (no field specified)
                filters['terms'].append({
                    'value': term.value,
                    'operator': term.operator_before.value if term.operator_before else 'AND',
                    'negated': term.is_negated
                })

        # Add port range if specified
        if self.port_range:
            filters['port_ranges'].append({
                'min': self.port_range.min_port,
                'max': self.port_range.max_port,
                'negated': False
            })

        return filters


def parse_search_query(query: str) -> Dict[str, Any]:
    """
    Parse a search query string and return structured filters.

    Args:
        query: The search query string

    Returns:
        Dictionary containing parsed filters
    """
    parser = SearchQueryParser(query)
    parser.parse()
    return parser.get_filters()
