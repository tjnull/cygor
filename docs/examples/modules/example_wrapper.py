#!/usr/bin/env python3
"""
Example Wrapper Module - Wrapping External Tools for Cygor
============================================================

This example shows how to wrap an external command-line tool (like nmap, nikto, etc.)
and produce cygor-result.json output for integration with the web UI.

This pattern is useful when:
- You want to integrate an existing tool into cygor
- The tool produces output you need to parse
- You want consistent output format across different tools

Usage:
    cygor enum example_wrapper -t 192.168.1.100
    cygor enum example_wrapper -f targets.txt

Requirements:
    - dig (DNS lookup utility) - usually pre-installed on Linux
"""

from cygor.modules.base import CygorModule, wrap_external


class DNSLookupModule(CygorModule):
    """
    Example module that wraps the 'dig' command for DNS lookups.

    This demonstrates how to:
    1. Call an external tool using wrap_external()
    2. Parse the output
    3. Produce standardized cygor results
    """

    name = "DNS Lookup (dig wrapper)"
    slug = "example_wrapper"
    version = "1.0.0"
    author = "Cygor Developer"
    description = "Performs DNS lookups using dig and reports the results"
    category = "enumeration"
    view = "table"

    columns = [
        {"key": "query", "label": "Query", "type": "string"},
        {"key": "record_type", "label": "Type", "type": "badge"},
        {"key": "answer", "label": "Answer", "type": "ip"},
        {"key": "ttl", "label": "TTL", "type": "string"},
        {"key": "status", "label": "Status", "type": "badge"},
    ]

    def run(self, targets: list, **kwargs) -> None:
        """
        Run DNS lookups against targets using dig.

        Args:
            targets: List of domains/hostnames to look up
            **kwargs: Additional arguments (record_type, verbose)
        """
        record_type = kwargs.get("record_type", "A")
        verbose = kwargs.get("verbose", 0)

        for target in targets:
            try:
                if verbose >= 1:
                    print(f"[*] Looking up {record_type} record for {target}")

                # Use wrap_external to run the command
                result = wrap_external(
                    ["dig", "+short", target, record_type],
                    timeout=10,
                )

                if result.returncode == 0 and result.stdout.strip():
                    # Parse the dig output (one answer per line)
                    answers = result.stdout.strip().split("\n")
                    for answer in answers:
                        answer = answer.strip()
                        if answer:
                            self.add_result({
                                "query": target,
                                "record_type": record_type,
                                "answer": answer,
                                "ttl": "N/A",  # dig +short doesn't show TTL
                                "status": "RESOLVED",
                            })
                            if verbose >= 1:
                                print(f"  [+] {answer}")
                else:
                    # No results or error
                    self.add_result({
                        "query": target,
                        "record_type": record_type,
                        "answer": "NXDOMAIN",
                        "ttl": "N/A",
                        "status": "NOT_FOUND",
                    })
                    self.increment_errors()
                    if verbose >= 1:
                        print(f"  [-] No records found")

            except Exception as e:
                self.add_result({
                    "query": target,
                    "record_type": record_type,
                    "answer": "",
                    "ttl": "",
                    "status": f"ERROR: {e}",
                })
                self.increment_errors()

    def setup_argparser(self, parser) -> None:
        """Add DNS-specific arguments."""
        parser.add_argument(
            "--record-type", "-r",
            default="A",
            choices=["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"],
            help="DNS record type to query (default: A)"
        )


# Module info for legacy loader
module_info = {
    "name": DNSLookupModule.name,
    "slug": DNSLookupModule.slug,
    "version": DNSLookupModule.version,
    "author": DNSLookupModule.author,
    "description": DNSLookupModule.description,
    "module_type": "enumeration",
    "category": DNSLookupModule.category,
    "view": DNSLookupModule.view,
    "template": "modules_unified.html",
    "table": {"columns": DNSLookupModule.columns},
}


if __name__ == "__main__":
    DNSLookupModule().cli()
