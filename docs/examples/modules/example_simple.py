#!/usr/bin/env python3
"""
Example Simple Module - Cygor Module Development Template
==========================================================

This is a minimal example showing how to create a cygor enumeration module
using the new CygorModule base class and cygor-result.json output format.

Usage:
    # Run from cygor CLI
    cygor enum example_simple -t 192.168.1.100
    cygor enum example_simple -f targets.txt

    # Run standalone
    python -m cygor.modules.example_simple -t 192.168.1.100

Output:
    - cygor-result.json (primary, with embedded schema for web UI)
    - example_simple-results.csv
    - example_simple-results.xml
    - example_simple-results.txt
"""

from cygor.modules.base import CygorModule


class ExampleSimpleModule(CygorModule):
    """
    A minimal example module that demonstrates the new module architecture.

    This module simply pings targets and records their reachability status.
    Replace the run() method with your own enumeration logic.
    """

    # Required: Module identification
    name = "Example Simple Scanner"
    slug = "example_simple"

    # Optional: Module metadata
    version = "1.0.0"
    author = "Cygor Developer"
    description = "A minimal example module demonstrating the new architecture"
    category = "enumeration"  # Options: screenshots, network-shares, enumeration, credentials, custom

    # Required: View type determines how results are displayed in web UI
    view = "table"  # Options: table, gallery, mixed

    # Required: Column definitions for the results table
    # Each column has: key (JSON key), label (display name), type (rendering type)
    # Types: string, ip, url, badge, code, screenshot
    columns = [
        {"key": "host", "label": "Host", "type": "ip"},
        {"key": "status", "label": "Status", "type": "badge"},
        {"key": "response_time", "label": "Response Time", "type": "string"},
        {"key": "notes", "label": "Notes", "type": "string"},
    ]

    def run(self, targets: list, **kwargs) -> None:
        """
        Execute the module against targets.

        This is the main method you implement. Use:
        - self.add_result({...}) to collect results
        - self.add_screenshot("filename.png") for gallery modules
        - self.increment_errors() for tracking failures

        Args:
            targets: List of target hosts/IPs/URLs
            **kwargs: Additional arguments from CLI (e.g., verbose)
        """
        import subprocess
        import time

        verbose = kwargs.get("verbose", 0)

        for target in targets:
            try:
                # Example: ping the target
                start = time.time()

                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "2", target],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                elapsed = round((time.time() - start) * 1000, 2)  # ms

                if result.returncode == 0:
                    status = "UP"
                    notes = "Host responded to ICMP ping"
                else:
                    status = "DOWN"
                    notes = "No response"
                    self.increment_errors()

                # Add the result
                self.add_result({
                    "host": target,
                    "status": status,
                    "response_time": f"{elapsed}ms" if status == "UP" else "N/A",
                    "notes": notes,
                })

                if verbose >= 1:
                    print(f"[+] {target}: {status} ({elapsed}ms)")

            except subprocess.TimeoutExpired:
                self.add_result({
                    "host": target,
                    "status": "TIMEOUT",
                    "response_time": "N/A",
                    "notes": "Ping timed out",
                })
                self.increment_errors()

            except Exception as e:
                self.add_result({
                    "host": target,
                    "status": "ERROR",
                    "response_time": "N/A",
                    "notes": str(e),
                })
                self.increment_errors()

    def setup_argparser(self, parser) -> None:
        """
        Add module-specific CLI arguments.

        Override this method to add custom arguments beyond the defaults.
        The base class provides: -t/--target, -f/--file, -o/--output-dir, --format

        Args:
            parser: argparse.ArgumentParser instance
        """
        # Example: add a custom timeout argument
        parser.add_argument(
            "--ping-timeout",
            type=int,
            default=2,
            help="Ping timeout in seconds (default: 2)"
        )


# Module info for legacy loader compatibility
module_info = {
    "name": ExampleSimpleModule.name,
    "slug": ExampleSimpleModule.slug,
    "version": ExampleSimpleModule.version,
    "author": ExampleSimpleModule.author,
    "description": ExampleSimpleModule.description,
    "module_type": "enumeration",
    "category": ExampleSimpleModule.category,
    "view": ExampleSimpleModule.view,
    "template": "modules_unified.html",
    "table": {"columns": ExampleSimpleModule.columns},
}


# Entry point for standalone execution
if __name__ == "__main__":
    ExampleSimpleModule().cli()
