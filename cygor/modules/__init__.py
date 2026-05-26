"""
Cygor Enumeration Modules
=========================

Service enumeration modules live here. Modules can either:
1. Use the CygorModule base class for automatic CLI/export/schema handling
2. Write cygor-result.json directly (for raw scripts or wrappers)

Quick Start (Base Class):

    from cygor.modules.base import CygorModule

    class MyScanner(CygorModule):
        name = "My Scanner"
        slug = "myscanner"
        view = "table"
        columns = [{"key": "host", "label": "Host", "type": "ip"}]

        def run(self, targets, **kwargs):
            for t in targets:
                self.add_result({"host": t, "status": "scanned"})

    if __name__ == "__main__":
        MyScanner().cli()

Quick Start (Raw JSON):

    import json
    from cygor.modules.schema import CygorResult, ModuleInfo, SchemaDefinition

    result = CygorResult(
        module=ModuleInfo(name="My Tool", slug="mytool"),
        schema=SchemaDefinition(view="table", columns=[...]),
        results=[{"host": "192.168.1.1"}]
    )
    result.save("cygor-result.json")
"""

# Core components
from .schema import (
    CygorResult,
    ModuleInfo,
    SchemaDefinition,
    ColumnDefinition,
    RunMetadata,
    AssetReferences,
    ViewType,
    ColumnType,
    ModuleCategory,
    make_column,
    make_table_schema,
    make_gallery_schema,
    get_common_column,
    COMMON_COLUMNS,
)

from .base import CygorModule, wrap_external, get_module_info

from .exporters import (
    export_to_csv,
    export_to_xml,
    export_to_txt,
    export_to_json,
    export_results,
)

__all__ = [
    # Schema
    "CygorResult",
    "ModuleInfo",
    "SchemaDefinition",
    "ColumnDefinition",
    "RunMetadata",
    "AssetReferences",
    "ViewType",
    "ColumnType",
    "ModuleCategory",
    "make_column",
    "make_table_schema",
    "make_gallery_schema",
    "get_common_column",
    "COMMON_COLUMNS",
    # Base class
    "CygorModule",
    "wrap_external",
    "get_module_info",
    # Exporters
    "export_to_csv",
    "export_to_xml",
    "export_to_txt",
    "export_to_json",
    "export_results",
]
