# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import json
import requests
import argparse
import logging
import contextvars
import functools
import inspect

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8179/"

logger = logging.getLogger(__name__)

active_program = contextvars.ContextVar("ghidra_active_program", default=None)

class ProgramAwareFastMCP(FastMCP):
    def tool(self, name=None, title=None, description=None, annotations=None, icons=None, meta=None, structured_output=None):
        register = super().tool(name=name, title=title, description=description, annotations=annotations, icons=icons, meta=meta, structured_output=structured_output)

        def decorator(fn):
            if fn.__name__ in {"get_open_programs", "switch_program"}:
                return register(fn)
            signature = inspect.signature(fn)
            if "program" in signature.parameters:
                return register(fn)
            program_parameter = inspect.Parameter("program", inspect.Parameter.KEYWORD_ONLY, annotation=str)
            parameters = list(signature.parameters.values())
            for index, parameter in enumerate(parameters):
                if parameter.kind is inspect.Parameter.VAR_KEYWORD:
                    parameters.insert(index, program_parameter)
                    break
            else:
                parameters.append(program_parameter)

            @functools.wraps(fn)
            def wrapped(*args, program, **kwargs):
                token = active_program.set(program)
                try:
                    return fn(*args, **kwargs)
                finally:
                    active_program.reset(token)

            wrapped.__annotations__ = {**getattr(fn, "__annotations__", {}), "program": str}
            wrapped.__signature__ = signature.replace(parameters=parameters)
            return register(wrapped)

        return decorator

mcp = ProgramAwareFastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    params = {**(params or {})}
    program = active_program.get()
    if program:
        params["program"] = program

    url = f"{ghidra_server_url}/{endpoint}"

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {e!r}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    params = {"program": active_program.get()} if active_program.get() else None
    try:
        if isinstance(data, dict):
            response = requests.post(f"{ghidra_server_url}/{endpoint}", params=params, json=data, timeout=5)
        else:
            response = requests.post(f"{ghidra_server_url}/{endpoint}", params=params, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {e!r}"

def safe_post_json(endpoint: str, data: dict) -> dict:
    params = {"program": active_program.get()} if active_program.get() else None
    try:
        response = requests.post(f"{ghidra_server_url}/{endpoint}", params=params, json=data, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            import json
            return json.loads(response.text)
        else:
            return {"error": f"Error {response.status_code}: {response.text.strip()}"}
    except Exception as e:
        return {"error": f"Request failed: {e!r}"}

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def search_strings(query: str = "", offset: int = 0, limit: int = 100) -> list:
    """
    Search for strings in the program. Returns list of "address: string" entries.
    """
    return safe_get("search_strings", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def search_bytes(pattern: str, limit: int = 100) -> list:
    """
    Search for byte patterns in the program. Pattern is hex bytes separated by spaces, use ? for wildcards.
    Example: "41 B8 88 13 00 00 E8 ? ? ? ?"
    """
    return safe_get("search_bytes", {"pattern": pattern, "limit": limit})

@mcp.tool()
def get_references(address: str) -> list:
    """
    Get all references to the specified address. Returns list of addresses that reference it.
    """
    return safe_get("get_references", {"address": address})

@mcp.tool()
def get_function_bytes(address: str, length: int = 32) -> dict:
    """
    Get raw bytes from a function's entry point. Returns hex string of bytes.
    Useful for extracting byte signatures for patching.
    """
    import json
    import requests
    url = f"{ghidra_server_url}/get_function_bytes"
    try:
        params = {"address": address, "length": length}
        program = active_program.get()
        if program:
            params["program"] = program
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return json.loads(response.text)
        else:
            return {"error": f"Error {response.status_code}: {response.text.strip()}"}
    except Exception as e:
        return {"error": f"Request failed: {e!r}"}

@mcp.tool()
def patch_bytes(address: str, bytes: str) -> str:
    """
    Patch bytes at the specified address. Takes hex bytes separated by spaces.
    Example: "B0 00 C3"
    """
    return safe_post("patch_bytes", {"address": address, "bytes": bytes})

@mcp.tool()
def get_strings_in_function(address: str) -> list:
    """
    Get all string literals referenced within a function.
    Returns list of "address: string" entries.
    """
    return safe_get("get_strings_in_function", {"address": address})

@mcp.tool()
def get_function_callers(address: str) -> list:
    """
    Get all functions that call the function at the specified address.
    Returns list of "call_address: caller_function_name" entries.
    """
    return safe_get("get_function_callers", {"address": address})

@mcp.tool()
def get_function_callees(address: str) -> list:
    """
    Get all functions called by the function at the specified address.
    Returns list of "target_address: callee_function_name" entries.
    """
    return safe_get("get_function_callees", {"address": address})

@mcp.tool()
def get_bytes_at(address: str, length: int = 32) -> dict:
    """
    Read raw bytes at any address (not just function start).
    Returns dict with address, bytes (hex string), and length.
    """
    response = safe_get("get_bytes_at", {"address": address, "length": length})
    if response and len(response) > 0:
        full_response = "\n".join(response)
        if full_response and not full_response.startswith("Error"):
            import json
            return json.loads(full_response)
    return {"error": "Failed to read bytes"}

@mcp.tool()
def disassemble_range(start: str, end: str) -> str:
    """
    Disassemble a range of addresses from start to end (inclusive).
    Returns assembly with bytes and instructions.
    """
    lines = safe_get("disassemble_range", {"start": start, "end": end})
    if isinstance(lines, list):
        return "\n".join(lines)
    return lines

@mcp.tool()
def export_binary(path: str) -> str:
    """
    Export the entire binary to a file.
    All initialized memory blocks will be written to the specified path.
    """
    return safe_post("export_binary", {"path": path})

@mcp.tool()
def get_function_params(address: str) -> list:
    """
    Get function parameters with types and register locations.
    Returns list of "type name (register)" entries.
    """
    return safe_get("get_function_params", {"address": address})

@mcp.tool()
def get_function_locals(address: str) -> list:
    """
    Get local variables for a function with types.
    Returns list of "type name (offset)" entries.
    """
    return safe_get("get_function_locals", {"address": address})

@mcp.tool()
def get_containing_block(address: str) -> dict:
    """
    Get memory block information for the address.
    Returns dict with name, start, end, size, permissions, etc.
    """
    response = safe_get("get_containing_block", {"address": address})
    if response and len(response) > 0:
        import json
        return json.loads(response[0])
    return {"error": "Failed to get block info"}

@mcp.tool()
def get_entry_points() -> list:
    """
    Get all entry points (external symbols).
    Returns list of "address: name" entries.
    """
    return safe_get("get_entry_points")

@mcp.tool()
def get_data_at(address: str) -> dict:
    """
    Get defined data at address (arrays, structs, etc).
    Returns dict with address, type, label, value.
    """
    response = safe_get("get_data_at", {"address": address})
    if response and len(response) > 0:
        import json
        return json.loads(response[0])
    return {"error": "No data at address"}

@mcp.tool()
def get_type_at(address: str) -> dict:
    """
    Get type information at address (data type or function).
    Returns dict with address, type, and related info.
    """
    response = safe_get("get_type_at", {"address": address})
    if response and len(response) > 0:
        import json
        return json.loads(response[0])
    return {"error": "No type at address"}

@mcp.tool()
def search_for_value(value: str) -> list:
    """
    Search for a hex value in all defined data.
    Returns list of "address: label" entries where value is found.
    """
    return safe_get("search_for_value", {"value": value})

@mcp.tool()
def get_xrefs_to(address: str) -> list:
    """
    Get detailed cross-references TO the specified address.
    Returns list with from, type, operator, function for each xref.
    """
    import json
    response = safe_get("get_xrefs_to", {"address": address})
    if response and len(response) > 0:
        full = "\n".join(response)
        if full.strip() and not full.startswith("Error"):
            try:
                return json.loads(full)
            except:
                pass
    return []

@mcp.tool()
def get_xrefs_from(address: str) -> list:
    """
    Get cross-references FROM the specified address.
    Returns list with to, type, operator for each xref.
    """
    import json
    response = safe_get("get_xrefs_from", {"address": address})
    if response and len(response) > 0:
        full = "\n".join(response)
        if full.strip() and not full.startswith("Error"):
            try:
                return json.loads(full)
            except:
                pass
    return []

@mcp.tool()
def get_function_body(address: str) -> dict:
    """
    Get address range of function body.
    Returns dict with min_address, max_address, num_addresses, ranges.
    """
    import json
    response = safe_get("get_function_body", {"address": address})
    if response and len(response) > 0:
        full = "\n".join(response)
        if full.strip() and not full.startswith("Error"):
            try:
                return json.loads(full)
            except:
                pass
    return {"error": "No function at address"}

@mcp.tool()
def get_function_signature(address: str) -> dict:
    """
    Get full calling convention signature of function.
    Returns dict with signature, calling_convention, return_type, varargs, name, entry.
    """
    import json
    response = safe_get("get_function_signature", {"address": address})
    if response and len(response) > 0:
        full = "\n".join(response)
        if full.strip() and not full.startswith("Error"):
            try:
                return json.loads(full)
            except:
                pass
    return {"error": "No function at address"}

@mcp.tool()
def get_stack_frame(address: str) -> dict:
    """
    Get stack frame size/layout info for function.
    Returns dict with stack_size, local_size, param_size, return_addr_size, locals, parameters.
    """
    import json
    response = safe_get("get_stack_frame", {"address": address})
    if response and len(response) > 0:
        full = "\n".join(response)
        if full.strip() and not full.startswith("Error"):
            try:
                return json.loads(full)
            except:
                pass
    return {"error": "No function at address"}

@mcp.tool()
def get_function_complexity(address: str) -> dict:
    """
    Get cyclomatic complexity of function.
    Returns dict with cyclomatic_complexity, branches, instructions.
    """
    import json
    response = safe_get("get_function_complexity", {"address": address})
    if response and len(response) > 0:
        full = "\n".join(response)
        if full.strip() and not full.startswith("Error"):
            try:
                return json.loads(full)
            except:
                pass
    return {"error": "No function at address"}

@mcp.tool()
def get_instruction_at(address: str) -> dict:
    """
    Get single instruction at address.
    Returns dict with address, bytes, mnemonic, operands, length.
    """
    import json
    response = safe_get("get_instruction_at", {"address": address})
    if response and len(response) > 0:
        full = "\n".join(response)
        if full.strip() and not full.startswith("Error"):
            try:
                return json.loads(full)
            except:
                pass
    return {"error": "No instruction at address"}

@mcp.tool()
def get_instructions_in_range(start: str, end: str) -> str:
    """
    Get list of instructions in address range.
    Returns assembly with bytes and instructions.
    """
    return "\n".join(safe_get("get_instructions_in_range", {"start": start, "end": end}))

@mcp.tool()
def get_basic_blocks(address: str) -> list:
    """
    Get basic blocks for CFG analysis of function.
    Returns list of blocks with start and size for each.
    """
    import json
    response = safe_get("get_basic_blocks", {"address": address})
    if response and len(response) > 0:
        full = "\n".join(response)
        if full.strip() and not full.startswith("Error"):
            try:
                return json.loads(full)
            except:
                pass
    return []

@mcp.tool()
def get_control_flow_graph(address: str) -> dict:
    """
    Get control flow graph (CFG) of function.
    Returns dict with function name, nodes, and edges.
    """
    import json
    response = safe_get("get_control_flow_graph", {"address": address})
    if response and len(response) > 0:
        full = "\n".join(response)
        if full.strip() and not full.startswith("Error"):
            try:
                return json.loads(full)
            except:
                pass
    return {"error": "No function at address"}

@mcp.tool()
def get_memory_map() -> list:
    """
    Get full memory map with permissions.
    Returns list of memory blocks with name, start, end, size, permissions, etc.
    """
    import json
    response = safe_get("get_memory_map")
    if response and len(response) > 0:
        full = "\n".join(response)
        if full.strip() and not full.startswith("Error"):
            try:
                return json.loads(full)
            except:
                pass
    return []

@mcp.tool()
def get_section_info() -> list:
    """
    Get PE/ELF section details.
    Returns list of sections with name, start, end, size, permissions.
    """
    import json
    response = safe_get("get_section_info")
    if response and len(response) > 0:
        full = "\n".join(response)
        if full.strip() and not full.startswith("Error"):
            try:
                return json.loads(full)
            except:
                pass
    return []

@mcp.tool()
def get_stack_strings(address: str) -> list:
    """
    Detect stack-allocated strings in function.
    Returns list of string variables with offset and type.
    """
    return safe_get("get_stack_strings", {"address": address})

@mcp.tool()
def get_data_access(address: str) -> list:
    """
    Get data accessed by function.
    Returns list of addresses with labels and types.
    """
    return safe_get("get_data_access", {"address": address})

@mcp.tool()
def get_bookmarks() -> list:
    """
    Get all bookmarks in program.
    Returns list with address, type, category, comment for each.
    """
    import json
    response = safe_get("get_bookmarks")
    if response and len(response) > 0:
        full = "\n".join(response)
        if full.strip() and not full.startswith("Error"):
            try:
                return json.loads(full)
            except:
                pass
    return []

@mcp.tool()
def get_equates(address: str) -> list:
    """
    Get equate tables for values at address.
    Returns list with name, value, operand_index for each equate.
    """
    import json
    response = safe_get("get_equates", {"address": address})
    if response and len(response) > 0:
        full = "\n".join(response)
        if full.strip() and not full.startswith("Error"):
            try:
                return json.loads(full)
            except:
                pass
    return []

@mcp.tool()
def get_open_programs() -> list:
    """
    Get all open programs in Ghidra.
    Returns list with path, name, and current (bool) for each.
    """
    import json
    response = safe_get("get_open_programs")
    if response and len(response) > 0:
        full = "\n".join(response)
        if full.strip() and not full.startswith("Error"):
            try:
                return json.loads(full)
            except:
                pass
    return []

@mcp.tool()
def switch_program(path: str) -> str:
    """
    Switch the active program in Ghidra.
    Use path or name from get_open_programs() to identify the program.
    Returns confirmation message.
    """
    return "\n".join(safe_get("switch_program", {"path": path}))

@mcp.tool()
def list_data_types(offset: int = 0, limit: int = 100) -> list:
    """List all defined structs, enums, and data types with pagination."""
    return safe_get("list_data_types", {"offset": offset, "limit": limit})

@mcp.tool()
def get_struct_fields(structName: str) -> list:
    """Get fields of a struct by name."""
    return safe_get("get_struct_fields", {"structName": structName})

@mcp.tool()
def get_enum_values(enumName: str) -> list:
    """Get values of an enum by name."""
    return safe_get("get_enum_values", {"enumName": enumName})

@mcp.tool()
def get_symbols_at(address: str) -> list:
    """Get all symbols at an address."""
    return safe_get("get_symbols_at", {"address": address})

@mcp.tool()
def get_external_functions(offset: int = 0, limit: int = 100) -> list:
    """List all external/imported functions."""
    return safe_get("get_external_functions", {"offset": offset, "limit": limit})

@mcp.tool()
def get_decompiler_comment(address: str) -> str:
    """Get comment from decompiler view at address."""
    return "\n".join(safe_get("get_decompiler_comment", {"address": address}))

@mcp.tool()
def get_disassembly_comment(address: str) -> str:
    """Get comment from listing view at address."""
    return "\n".join(safe_get("get_disassembly_comment", {"address": address}))

@mcp.tool()
def get_references_count(address: str) -> dict:
    """Get count of references to an address, categorized by type."""
    response = safe_get("get_references_count", {"address": address})
    return json.loads("\n".join(response)) if response else {}

@mcp.tool()
def get_code_units_in_range(start: str, end: str) -> list:
    """Get all instructions and data in address range."""
    return safe_get("get_code_units_in_range", {"start": start, "end": end})

@mcp.tool()
def compare_memory(address1: str, address2: str, length: int) -> list:
    """Compare two memory regions and return differences."""
    return safe_get("compare_memory", {"address1": address1, "address2": address2, "length": length})

@mcp.tool()
def create_function(address: str, functionName: str) -> str:
    """Define a new function at address."""
    return safe_post("create_function", {"address": address, "functionName": functionName})

@mcp.tool()
def delete_function(address: str) -> str:
    """Undefine function at address."""
    return safe_post("delete_function", {"address": address})

@mcp.tool()
def add_bookmark(address: str, category: str, description: str) -> str:
    """Add bookmark at address."""
    return safe_post("add_bookmark", {"address": address, "category": category, "description": description})

@mcp.tool()
def remove_bookmark(address: str) -> str:
    """Remove bookmark at address."""
    return safe_post("remove_bookmark", {"address": address})

@mcp.tool()
def run_auto_analysis() -> str:
    """Trigger Ghidra's auto-analysis on current program."""
    return safe_post("run_auto_analysis", {})

@mcp.tool()
def undo() -> str:
    """Undo the last Ghidra operation."""
    return safe_post("undo", {})

@mcp.tool()
def redo() -> str:
    """Redo the last undone Ghidra operation."""
    return safe_post("redo", {})

@mcp.tool()
def create_data(address: str, datatype: str) -> str:
    """Create data at the specified address with the given datatype."""
    return safe_post("create_data", {"address": address, "datatype": datatype})

@mcp.tool()
def apply_data_type(address: str, datatype_name: str) -> str:
    """Apply a named data type to the data at the specified address."""
    return safe_post("apply_data_type", {"address": address, "datatype_name": datatype_name})

@mcp.tool()
def go_to_address(address: str) -> str:
    """Navigate to the specified address in Ghidra."""
    return safe_post("go_to_address", {"address": address})

@mcp.tool()
def get_current_selection() -> dict:
    """Get the current address selection in Ghidra. Returns dict with start and end addresses."""
    response = safe_get("get_current_selection")
    if response and len(response) > 0:
        full = "\n".join(response)
        if full.strip() and not full.startswith("Error"):
            try:
                return json.loads(full)
            except:
                pass
    return {"error": "No selection"}

@mcp.tool()
def set_selection(start: str, end: str) -> str:
    """Set the current address selection in Ghidra."""
    return safe_post("set_selection", {"start": start, "end": end})

@mcp.tool()
def run_script(script_path: str) -> str:
    """Run a Ghidra script at the specified path."""
    return safe_post("run_script", {"script_path": script_path})

@mcp.tool()
def save_program() -> str:
    """Save the current Ghidra program."""
    return safe_post("save_program", {})

@mcp.tool()
def get_program_info() -> dict:
    """Get information about the current Ghidra program. Returns dict with program metadata."""
    response = safe_get("get_program_info")
    if response and len(response) > 0:
        full = "\n".join(response)
        if full.strip() and not full.startswith("Error"):
            try:
                return json.loads(full)
            except:
                pass
    return {"error": "Failed to get program info"}

@mcp.tool()
def analyze_function(address: str) -> str:
    """Analyze the function at the specified address."""
    return safe_post("analyze_function", {"address": address})

@mcp.tool()
def clear_analysis(address: str) -> str:
    """Clear analysis results at the specified address."""
    return safe_post("clear_analysis", {"address": address})

def main():
    global ghidra_server_url
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (used for network transports), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (used for network transports), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse", "streamable-http"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server.rstrip("/")
    
    if args.transport in ("sse", "streamable-http"):
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            endpoint = "/sse" if args.transport == "sse" else "/mcp"
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}{endpoint}")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport=args.transport)
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

