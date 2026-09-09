[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/Denveous/GhidraMCP)](https://github.com/Denveous/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/Denveous/GhidraMCP)](https://github.com/Denveous/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Denveous/GhidraMCP)](https://github.com/Denveous/GhidraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/Denveous/GhidraMCP)](https://github.com/Denveous/GhidraMCP/graphs/contributors)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)


# MCP bridge for Ghidra reverse engineering
GhidraMCP is a Model Context Protocol server that exposes core Ghidra functionality to MCP clients for reverse engineering applications.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9


# Features
MCP Server + Ghidra Plugin

- Decompile and analyze binaries in Ghidra
- Automatically rename methods and data
- List methods, classes, imports, and exports

## Program targeting

Call `get_open_programs` first and use its `path`, `name`, or `executablePath` as the required `program` argument on every program-analysis tool. The target is attached to each MCP request, so requests from different sessions do not change Ghidra's current program; requests for the same program are serialized and requests for different programs can run concurrently. `switch_program` is reserved for explicitly changing the Ghidra UI's current program.

# MCP Tools

GhidraMCP exposes 86 tools through MCP for LLM-assisted reverse engineering:

## Listing & Navigation

| Tool | Description |
|------|-------------|
| `list_methods` | List all function names with pagination |
| `list_classes` | List all namespace/class names with pagination |
| `list_functions` | List all functions in the database |
| `list_segments` | List all memory segments with pagination |
| `list_imports` | List imported symbols with pagination |
| `list_exports` | List exported functions/symbols with pagination |
| `list_namespaces` | List all non-global namespaces with pagination |
| `list_data_items` | List defined data labels and values with pagination |
| `get_current_address` | Get the address currently selected by user |
| `get_current_function` | Get the function currently selected by user |
| `get_entry_points` | Get all entry points (external symbols) |
| `get_open_programs` | List all programs in the current Ghidra project (open and available) |
| `switch_program` | Explicitly change the Ghidra UI's current program or open a new program |
| `get_external_functions` | List all external/imported functions with pagination |

## Decompilation & Disassembly

| Tool | Description |
|------|-------------|
| `decompile_function` | Decompile function by name to C code |
| `decompile_function_by_address` | Decompile function at address to C code |
| `disassemble_function` | Get assembly code for a function |
| `disassemble_range` | Disassemble address range (start to end) |
| `get_instruction_at` | Get single instruction at address (bytes, mnemonic, operands) |
| `get_instructions_in_range` | Get list of instructions in address range |

## Function Analysis

| Tool | Description |
|------|-------------|
| `get_function_by_address` | Get function by its address |
| `get_function_params` | Get function parameters with types and registers |
| `get_function_locals` | Get local variables with types and offsets |
| `get_function_callers` | Get all functions that call this function |
| `get_function_callees` | Get all functions called by this function |
| `get_strings_in_function` | Get all string literals referenced in function |
| `get_function_bytes` | Get raw bytes from function entry point |
| `get_function_body` | Get address range of function body |
| `get_function_signature` | Get full calling convention signature |
| `get_stack_frame` | Get stack frame size/layout info |
| `get_function_complexity` | Get cyclomatic complexity |
| `get_basic_blocks` | Get basic blocks for CFG analysis |
| `get_control_flow_graph` | Get control flow graph (CFG) |

## XREF Analysis

| Tool | Description |
|------|-------------|
| `get_xrefs_to` | Get detailed cross-references TO address |
| `get_xrefs_from` | Get cross-references FROM address |

## Memory & Data Analysis

| Tool | Description |
|------|-------------|
| `get_bytes_at` | Read raw bytes at any address |
| `get_data_at` | Get defined data at address (arrays, structs, etc) |
| `get_type_at` | Get type information at address (data or function) |
| `get_containing_block` | Get memory block info (permissions, section, size) |
| `get_references` | Get all references to specified address |
| `get_memory_map` | Get full memory map with permissions |
| `get_section_info` | Get PE/ELF section details |
| `get_data_access` | Get data accessed by function |
| `get_stack_strings` | Detect stack-allocated strings |
| `list_data_types` | List all defined structs, enums, and data types with pagination |
| `get_struct_fields` | Get fields of a struct by name |
| `get_enum_values` | Get values of an enum by name |
| `get_symbols_at` | Get all symbols at an address |
| `compare_memory` | Compare two memory regions and return differences |
| `get_references_count` | Get count of references to an address, categorized by type |

## Search

| Tool | Description |
|------|-------------|
| `search_functions_by_name` | Search for functions by name substring |
| `search_strings` | Search for strings in program |
| `search_bytes` | Search for byte patterns (hex, ? wildcards) |
| `search_for_value` | Search for hex value in all defined data |
| `get_code_units_in_range` | Get all instructions and data in address range |

## Renaming & Modification

| Tool | Description |
|------|-------------|
| `rename_function` | Rename function by name |
| `rename_function_by_address` | Rename function by address |
| `rename_data` | Rename data label at address |
| `rename_variable` | Rename local variable within function |
| `patch_bytes` | Patch bytes at address (hex) |
| `set_function_prototype` | Set function's prototype |
| `set_local_variable_type` | Set local variable's type |
| `set_decompiler_comment` | Set comment in function pseudocode |
| `set_disassembly_comment` | Set comment in function disassembly |

## Bookmarks & Equates

| Tool | Description |
|------|-------------|
| `get_bookmarks` | Get all bookmarks in program |
| `get_equates` | Get equate tables for values at address |

## Data Creation & Navigation

| Tool | Description |
|------|-------------|
| `create_data` | Create data at address with specified datatype (byte, word, dword, qword, float, double, pointer) |
| `apply_data_type` | Apply named data type from DataTypeManager to address *(pending - type lookup issues)* |
| `go_to_address` | Navigate to specified address in Ghidra |
| `get_program_info` | Get information about current program (name, language, compiler, architecture) |
| `analyze_function` | Analyze function at specified address |
| `clear_analysis` | Clear analysis results at specified address |

## Export

| Tool | Description |
|------|-------------|
| `export_binary` | Export entire binary to file |

# Installation

## Prerequisites
- Install [Ghidra](https://ghidra-sre.org)
- Python3
- MCP [SDK](https://github.com/modelcontextprotocol/python-sdk)

## Ghidra
First, download the latest [release](https://github.com/Denveous/GhidraMCP/releases) from this repository. This contains the Ghidra plugin and Python MCP client. Then, you can directly import the plugin into Ghidra.

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the downloaded GhidraMCP extension ZIP
5. Restart Ghidra
6. Make sure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`
7. *Optional*: Configure the port in Ghidra with `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`

Video Installation Guide:


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## MCP Clients

Theoretically, any MCP client should work with ghidraMCP.  Two examples are given below.

## Example 1: Claude Desktop
To set up Claude Desktop as a Ghidra MCP client, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the following:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8179/"
      ]
    }
  }
}
```

Alternatively, edit this file directly:
```
/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json
```

The server IP and port are configurable and should be set to point to the target Ghidra instance. The default Ghidra plugin endpoint is `http://127.0.0.1:8179/`.

## Example 2: Cline
To use GhidraMCP with [Cline](https://cline.bot), this requires manually running the MCP server as well. First run the following command:

```
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8179/
```

The only *required* argument is the transport. If all other arguments are unspecified, they will default to the above. Once the MCP server is running, open up Cline and select `MCP Servers` at the top.

![Cline select](https://github.com/user-attachments/assets/88e1f336-4729-46ee-9b81-53271e9c0ce0)

Then select `Remote Servers` and add the following, ensuring that the url matches the MCP host and port:

1. Server Name: GhidraMCP
2. Server URL: `http://127.0.0.1:8081/sse`

## Example 3: 5ire
Another MCP client that supports multiple models on the backend is [5ire](https://github.com/nanbingxyz/5ire). To set up GhidraMCP, open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: ghidra
2. Name: GhidraMCP
3. Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py`

# Building from Source
Build with Java 21 and Gradle by running from this directory:

`.\gradlew.bat buildExtension`

The generated extension ZIP is written to `dist/` and includes the built Ghidra plugin and Python MCP bridge.

- `lib/GhidraMCP.jar`
- `extension.properties`
- `Module.manifest`
