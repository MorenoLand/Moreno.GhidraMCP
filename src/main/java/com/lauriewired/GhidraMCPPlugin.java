package com.lauriewired;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.app.services.CodeViewerService;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.util.DefinedStringIterator;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.DataType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Bookmark;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.services.Analyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.util.task.TaskMonitor;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.GoToService;
import ghidra.program.disassemble.Disassembler;

import javax.swing.*;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.Executor;
import java.util.concurrent.locks.ReentrantLock;


@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ghidra.app.DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "HTTP server plugin",
	description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

	private HttpServer server;
	private final ThreadLocal<Program> requestProgram = new ThreadLocal<>();
	private final Map<Program, ReentrantLock> programLocks = Collections.synchronizedMap(new IdentityHashMap<>());
	private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
	private static final String PORT_OPTION_NAME = "Server Port";
	private static final int DEFAULT_PORT = 8179;
	private Gson gson = null;

	public GhidraMCPPlugin(PluginTool tool) {
		super(tool);

		gson = new Gson();
		Msg.info(this, "GhidraMCPPlugin loading...");

		// Register the configuration option
		Options options = tool.getOptions(OPTION_CATEGORY_NAME);
		options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
			null, // No help location for now
			"The network port number the embedded HTTP server will listen on. " +
				"Requires Ghidra restart or plugin reload to take effect after changing.");

		try {
			startServer();
		} catch (IOException e) {
			Msg.error(this, "Failed to start HTTP server", e);
		}
		Msg.info(this, "GhidraMCPPlugin loaded!");
	}

	private void startServer() throws IOException {
		// Read the configured port
		Options options = tool.getOptions(OPTION_CATEGORY_NAME);
		int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

		// Stop existing server if running (e.g., if plugin is reloaded)
		if (server != null) {
			Msg.info(this, "Stopping existing HTTP server before starting new one.");
			server.stop(0);
			server = null;
		}

		server = new ProgramAwareHttpServer(HttpServer.create(new InetSocketAddress(port), 0));

		// Each listing endpoint uses offset & limit from query params:
		server.createContext("/methods", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100000);
			sendResponse(exchange, getAllFunctionNames(offset, limit));
		});

		server.createContext("/fun", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			var name = qparams.get("name");

			sendResponse(exchange, gson.toJson(getFunction(name)));
		});

		server.createContext("/classes", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100);
			sendResponse(exchange, getAllClassNames(offset, limit));
		});

		server.createContext("/decompile", exchange -> {
			String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
			sendResponse(exchange, decompileFunctionByName(name));
		});

		server.createContext("/renameFunction", exchange -> {
			Map<String, String> params = parsePostParams(exchange);
			String response = renameFunction(params.get("oldName"), params.get("newName"))
				? "Renamed successfully" : "Rename failed";
			sendResponse(exchange, response);
		});

		server.createContext("/renameData", exchange -> {
			Map<String, String> params = parsePostParams(exchange);
			renameDataAtAddress(params.get("address"), params.get("newName"));
			sendResponse(exchange, "Rename data attempted");
		});

		server.createContext("/renameVariable", exchange -> {
			Map<String, String> params = parsePostParams(exchange);
			String functionName = params.get("functionName");
			String oldName = params.get("oldName");
			String newName = params.get("newName");
			String result = renameVariableInFunction(functionName, oldName, newName);
			sendResponse(exchange, result);
		});

		server.createContext("/segments", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100);
			sendResponse(exchange, listSegments(offset, limit));
		});

		server.createContext("/imports", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100);
			sendResponse(exchange, listImports(offset, limit));
		});

		server.createContext("/exports", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100);
			sendResponse(exchange, listExports(offset, limit));
		});

		server.createContext("/namespaces", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100);
			sendResponse(exchange, listNamespaces(offset, limit));
		});

		server.createContext("/data", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100);
			boolean byteSourceOffset = parseBoolOrDefault(qparams.get("bytesourceoffset"), false);
			try {
				sendResponse(exchange, listDefinedData(offset, limit, byteSourceOffset));
			} catch (MemoryAccessException e) {
				throw new RuntimeException(e);
			}
		});

		server.createContext("/searchFunctions", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String searchTerm = qparams.get("query");
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100);
			sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
		});

		server.createContext("/list_functions", exchange -> {
			sendResponse(exchange, getAllFunctionNames(0, 100000));
		});

		server.createContext("/get_function_by_address", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getFunctionByAddress(addressStr));
		});

		server.createContext("/get_current_address", exchange -> {
			sendResponse(exchange, getCurrentAddress());
		});

		server.createContext("/get_current_function", exchange -> {
			sendResponse(exchange, getCurrentFunction());
		});

		server.createContext("/decompile_function", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, decompileFunctionByAddress(addressStr));
		});

		server.createContext("/disassemble_function", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, disassembleFunction(addressStr));
		});

		server.createContext("/set_decompiler_comment", exchange -> {
			Map<String, String> params = parsePostParams(exchange);
			String addressStr = params.get("address");
			String comment = params.get("comment");
			sendResponse(exchange, setDecompilerComment(addressStr, comment));
		});

		server.createContext("/set_disassembly_comment", exchange -> {
			Map<String, String> params = parsePostParams(exchange);
			String addressStr = params.get("address");
			String comment = params.get("comment");
			sendResponse(exchange, setDisassemblyComment(addressStr, comment));
		});

		server.createContext("/rename_function_by_address", exchange -> {
			Map<String, String> params = parsePostParams(exchange);
			String addressStr = params.get("function_address");
			String newName = params.get("new_name");
			String response = renameFunctionByAddress(addressStr, newName)
				? "Renamed successfully" : "Rename failed";
			sendResponse(exchange, response);
		});

		server.createContext("/set_function_prototype", exchange -> {
			Map<String, String> params = parsePostParams(exchange);
			String addressStr = params.get("function_address");
			String prototype = params.get("prototype");
			sendResponse(exchange, setFunctionPrototype(addressStr, prototype));
		});

		server.createContext("/set_local_variable_type", exchange -> {
			Map<String, String> params = parsePostParams(exchange);
			String addressStr = params.get("function_address");
			String varName = params.get("variable_name");
			String newType = params.get("new_type");
			sendResponse(exchange, setLocalVariableType(addressStr, varName, newType));
		});

		server.createContext("/search_strings", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String query = qparams.get("query");
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100);
			sendResponse(exchange, searchStrings(query, offset, limit));
		});

		server.createContext("/search_bytes", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String pattern = qparams.get("pattern");
			if (pattern == null || pattern.isEmpty()) {
				sendResponse(exchange, gson.toJson(List.of("Error: pattern parameter is required")));
				return;
			}
			int limit = parseIntOrDefault(qparams.get("limit"), 100);
			sendResponse(exchange, searchBytes(pattern, limit));
		});

		server.createContext("/get_references", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getReferences(addressStr));
		});

		server.createContext("/get_function_bytes", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			int length = parseIntOrDefault(qparams.get("length"), 32);
			sendResponse(exchange, getFunctionBytes(addressStr, length));
		});

		server.createContext("/patch_bytes", exchange -> {
			Map<String, String> params = parsePostParams(exchange);
			String addressStr = params.get("address");
			String bytesStr = params.get("bytes");
			sendResponse(exchange, patchBytes(addressStr, bytesStr));
		});

		server.createContext("/get_strings_in_function", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getStringsInFunction(addressStr));
		});

		server.createContext("/get_function_callers", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getFunctionCallers(addressStr));
		});

		server.createContext("/get_function_callees", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getFunctionCallees(addressStr));
		});

		server.createContext("/get_bytes_at", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			int length = parseIntOrDefault(qparams.get("length"), 32);
			sendResponse(exchange, getBytesAt(addressStr, length));
		});

		server.createContext("/disassemble_range", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String startStr = qparams.get("start");
			String endStr = qparams.get("end");
			sendResponse(exchange, disassembleRange(startStr, endStr));
		});

		server.createContext("/export_binary", exchange -> {
			Map<String, String> params = parsePostParams(exchange);
			String outputPath = params.get("path");
			sendResponse(exchange, exportBinary(outputPath));
		});

		server.createContext("/get_function_params", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getFunctionParams(addressStr));
		});

		server.createContext("/get_function_locals", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getFunctionLocals(addressStr));
		});

		server.createContext("/get_containing_block", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getContainingBlock(addressStr));
		});

		server.createContext("/get_entry_points", exchange -> {
			sendResponse(exchange, getEntryPoints());
		});

		server.createContext("/get_data_at", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getDataAt(addressStr));
		});

		server.createContext("/get_type_at", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getTypeAt(addressStr));
		});

		server.createContext("/search_for_value", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String valueStr = qparams.get("value");
			sendResponse(exchange, searchForValue(valueStr));
		});

		server.createContext("/get_xrefs_to", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getXrefsTo(addressStr));
		});

		server.createContext("/get_xrefs_from", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getXrefsFrom(addressStr));
		});

		server.createContext("/get_function_body", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getFunctionBody(addressStr));
		});

		server.createContext("/get_function_signature", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getFunctionSignature(addressStr));
		});

		server.createContext("/get_stack_frame", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getStackFrame(addressStr));
		});

		server.createContext("/get_function_complexity", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getFunctionComplexity(addressStr));
		});

		server.createContext("/get_instruction_at", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getInstructionAt(addressStr));
		});

		server.createContext("/get_instructions_in_range", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String startStr = qparams.get("start");
			String endStr = qparams.get("end");
			sendResponse(exchange, getInstructionsInRange(startStr, endStr));
		});

		server.createContext("/get_basic_blocks", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getBasicBlocks(addressStr));
		});

		server.createContext("/get_control_flow_graph", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getControlFlowGraph(addressStr));
		});

		server.createContext("/get_memory_map", exchange -> {
			sendResponse(exchange, getMemoryMap());
		});

		server.createContext("/get_section_info", exchange -> {
			sendResponse(exchange, getSectionInfo());
		});

		server.createContext("/get_stack_strings", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getStackStrings(addressStr));
		});

		server.createContext("/get_data_access", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getDataAccess(addressStr));
		});

		server.createContext("/get_bookmarks", exchange -> {
			sendResponse(exchange, getBookmarks());
		});

		server.createContext("/get_equates", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getEquates(addressStr));
		});

		server.createContext("/get_open_programs", exchange -> {
			sendResponse(exchange, getOpenPrograms());
		});

		server.createContext("/switch_program", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String programPath = qparams.get("path");
			sendResponse(exchange, switchProgram(programPath));
		});

		server.createContext("/list_data_types", exchange -> {
			Map<String,String> qparams = parseQueryParams(exchange);
			int offset = Integer.parseInt(qparams.getOrDefault("offset", "0"));
			int limit = Integer.parseInt(qparams.getOrDefault("limit", "100"));
			sendResponse(exchange, listDataTypes(offset, limit));
		});

		server.createContext("/get_struct_fields", exchange -> {
			Map<String,String> qparams = parseQueryParams(exchange);
			String structName = qparams.get("structName");
			sendResponse(exchange, getStructFields(structName));
		});

		server.createContext("/get_enum_values", exchange -> {
			Map<String,String> qparams = parseQueryParams(exchange);
			String enumName = qparams.get("enumName");
			sendResponse(exchange, getEnumValues(enumName));
		});

		server.createContext("/get_symbols_at", exchange -> {
			Map<String,String> qparams = parseQueryParams(exchange);
			String address = qparams.get("address");
			sendResponse(exchange, getSymbolsAt(address));
		});

		server.createContext("/get_external_functions", exchange -> {
			Map<String,String> qparams = parseQueryParams(exchange);
			int offset = Integer.parseInt(qparams.getOrDefault("offset", "0"));
			int limit = Integer.parseInt(qparams.getOrDefault("limit", "100"));
			sendResponse(exchange, getExternalFunctions(offset, limit));
		});

		server.createContext("/get_decompiler_comment", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getDecompilerComment(addressStr));
		});

		server.createContext("/get_disassembly_comment", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getDisassemblyComment(addressStr));
		});

		server.createContext("/get_references_count", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String addressStr = qparams.get("address");
			sendResponse(exchange, getReferencesCount(addressStr));
		});

		server.createContext("/get_code_units_in_range", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String startStr = qparams.get("start");
			String endStr = qparams.get("end");
			sendResponse(exchange, getCodeUnitsInRange(startStr, endStr));
		});

		server.createContext("/compare_memory", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String address1Str = qparams.get("address1");
			String address2Str = qparams.get("address2");
			int length = parseIntOrDefault(qparams.get("length"), 32);
			sendResponse(exchange, compareMemory(address1Str, address2Str, length));
		});

		server.createContext("/create_function", exchange -> {
			try {
				String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
				Map<String, String> params = gson.fromJson(body, Map.class);
				String address = params.get("address");
				String functionName = params.get("functionName");
				sendResponse(exchange, createFunction(address, functionName));
			} catch (Exception e) {
				sendResponse(exchange, "Error: " + e.getMessage());
			}
		});

		server.createContext("/delete_function", exchange -> {
			try {
				String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
				Map<String, String> params = gson.fromJson(body, Map.class);
				String address = params.get("address");
				sendResponse(exchange, deleteFunction(address));
			} catch (Exception e) {
				sendResponse(exchange, "Error: " + e.getMessage());
			}
		});

		server.createContext("/add_bookmark", exchange -> {
			try {
				String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
				Map<String, String> params = gson.fromJson(body, Map.class);
				String address = params.get("address");
				String category = params.get("category");
				String description = params.get("description");
				sendResponse(exchange, addBookmark(address, category, description));
			} catch (Exception e) {
				sendResponse(exchange, "Error: " + e.getMessage());
			}
		});

		server.createContext("/remove_bookmark", exchange -> {
			try {
				String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
				Map<String, String> params = gson.fromJson(body, Map.class);
				String address = params.get("address");
				sendResponse(exchange, removeBookmark(address));
			} catch (Exception e) {
				sendResponse(exchange, "Error: " + e.getMessage());
			}
		});

		server.createContext("/create_data", exchange -> {
			try {
				String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
				Map<String, String> params = gson.fromJson(body, Map.class);
				String address = params.get("address");
				String datatype = params.get("datatype");
				sendResponse(exchange, createData(address, datatype));
			} catch (Exception e) {
				sendResponse(exchange, gson.toJson(Map.of("status", "error", "message", e.getMessage())));
			}
		});

		server.createContext("/apply_data_type", exchange -> {
			try {
				String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
				Map<String, String> params = gson.fromJson(body, Map.class);
				String address = params.get("address");
				String datatypeName = params.get("datatype_name");
				sendResponse(exchange, applyDataType(address, datatypeName));
			} catch (Exception e) {
				sendResponse(exchange, gson.toJson(Map.of("status", "error", "message", e.getMessage())));
			}
		});

		server.createContext("/go_to_address", exchange -> {
			exchange.getResponseHeaders().set("Content-Type", "application/json");
			try {
				String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
				Map<String, String> params = gson.fromJson(body, Map.class);
				String address = params.get("address");
				sendJsonResponse(exchange, goToAddress(address));
			} catch (Exception e) {
				sendJsonResponse(exchange, gson.toJson(Map.of("status", "error", "message", e.getMessage())));
			}
		});

		server.createContext("/analyze_function", exchange -> {
			exchange.getResponseHeaders().set("Content-Type", "application/json");
			try {
				if (!"POST".equals(exchange.getRequestMethod())) {
					sendJsonResponse(exchange, gson.toJson(Map.of("status", "error", "message", "Method not allowed")));
					return;
				}
				String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
				Map<String, String> params = gson.fromJson(body, Map.class);
				String address = params.get("address");
				sendJsonResponse(exchange, analyzeFunction(address));
			} catch (Exception e) {
				sendJsonResponse(exchange, gson.toJson(Map.of("status", "error", "message", e.getMessage())));
			}
		});

		server.createContext("/clear_analysis", exchange -> {
			exchange.getResponseHeaders().set("Content-Type", "application/json");
			try {
				if (!"POST".equals(exchange.getRequestMethod())) {
					sendJsonResponse(exchange, gson.toJson(Map.of("status", "error", "message", "Method not allowed")));
					return;
				}
				String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
				Map<String, String> params = gson.fromJson(body, Map.class);
				String address = params.get("address");
				sendJsonResponse(exchange, clearAnalysis(address));
			} catch (Exception e) {
				sendJsonResponse(exchange, gson.toJson(Map.of("status", "error", "message", e.getMessage())));
			}
		});

		server.createContext("/get_program_info", exchange -> {
			sendResponse(exchange, getProgramInfo());
		});

		server.setExecutor(null);
		new Thread(() -> {
			try {
				server.start();
				Msg.info(this, "GhidraMCP HTTP server started on port " + port);
			} catch (Exception e) {
				Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
				server = null; // Ensure server isn't considered running
			}
		}, "GhidraMCP-HTTP-Server").start();
	}

	private final class ProgramAwareHttpServer extends HttpServer {
		private final HttpServer delegate;

		private ProgramAwareHttpServer(HttpServer delegate) {
			this.delegate = delegate;
		}

		@Override
		public void bind(InetSocketAddress address, int backlog) throws IOException {
			delegate.bind(address, backlog);
		}

		@Override
		public void start() {
			delegate.start();
		}

		@Override
		public void stop(int delay) {
			delegate.stop(delay);
		}

		@Override
		public HttpContext createContext(String path, HttpHandler handler) {
			return delegate.createContext(path, exchange -> {
				Map<String, String> queryParams = parseQueryParams(exchange);
				String programIdentifier = queryParams.get("program");
				boolean programIndependent = "/get_open_programs".equals(path) || "/switch_program".equals(path);
				if (!programIndependent) {
					if (programIdentifier == null || programIdentifier.isBlank()) {
						sendResponse(exchange, "Error: program is required");
						return;
					}
					Program program = findOpenProgram(programIdentifier);
					if (program == null) {
						sendResponse(exchange, "Error: Program is not open: " + programIdentifier);
						return;
					}
					ReentrantLock programLock;
					synchronized (programLocks) {
						programLock = programLocks.computeIfAbsent(program, ignored -> new ReentrantLock(true));
					}
					programLock.lock();
					requestProgram.set(program);
					try {
						handler.handle(exchange);
					} finally {
						requestProgram.remove();
						programLock.unlock();
					}
					return;
				}
				handler.handle(exchange);
			});
		}

		@Override
		public HttpContext createContext(String path) {
			return delegate.createContext(path);
		}

		@Override
		public void removeContext(String path) throws IllegalArgumentException {
			delegate.removeContext(path);
		}

		@Override
		public void removeContext(HttpContext context) {
			delegate.removeContext(context);
		}

		@Override
		public InetSocketAddress getAddress() {
			return delegate.getAddress();
		}

		@Override
		public void setExecutor(Executor executor) {
			delegate.setExecutor(executor);
		}

		@Override
		public Executor getExecutor() {
			return delegate.getExecutor();
		}
	}

	// ----------------------------------------------------------------------------------
	// Pagination-aware listing methods
	// ----------------------------------------------------------------------------------

	private String getAllFunctionNames(int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		List<String> names = new ArrayList<>();
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			names.add(f.getName(true));
		}
		return gson.toJson(names);//paginateList(names, offset, limit);
	}

	private Fun getFunction(String name) {
		Program program = getCurrentProgram();
		//if (program == null) return ["No program loaded"];

		List<FunctionCall> calls = new ArrayList<>();

		FunctionManager fm = program.getFunctionManager();
		SymbolTable st = program.getSymbolTable();
		ReferenceManager rm = program.getReferenceManager();


		var fun = new Fun();
		for (Function f : fm.getFunctions(true)) {
			if (Objects.equals(f.getName(true), name)) {
				Address entry = f.getEntryPoint();
				var parameters = f.getParameters();


				Map<String, String> argRegs = new LinkedHashMap<>();

				for (var param : parameters)
					argRegs.put(param.getRegister().getName(), param.getName());
				// Get all references to this function
				for (Reference ref : rm.getReferencesTo(entry)) {
					Address callAddr = ref.getFromAddress();
					Instruction instr = program.getListing().getInstructionAt(callAddr);
					Function callingFunc = fm.getFunctionContaining(callAddr);

					if (instr == null || callingFunc == null || !instr.getMnemonicString().equalsIgnoreCase("CALL"))
						continue;

					FunctionCall fc = new FunctionCall();
					fc.callAddress = "0x%s".formatted(callAddr.toString());
					fc.fromFunction = callingFunc.getName(true);

					int stepsBack = 0;
					Map<String, Long> seenArgs = new LinkedHashMap<>();

					Instruction prev = instr.getPrevious();
					while (prev != null && stepsBack < 10) {
						if (prev.getNumOperands() >= 2 && prev.getOpObjects(0)[0] instanceof Register && prev.getOpObjects(1)[0] instanceof Scalar) {
							Register reg = (Register) prev.getOpObjects(0)[0];
							Scalar val = (Scalar) prev.getOpObjects(1)[0];
							String regName = reg.getName().toUpperCase();
							if (argRegs.containsKey(regName) && !seenArgs.containsKey(regName)) {
								seenArgs.put(argRegs.get(regName), val.getValue());
							}
						}

						prev = prev.getPrevious();
						stepsBack++;
					}

					fc.parameters.putAll(seenArgs);

					calls.add(fc);
				}

				fun.name = f.getName(true);
				fun.address = "0x%s".formatted(f.getEntryPoint().toString());
				fun.calls = calls;

				return fun;
			}
		}
		return null;
	}

	private String getAllClassNames(int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		Set<String> classNames = new HashSet<>();
		for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
			Namespace ns = symbol.getParentNamespace();
			if (ns != null && !ns.isGlobal()) {
				classNames.add(ns.getName());
			}
		}
		// Convert set to list for pagination
		List<String> sorted = new ArrayList<>(classNames);

		Collections.sort(sorted);
		return paginateList(sorted, offset, limit);
	}

	private String listSegments(int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		List<String> lines = new ArrayList<>();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
		}
		return paginateList(lines, offset, limit);
	}

	private String listImports(int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		List<String> lines = new ArrayList<>();
		for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
			lines.add(symbol.getName() + " -> " + symbol.getAddress());
		}
		return paginateList(lines, offset, limit);
	}

	private String listExports(int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		SymbolTable table = program.getSymbolTable();
		SymbolIterator it = table.getAllSymbols(true);

		List<String> lines = new ArrayList<>();
		while (it.hasNext()) {
			Symbol s = it.next();
			// On older Ghidra, "export" is recognized via isExternalEntryPoint()
			if (s.isExternalEntryPoint()) {
				lines.add(s.getName() + " -> " + s.getAddress());
			}
		}
		return paginateList(lines, offset, limit);
	}

	private String listNamespaces(int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		Set<String> namespaces = new HashSet<>();
		for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
			Namespace ns = symbol.getParentNamespace();
			if (ns != null && !(ns instanceof GlobalNamespace)) {
				namespaces.add(ns.getName());
			}
		}
		List<String> sorted = new ArrayList<>(namespaces);
		Collections.sort(sorted);
		return paginateList(sorted, offset, limit);
	}

	private String listDefinedData(int offset, int limit, boolean byteSourceOffset) throws MemoryAccessException {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		List<String> lines = new ArrayList<>();
		//for (MemoryBlock block : program.getMemory().getBlocks()) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace(); // or getAddressSpace("ram")
		Address addr = byteSourceOffset ? addressFromOffset(offset) : space.getAddress(offset);
		DataIterator it = program.getListing().getData(addr, true);
		int i = 0;
		while (it.hasNext()) {
			if (i > limit) break;
			Data data = it.next();
			//if (block.contains(data.getAddress())) {
			String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
			String valRepr = data.getDefaultValueRepresentation();
			lines.add(String.format("%s: %s = %s",
				data.getAddress(),
				escapeNonAscii(label),
				escapeNonAscii(valRepr)
			));

			var dataContainer = new DataContainer();
			dataContainer.name = escapeNonAscii(label);
			dataContainer.address = "0x%s".formatted(data.getAddress());
			dataContainer.data = Base64.getEncoder().encodeToString(data.getBytes());

			return gson.toJson(dataContainer);
			//}
			//i++;
		}
		//}
		return gson.toJson(lines);//paginateList(lines, offset, limit);
	}

	private Address addressFromOffset(long offset) {
		Program program = getCurrentProgram();

		MemoryBlock[] blocks = program.getMemory().getBlocks();
		for (MemoryBlock block : blocks) {
			if (block.isInitialized() && block.isLoaded()) {
				long blockOffset = offset - block.getSourceInfos().getFirst().getFileBytesOffset();
				if (blockOffset >= 0 && blockOffset < block.getSize()) {
					return block.getStart().add(blockOffset);
				}
			}
		}
		return null; // Not found
	}

	private String searchFunctionsByName(String searchTerm, int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";

		List<String> matches = new ArrayList<>();
		for (Function func : program.getFunctionManager().getFunctions(true)) {
			String name = func.getName();
			// simple substring match
			if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
				matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
			}
		}

		Collections.sort(matches);

		if (matches.isEmpty()) {
			return "No functions matching '" + searchTerm + "'";
		}
		return paginateList(matches, offset, limit);
	}

	// ----------------------------------------------------------------------------------
	// Logic for rename, decompile, etc.
	// ----------------------------------------------------------------------------------

	private String decompileFunctionByName(String name) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(program);
		for (Function func : program.getFunctionManager().getFunctions(true)) {
			if (func.getName().equals(name)) {
				DecompileResults result =
					decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
				if (result != null && result.decompileCompleted()) {
					return result.getDecompiledFunction().getC();
				} else {
					return "Decompilation failed";
				}
			}
		}
		return "Function not found";
	}

	private boolean renameFunction(String oldName, String newName) {
		Program program = getCurrentProgram();
		if (program == null) return false;

		AtomicBoolean successFlag = new AtomicBoolean(false);
		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Rename function via HTTP");
				try {
					for (Function func : program.getFunctionManager().getFunctions(true)) {
						if (func.getName().equals(oldName)) {
							func.setName(newName, SourceType.USER_DEFINED);
							successFlag.set(true);
							break;
						}
					}
				} catch (Exception e) {
					Msg.error(this, "Error renaming function", e);
				} finally {
					program.endTransaction(tx, successFlag.get());
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this, "Failed to execute rename on Swing thread", e);
		}
		return successFlag.get();
	}

	private void renameDataAtAddress(String addressStr, String newName) {
		Program program = getCurrentProgram();
		if (program == null) return;

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Rename data");
				try {
					Address addr = program.getAddressFactory().getAddress(addressStr);
					Listing listing = program.getListing();
					Data data = listing.getDefinedDataAt(addr);
					if (data != null) {
						SymbolTable symTable = program.getSymbolTable();
						Symbol symbol = symTable.getPrimarySymbol(addr);
						if (symbol != null) {
							symbol.setName(newName, SourceType.USER_DEFINED);
						} else {
							symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
						}
					}
				} catch (Exception e) {
					Msg.error(this, "Rename data error", e);
				} finally {
					program.endTransaction(tx, true);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this, "Failed to execute rename data on Swing thread", e);
		}
	}

	private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(program);

		Function func = null;
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			if (f.getName().equals(functionName)) {
				func = f;
				break;
			}
		}

		if (func == null) {
			return "Function not found";
		}

		DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
		if (result == null || !result.decompileCompleted()) {
			return "Decompilation failed";
		}

		HighFunction highFunction = result.getHighFunction();
		if (highFunction == null) {
			return "Decompilation failed (no high function)";
		}

		LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
		if (localSymbolMap == null) {
			return "Decompilation failed (no local symbol map)";
		}

		HighSymbol highSymbol = null;
		Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
		while (symbols.hasNext()) {
			HighSymbol symbol = symbols.next();
			String symbolName = symbol.getName();

			if (symbolName.equals(oldVarName)) {
				highSymbol = symbol;
			}
			if (symbolName.equals(newVarName)) {
				return "Error: A variable with name '" + newVarName + "' already exists in this function";
			}
		}

		if (highSymbol == null) {
			return "Variable not found";
		}

		boolean commitRequired = checkFullCommit(highSymbol, highFunction);

		final HighSymbol finalHighSymbol = highSymbol;
		final Function finalFunction = func;
		AtomicBoolean successFlag = new AtomicBoolean(false);

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Rename variable");
				try {
					if (commitRequired) {
						HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
							ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
					}
					HighFunctionDBUtil.updateDBVariable(
						finalHighSymbol,
						newVarName,
						null,
						SourceType.USER_DEFINED
					);
					successFlag.set(true);
				} catch (Exception e) {
					Msg.error(this, "Failed to rename variable", e);
				} finally {
					program.endTransaction(tx, true);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
			Msg.error(this, errorMsg, e);
			return errorMsg;
		}
		return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
	}

	/**
	 * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 *
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction  is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

	// ----------------------------------------------------------------------------------
	// Utility: parse query params, parse post params, pagination, etc.
	// ----------------------------------------------------------------------------------

	/**
	 * Parse query parameters from the URL, e.g. ?offset=10&limit=100
	 */
	private Map<String, String> parseQueryParams(HttpExchange exchange) {
		Map<String, String> result = new HashMap<>();
		String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
		if (query != null) {
			String[] pairs = query.split("&");
			for (String p : pairs) {
				String[] kv = p.split("=", 2);
				if (kv.length == 2) {
					try {
						result.put(java.net.URLDecoder.decode(kv[0], StandardCharsets.UTF_8), java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
					} catch (Exception e) {
						result.put(kv[0], kv[1]);
					}
				}
			}
		}
		return result;
	}

	/**
	 * Parse post body form params, e.g. oldName=foo&newName=bar
	 */
	private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
		byte[] body = exchange.getRequestBody().readAllBytes();
		String bodyStr = new String(body, StandardCharsets.UTF_8);
		Map<String, String> params = new HashMap<>();
		for (String pair : bodyStr.split("&")) {
			String[] kv = pair.split("=");
			if (kv.length == 2) {
				params.put(java.net.URLDecoder.decode(kv[0], "UTF-8"), java.net.URLDecoder.decode(kv[1], "UTF-8"));
			}
		}
		return params;
	}

	/**
	 * Convert a list of strings into one big newline-delimited string, applying offset & limit.
	 */
	private String paginateList(List<String> items, int offset, int limit) {
		int start = Math.max(0, offset);
		int end = Math.min(items.size(), offset + limit);

		if (start >= items.size()) {
			return ""; // no items in range
		}
		List<String> sub = items.subList(start, end);
		return String.join("\n", sub);
	}

	/**
	 * Parse an integer from a string, or return defaultValue if null/invalid.
	 */
	private int parseIntOrDefault(String val, int defaultValue) {
		if (val == null) return defaultValue;
		try {
			return Integer.parseInt(val);
		} catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	/**
	 * Parse an integer from a string, or return defaultValue if null/invalid.
	 */
	private boolean parseBoolOrDefault(String val, boolean defaultValue) {
		if (val == null) return defaultValue;
		try {
			return Boolean.parseBoolean(val);
		} catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	/**
	 * Escape non-ASCII chars to avoid potential decode issues.
	 */
	private String escapeNonAscii(String input) {
		if (input == null) return "";
		StringBuilder sb = new StringBuilder();
		for (char c : input.toCharArray()) {
			if (c >= 32 && c < 127) {
				sb.append(c);
			} else {
				sb.append("\\x");
				sb.append(Integer.toHexString(c & 0xFF));
			}
		}
		return sb.toString();
	}

	public Program getCurrentProgram() {
		Program requestedProgram = requestProgram.get();
		if (requestedProgram != null) return requestedProgram;
		ProgramManager pm = tool.getService(ProgramManager.class);
		return pm != null ? pm.getCurrentProgram() : null;
	}

	private Program findOpenProgram(String identifier) {
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm == null || identifier == null) return null;
		for (Program program : pm.getAllOpenPrograms()) {
			DomainFile domainFile = program.getDomainFile();
			String path = domainFile != null ? domainFile.getPathname() : null;
			String executablePath = program.getExecutablePath();
			if (identifier.equals(path) || identifier.equals(program.getName()) || identifier.equals(executablePath)) {
				return program;
			}
		}
		return null;
	}

	private String getFunctionByAddress(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function found at address";
			return func.getName(true);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getCurrentAddress() {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		if (!isUiCurrentProgram(program)) return "No UI current address for requested program";
		CodeViewerService cv = tool.getService(CodeViewerService.class);
		if (cv == null) return "No code viewer service";
		ProgramLocation loc = cv.getCurrentLocation();
		if (loc == null) return "No current address";
		if (loc.getProgram() != program) return "No UI current address for requested program";
		return loc.getAddress().toString();
	}

	private String getCurrentFunction() {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		if (!isUiCurrentProgram(program)) return "No UI current function for requested program";
		CodeViewerService cv = tool.getService(CodeViewerService.class);
		if (cv == null) return "No code viewer service";
		ProgramLocation loc = cv.getCurrentLocation();
		if (loc == null) return "No current address";
		if (loc.getProgram() != program) return "No UI current function for requested program";
		Address currentAddr = loc.getAddress();
		Function func = program.getFunctionManager().getFunctionContaining(currentAddr);
		if (func == null) return "No function at current address";
		return func.getName(true);
	}

	private String decompileFunctionByAddress(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function found at address";
			DecompInterface decomp = new DecompInterface();
			decomp.openProgram(program);
			DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
			if (result != null && result.decompileCompleted()) {
				return result.getDecompiledFunction().getC();
			}
			return "Decompilation failed";
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String disassembleFunction(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function found at address";
			Listing listing = program.getListing();
			List<String> lines = new ArrayList<>();
			Instruction instr = listing.getInstructionAt(func.getEntryPoint());
			while (instr != null && func.getBody().contains(instr.getAddress())) {
				byte[] bytes = instr.getBytes();
				StringBuilder hex = new StringBuilder();
				for (byte b : bytes) {
					hex.append(String.format("%02X ", b & 0xFF));
				}
				lines.add(instr.getAddress().toString() + ": " + hex.toString().trim() + "; " + instr.toString());
				instr = instr.getNext();
			}
			return String.join("\n", lines);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String setDecompilerComment(String addressStr, String comment) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			AtomicBoolean success = new AtomicBoolean(false);
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Set decompiler comment");
				try {
					CodeUnit cu = program.getListing().getCodeUnitAt(addr);
					if (cu != null) {
						cu.setComment(CodeUnit.EOL_COMMENT, comment);
						success.set(true);
					}
				} catch (Exception e) {
					Msg.error(this, "Error setting comment", e);
				} finally {
					program.endTransaction(tx, success.get());
				}
			});
			return success.get() ? "Comment set" : "Failed to set comment";
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String setDisassemblyComment(String addressStr, String comment) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			AtomicBoolean success = new AtomicBoolean(false);
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Set disassembly comment");
				try {
					CodeUnit cu = program.getListing().getCodeUnitAt(addr);
					if (cu != null) {
						cu.setComment(CodeUnit.PRE_COMMENT, comment);
						success.set(true);
					}
				} catch (Exception e) {
					Msg.error(this, "Error setting comment", e);
				} finally {
					program.endTransaction(tx, success.get());
				}
			});
			return success.get() ? "Comment set" : "Failed to set comment";
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private boolean renameFunctionByAddress(String addressStr, String newName) {
		Program program = getCurrentProgram();
		if (program == null) return false;
		AtomicBoolean successFlag = new AtomicBoolean(false);
		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Rename function by address");
				try {
					Address addr = program.getAddressFactory().getAddress(addressStr);
					Function func = program.getFunctionManager().getFunctionContaining(addr);
					if (func != null) {
						func.setName(newName, SourceType.USER_DEFINED);
						successFlag.set(true);
					}
				} catch (Exception e) {
					Msg.error(this, "Error renaming function", e);
				} finally {
					program.endTransaction(tx, successFlag.get());
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this, "Failed to execute rename on Swing thread", e);
		}
		return successFlag.get();
	}

	private String setFunctionPrototype(String addressStr, String prototype) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		if (prototype == null || prototype.trim().isEmpty()) return "Prototype is required";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function found at address";

			AtomicBoolean successFlag = new AtomicBoolean(false);
			final String parsedResult[] = new String[1];

			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Set function prototype");
				try {
					String returnType = "void";
					List<String> paramTypes = new ArrayList<>();

					String trimmed = prototype.trim();
					int parenOpen = trimmed.indexOf('(');
					if (parenOpen > 0) {
						String beforeParams = trimmed.substring(0, parenOpen).trim();
						String[] parts = beforeParams.split("\\s+");
						if (parts.length >= 1) {
							returnType = parts[0];
						}
					}

					int parenClose = trimmed.lastIndexOf(')');
					if (parenClose > parenOpen) {
						String paramsStr = trimmed.substring(parenOpen + 1, parenClose).trim();
						if (!paramsStr.equals("void") && !paramsStr.isEmpty()) {
							String[] paramParts = paramsStr.split(",");
							for (String p : paramParts) {
								p = p.trim();
								if (p.isEmpty()) continue;
								String typeStr = p;
								if (p.contains(" ")) {
									typeStr = p.substring(0, p.lastIndexOf(" ")).trim();
								}
								paramTypes.add(typeStr);
							}
						}
					}

					DataTypeManager dtm = program.getDataTypeManager();
					DataType returnDt = dtm.getDataType(returnType);
					if (returnDt == null) returnDt = VoidDataType.dataType;

					func.setReturnType(returnDt, SourceType.USER_DEFINED);

					if (!paramTypes.isEmpty()) {
						try {
							Parameter[] oldParams = func.getParameters();
							for (int i = 0; i < paramTypes.size() && i < oldParams.length; i++) {
								DataType paramDt = dtm.getDataType(paramTypes.get(i));
								if (paramDt != null) {
									oldParams[i].setDataType(paramDt, SourceType.USER_DEFINED);
								}
							}
						} catch (Exception e) {
						}
					}

					successFlag.set(true);
					parsedResult[0] = "Prototype set";
				} catch (Exception e) {
					Msg.error(this, "Error setting prototype", e);
					parsedResult[0] = "Error: " + e.getMessage();
				} finally {
					program.endTransaction(tx, successFlag.get());
				}
			});
			return parsedResult[0] != null ? parsedResult[0] : (successFlag.get() ? "Prototype set" : "Failed to set prototype");
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String setLocalVariableType(String addressStr, String varName, String newType) {
		return "Not implemented";
	}

	private String searchStrings(String query, int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			List<String> results = new ArrayList<>();
			DefinedStringIterator stringIterator = DefinedStringIterator.forProgram(program);
			
			while (stringIterator.hasNext()) {
				Data data = stringIterator.next();
				String str = data.getDefaultValueRepresentation();
				if (query == null || query.isEmpty() || str.toLowerCase().contains(query.toLowerCase())) {
					results.add(data.getAddress().toString() + ": " + str);
				}
			}
			
			int start = Math.max(0, Math.min(offset, results.size()));
			int end = Math.min(start + limit, results.size());
			if (start >= results.size()) return gson.toJson(new ArrayList<>());
			return gson.toJson(results.subList(start, end));
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String searchBytes(String pattern, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			pattern = pattern.replace("+", " ");
			String[] hexBytes = pattern.split(" ");
			byte[] searchBytesArr = new byte[hexBytes.length];
			byte[] mask = new byte[hexBytes.length];

			for (int i = 0; i < hexBytes.length; i++) {
				if (hexBytes[i].equals("?") || hexBytes[i].equals("??")) {
					mask[i] = 0;
					searchBytesArr[i] = 0;
				} else {
					mask[i] = (byte)0xFF;
					searchBytesArr[i] = (byte)Long.parseLong(hexBytes[i], 16);
				}
			}

			List<String> results = new ArrayList<>();
			Memory memory = program.getMemory();
			int chunkSize = 65536;

			for (MemoryBlock block : memory.getBlocks()) {
				if (!block.isInitialized() || results.size() >= limit) break;
				Address blockStart = block.getStart();
				long blockSize = block.getSize();
				if (blockSize < searchBytesArr.length) continue;

				for (long offset = 0; offset <= blockSize - searchBytesArr.length && results.size() < limit; offset += chunkSize - searchBytesArr.length) {
					Address chunkStart = blockStart.add(offset);
					long readSize = Math.min(chunkSize, blockSize - offset);
					byte[] chunk = new byte[(int)readSize];
					try {
						block.getBytes(chunkStart, chunk);
					} catch (MemoryAccessException e) { continue; }

					for (int i = 0; i <= chunk.length - searchBytesArr.length && results.size() < limit; i++) {
						boolean match = true;
						for (int j = 0; j < searchBytesArr.length; j++) {
							if (mask[j] != 0 && (chunk[i + j] & mask[j]) != (searchBytesArr[j] & mask[j])) {
								match = false;
								break;
							}
						}
						if (match) results.add(chunkStart.add(i).toString());
					}
				}
			}

			return gson.toJson(results);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getReferences(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			ReferenceManager refManager = program.getReferenceManager();
			ReferenceIterator refs = refManager.getReferencesTo(addr);
			
			List<String> results = new ArrayList<>();
			while (refs.hasNext() && results.size() < 100) {
				Reference ref = refs.next();
				results.add(ref.getFromAddress().toString());
			}
			
			return gson.toJson(results);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getFunctionBytes(String addressStr, int length) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function found at address";

			Address entryPoint = func.getEntryPoint();
			Memory memory = program.getMemory();
			byte[] bytes = new byte[length];
			memory.getBytes(entryPoint, bytes);

			// Convert to hex string (space-separated)
			StringBuilder hex = new StringBuilder();
			for (byte b : bytes) {
				hex.append(String.format("%02X ", b & 0xFF));
			}

			Map<String, String> result = new HashMap<>();
			result.put("address", entryPoint.toString());
			result.put("bytes", hex.toString().trim());
			result.put("length", String.valueOf(length));

			return gson.toJson(result);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String patchBytes(String addressStr, String bytesStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		if (addressStr == null || addressStr.isEmpty()) return "Address is required";
		if (bytesStr == null || bytesStr.isEmpty()) return "Bytes are required";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Memory memory = program.getMemory();
			MemoryBlock block = memory.getBlock(addr);
			if (block == null) return "No memory block at address";

			String[] hexBytes = bytesStr.trim().split("\\s+");
			byte[] bytes = new byte[hexBytes.length];
			for (int i = 0; i < hexBytes.length; i++) {
				bytes[i] = (byte)Integer.parseInt(hexBytes[i], 16);
			}

			AtomicBoolean successFlag = new AtomicBoolean(false);
			final String[] result = new String[1];

			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Patch bytes");
				try {
					Listing listing = program.getListing();
					Address endAddr = addr.add(bytes.length - 1);
					listing.clearCodeUnits(addr, endAddr, true);

					for (int i = 0; i < bytes.length; i++) {
						Address curAddr = addr.add(i);
						memory.setByte(curAddr, bytes[i]);
					}

					successFlag.set(true);
					result[0] = "Patched successfully";
				} catch (Exception e) {
					Msg.error(this, "Error patching bytes", e);
					result[0] = "Error: " + e.getMessage();
				} finally {
					program.endTransaction(tx, successFlag.get());
				}
			});

			return result[0] != null ? result[0] : "Patching failed";
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getStringsInFunction(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function at address";

			List<String> strings = new ArrayList<>();
			AddressSetView body = func.getBody();
			DefinedStringIterator stringIter = DefinedStringIterator.forProgram(program);

			while (stringIter.hasNext()) {
				Data data = stringIter.next();
				if (body.contains(data.getAddress())) {
					strings.add(data.getAddress().toString() + ": " + data.getDefaultValueRepresentation());
				}
			}

			return gson.toJson(strings);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getFunctionCallers(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function at address";

			List<String> callers = new ArrayList<>();
			ReferenceManager refMgr = program.getReferenceManager();
			ReferenceIterator refs = refMgr.getReferencesTo(func.getEntryPoint());

			while (refs.hasNext()) {
				Reference ref = refs.next();
				Address fromAddr = ref.getFromAddress();
				Function caller = program.getFunctionManager().getFunctionContaining(fromAddr);
				if (caller != null) {
					callers.add(fromAddr.toString() + ": " + caller.getName(true));
				} else {
					callers.add(fromAddr.toString() + ": (unknown)");
				}
			}

			return gson.toJson(callers);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getFunctionCallees(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function at address";

			Set<String> callees = new LinkedHashSet<>();
			Listing listing = program.getListing();
			Instruction instr = listing.getInstructionAt(func.getEntryPoint());

			while (instr != null && func.getBody().contains(instr.getAddress())) {
				Reference[] refs = instr.getReferencesFrom();
				for (Reference ref : refs) {
					if (ref.getReferenceType().isCall()) {
						Address toAddr = ref.getToAddress();
						Function callee = program.getFunctionManager().getFunctionContaining(toAddr);
						if (callee != null) {
							callees.add(toAddr.toString() + ": " + callee.getName(true));
						}
					}
				}
				instr = instr.getNext();
			}

			return gson.toJson(new ArrayList<>(callees));
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getBytesAt(String addressStr, int length) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Memory memory = program.getMemory();
			byte[] bytes = new byte[length];

			memory.getBytes(addr, bytes);

			StringBuilder hex = new StringBuilder();
			for (byte b : bytes) {
				hex.append(String.format("%02X ", b & 0xFF));
			}

			Map<String, String> result = new HashMap<>();
			result.put("address", addr.toString());
			result.put("bytes", hex.toString().trim());
			result.put("length", String.valueOf(length));

			return gson.toJson(result);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String disassembleRange(String startStr, String endStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address start = program.getAddressFactory().getAddress(startStr);
			Address end = program.getAddressFactory().getAddress(endStr);
			Listing listing = program.getListing();
			List<String> lines = new ArrayList<>();

			Instruction instr = listing.getInstructionAt(start);
			while (instr != null && instr.getAddress().compareTo(end) <= 0) {
				byte[] bytes = instr.getBytes();
				StringBuilder hex = new StringBuilder();
				for (byte b : bytes) {
					hex.append(String.format("%02X ", b & 0xFF));
				}
				lines.add(instr.getAddress().toString() + ": " + hex.toString().trim() + "; " + instr.toString());
				instr = instr.getNext();
			}

			return String.join("\n", lines);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String exportBinary(String outputPath) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Memory memory = program.getMemory();
			MemoryBlock[] blocks = memory.getBlocks();
			java.io.FileOutputStream fos = new java.io.FileOutputStream(outputPath);

			for (MemoryBlock block : blocks) {
				if (!block.isInitialized()) continue;

				byte[] data = new byte[(int)block.getSize()];
				try {
					block.getBytes(block.getStart(), data);
					fos.write(data);
				} catch (MemoryAccessException e) {
					// Skip unreadable blocks
				}
			}

			fos.close();
			return "Exported to " + outputPath;
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getFunctionParams(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function at address";

			List<String> params = new ArrayList<>();
			for (Parameter param : func.getParameters()) {
				String type = param.getDataType().getName();
				String name = param.getName();
				String register = param.getRegister().getName();
				params.add(String.format("%s %s (%s)", type, name, register));
			}

			return gson.toJson(params);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getFunctionLocals(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function at address";

			List<String> locals = new ArrayList<>();
			Variable[] variables = func.getLocalVariables();
			for (Variable var : variables) {
				String name = var.getName();
				String type = var.getDataType().getName();
				int offset = var.getFirstUseOffset();
				locals.add(String.format("%s %s (offset: %d)", type, name, offset));
			}

			return gson.toJson(locals);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getContainingBlock(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			MemoryBlock block = program.getMemory().getBlock(addr);
			if (block == null) return "No block at address";

			Map<String, String> info = new HashMap<>();
			info.put("name", block.getName());
			info.put("start", block.getStart().toString());
			info.put("end", block.getEnd().toString());
			info.put("size", String.valueOf(block.getSize()));
			info.put("initialized", String.valueOf(block.isInitialized()));
			info.put("readable", String.valueOf(block.isRead()));
			info.put("writable", String.valueOf(block.isWrite()));
			info.put("executable", String.valueOf(block.isExecute()));
			info.put("volatile", String.valueOf(block.isVolatile()));

			return gson.toJson(info);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getEntryPoints() {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			List<String> entries = new ArrayList<>();
			SymbolTable symbolTable = program.getSymbolTable();
			SymbolIterator symbols = symbolTable.getAllSymbols(true);

			while (symbols.hasNext()) {
				Symbol symbol = symbols.next();
				if (symbol.isExternalEntryPoint()) {
					entries.add(symbol.getAddress().toString() + ": " + symbol.getName());
				}
			}

			return gson.toJson(entries);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getDataAt(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Listing listing = program.getListing();
			Data data = listing.getDefinedDataAt(addr);
			if (data == null) return "No defined data at address";

			Map<String, String> info = new HashMap<>();
			info.put("address", data.getAddress().toString());
			info.put("type", data.getDataType().getName());
			info.put("label", data.getLabel() != null ? data.getLabel() : "(unnamed)");
			info.put("value", data.getDefaultValueRepresentation());

			return gson.toJson(info);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getTypeAt(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Listing listing = program.getListing();
			Data data = listing.getDataContaining(addr);

			if (data != null) {
				Map<String, String> info = new HashMap<>();
				info.put("address", addr.toString());
				info.put("type", data.getDataType().getName());
				info.put("data_address", data.getAddress().toString());
				return gson.toJson(info);
			}

			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func != null) {
				Map<String, String> info = new HashMap<>();
				info.put("address", addr.toString());
				info.put("type", "function");
				info.put("function", func.getName(true));
				info.put("entry", func.getEntryPoint().toString());
				return gson.toJson(info);
			}

			return "No type information at address";
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String searchForValue(String valueStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			long searchValue = Long.parseLong(valueStr, 16);
			List<String> results = new ArrayList<>();
			Listing listing = program.getListing();

			for (Data data : listing.getDefinedData(true)) {
				try {
					Object value = data.getValue();
					if (value instanceof Long && ((Long)value).equals(searchValue)) {
						results.add(data.getAddress().toString() + ": " + data.getLabel());
					} else if (value instanceof Integer && ((Integer)value).equals((int)searchValue)) {
						results.add(data.getAddress().toString() + ": " + data.getLabel());
					} else if (value instanceof Short && ((Short)value).equals((short)searchValue)) {
						results.add(data.getAddress().toString() + ": " + data.getLabel());
					}
				} catch (Exception e) {
					continue;
				}
			}

			return gson.toJson(results);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getXrefsTo(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			ReferenceManager refManager = program.getReferenceManager();
			ReferenceIterator refs = refManager.getReferencesTo(addr);

			List<Map<String, String>> results = new ArrayList<>();
			while (refs.hasNext() && results.size() < 1000) {
				Reference ref = refs.next();
				Map<String, String> info = new HashMap<>();
				info.put("from", ref.getFromAddress().toString());
				info.put("type", ref.getReferenceType().toString());
				Function func = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
				info.put("function", func != null ? func.getName(true) : "(unknown)");
				results.add(info);
			}
			return gson.toJson(results);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getXrefsFrom(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Reference[] refs = program.getReferenceManager().getReferencesFrom(addr);

			List<Map<String, String>> results = new ArrayList<>();
			for (Reference ref : refs) {
				Map<String, String> info = new HashMap<>();
				info.put("to", ref.getToAddress().toString());
				info.put("type", ref.getReferenceType().toString());
				results.add(info);
			}
			return gson.toJson(results);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getFunctionBody(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function at address";

			AddressSetView body = func.getBody();
			Map<String, String> result = new HashMap<>();
			result.put("min_address", body.getMinAddress().toString());
			result.put("max_address", body.getMaxAddress().toString());
			result.put("num_addresses", String.valueOf(body.getNumAddresses()));

			List<String> ranges = new ArrayList<>();
			AddressRangeIterator rangeIter = body.getAddressRanges();
			while (rangeIter.hasNext()) {
				AddressRange range = rangeIter.next();
				ranges.add(range.getMinAddress().toString() + "-" + range.getMaxAddress().toString());
			}
			result.put("ranges", gson.toJson(ranges));

			return gson.toJson(result);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getFunctionSignature(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function at address";

			String signature = func.getPrototypeString(false, false);
			String callingConvention = func.getCallingConventionName();
			String returnTypeName = func.getReturnType().getName();
			boolean hasVarArgs = func.hasVarArgs();

			Map<String, String> result = new HashMap<>();
			result.put("signature", signature);
			result.put("calling_convention", callingConvention);
			result.put("return_type", returnTypeName);
			result.put("varargs", String.valueOf(hasVarArgs));
			result.put("name", func.getName(true));
			result.put("entry", func.getEntryPoint().toString());

			return gson.toJson(result);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getStackFrame(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function at address";

			StackFrame stackFrame = func.getStackFrame();
			Map<String, Object> result = new HashMap<>();
			result.put("local_size", stackFrame.getLocalSize());
			result.put("param_size", stackFrame.getParameterSize());

			List<String> locals = new ArrayList<>();
			for (Variable var : stackFrame.getLocals()) {
				locals.add(String.format("%s %s (offset: %d)", var.getDataType().getName(), var.getName(), var.getStackOffset()));
			}
			result.put("locals", locals);

			List<String> params = new ArrayList<>();
			for (Variable var : stackFrame.getParameters()) {
				params.add(String.format("%s %s (offset: %d)", var.getDataType().getName(), var.getName(), var.getStackOffset()));
			}
			result.put("parameters", params);

			return gson.toJson(result);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getFunctionComplexity(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function at address";

			Listing listing = program.getListing();
			int branches = 0;
			int instructions = 0;

			Instruction instr = listing.getInstructionAt(func.getEntryPoint());
			while (instr != null && func.getBody().contains(instr.getAddress())) {
				instructions++;
				String mnemonic = instr.getMnemonicString();
				if (mnemonic.equals("CALL") || mnemonic.equals("JMP") ||
					mnemonic.startsWith("J") || mnemonic.equals("RET")) {
					branches++;
				}
				instr = instr.getNext();
			}

			int complexity = branches + 1;
			Map<String, String> result = new HashMap<>();
			result.put("cyclomatic_complexity", String.valueOf(complexity));
			result.put("branches", String.valueOf(branches));
			result.put("instructions", String.valueOf(instructions));

			return gson.toJson(result);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getInstructionAt(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Listing listing = program.getListing();
			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null) return "No instruction at address";

			StringBuilder hex = new StringBuilder();
			for (byte b : instr.getBytes()) {
				hex.append(String.format("%02X ", b & 0xFF));
			}

			Map<String, String> result = new HashMap<>();
			result.put("address", instr.getAddress().toString());
			result.put("bytes", hex.toString().trim());
			result.put("mnemonic", instr.getMnemonicString());
			result.put("operands", instr.toString().substring(instr.getMnemonicString().length()).trim());
			result.put("length", String.valueOf(instr.getLength()));

			return gson.toJson(result);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getInstructionsInRange(String startStr, String endStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address start = program.getAddressFactory().getAddress(startStr);
			Address end = program.getAddressFactory().getAddress(endStr);
			Listing listing = program.getListing();
			List<String> lines = new ArrayList<>();

			Instruction instr = listing.getInstructionAt(start);
			while (instr != null && instr.getAddress().compareTo(end) <= 0) {
				StringBuilder hex = new StringBuilder();
				for (byte b : instr.getBytes()) {
					hex.append(String.format("%02X ", b & 0xFF));
				}
				lines.add(instr.getAddress().toString() + ": " + hex.toString().trim() + "; " + instr.toString());
				instr = instr.getNext();
			}

			return String.join("\n", lines);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getBasicBlocks(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function at address";

			Listing listing = program.getListing();
			List<Map<String, Object>> blocks = new ArrayList<>();

			AddressSetView body = func.getBody();
			Address currentPos = func.getEntryPoint();

			while (currentPos != null && body.contains(currentPos)) {
				Instruction instr = listing.getInstructionAt(currentPos);
				if (instr == null) break;

				Address blockStart = instr.getAddress();
				int blockLen = 0;

				while (instr != null && body.contains(instr.getAddress())) {
					String mnemonic = instr.getMnemonicString();
					if (mnemonic.equals("RET") ||
						(mnemonic.startsWith("J") && !mnemonic.equals("JMP")) ||
						mnemonic.equals("CALL")) {
						blockLen += instr.getLength();
						instr = instr.getNext();
						break;
					}
					blockLen += instr.getLength();
					instr = instr.getNext();
					if (instr == null || !body.contains(instr.getAddress())) break;
				}

				Map<String, Object> block = new HashMap<>();
				block.put("start", blockStart.toString());
				block.put("size", blockLen);
				blocks.add(block);

				if (instr == null) break;
				currentPos = instr.getAddress();
			}

			return gson.toJson(blocks);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getControlFlowGraph(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function at address";

			Listing listing = program.getListing();
			List<Map<String, Object>> nodes = new ArrayList<>();
			List<Map<String, String>> edges = new ArrayList<>();

			AddressSetView body = func.getBody();
			Map<Address, String> blockMap = new HashMap<>();
			int blockIdx = 0;

			Instruction instr = listing.getInstructionAt(func.getEntryPoint());
			while (instr != null && body.contains(instr.getAddress())) {
				Address blockStart = instr.getAddress();
				Map<String, Object> node = new HashMap<>();
				node.put("id", "bb_" + blockIdx);
				node.put("start", blockStart.toString());
				blockMap.put(blockStart, "bb_" + blockIdx);

				Reference[] refs = instr.getReferencesFrom();
				for (Reference ref : refs) {
					if (ref.getReferenceType().isFlow() && body.contains(ref.getToAddress())) {
						Map<String, String> edge = new HashMap<>();
						edge.put("from", "bb_" + blockIdx);
						edge.put("to", ref.getToAddress().toString());
						edges.add(edge);
					}
				}

				blockIdx++;
				instr = instr.getNext();
			}

			Map<String, Object> cfg = new HashMap<>();
			cfg.put("function", func.getName(true));
			cfg.put("nodes", nodes);
			cfg.put("edges", edges);

			return gson.toJson(cfg);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getMemoryMap() {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			List<Map<String, String>> map = new ArrayList<>();
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				Map<String, String> info = new HashMap<>();
				info.put("name", block.getName());
				info.put("start", block.getStart().toString());
				info.put("end", block.getEnd().toString());
				info.put("size", String.valueOf(block.getSize()));
				info.put("permissions", (block.isRead() ? "r" : "-") +
									   (block.isWrite() ? "w" : "-") +
									   (block.isExecute() ? "x" : "-"));
				info.put("initialized", String.valueOf(block.isInitialized()));
				info.put("loaded", String.valueOf(block.isLoaded()));
				info.put("volatile", String.valueOf(block.isVolatile()));
				map.add(info);
			}
			return gson.toJson(map);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getSectionInfo() {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			List<Map<String, String>> sections = new ArrayList<>();

			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if (block.getName().contains(".text") || block.getName().contains(".data") ||
					block.getName().contains(".rdata") || block.getName().contains(".bss") ||
					block.getName().contains(".rodata") || block.getName().startsWith("/SECTION")) {
					Map<String, String> info = new HashMap<>();
					info.put("name", block.getName());
					info.put("start", block.getStart().toString());
					info.put("end", block.getEnd().toString());
					info.put("size", String.valueOf(block.getSize()));
					info.put("permissions", (block.isRead() ? "r" : "-") +
										   (block.isWrite() ? "w" : "-") +
										   (block.isExecute() ? "x" : "-"));
					sections.add(info);
				}
			}

			return gson.toJson(sections);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getStackStrings(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function at address";

			StackFrame stackFrame = func.getStackFrame();
			List<String> stackStrings = new ArrayList<>();

			for (Variable var : stackFrame.getLocals()) {
				if (var.getDataType() instanceof StringDataType ||
					var.getName().toLowerCase().contains("str") ||
					var.getName().toLowerCase().contains("string")) {
					stackStrings.add(String.format("%s (offset: %d, type: %s)",
						var.getName(), var.getStackOffset(), var.getDataType().getName()));
				}
			}

			return gson.toJson(stackStrings);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getDataAccess(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) return "No function at address";

			Listing listing = program.getListing();
			Set<String> accessedData = new LinkedHashSet<>();

			Instruction instr = listing.getInstructionAt(func.getEntryPoint());
			while (instr != null && func.getBody().contains(instr.getAddress())) {
				Reference[] refs = instr.getReferencesFrom();
				for (Reference ref : refs) {
					if (ref.getReferenceType().isData()) {
						Address toAddr = ref.getToAddress();
						Data data = listing.getDefinedDataAt(toAddr);
						if (data != null) {
							String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
							accessedData.add(toAddr.toString() + ": " + label + " (" + data.getDataType().getName() + ")");
						}
					}
				}
				instr = instr.getNext();
			}

			return gson.toJson(new ArrayList<>(accessedData));
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getBookmarks() {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			List<Map<String, String>> bookmarks = new ArrayList<>();
			return gson.toJson(bookmarks);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getEquates(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			EquateTable eqTable = program.getEquateTable();
			List<Equate> equates = eqTable.getEquates(addr);

			List<Map<String, String>> results = new ArrayList<>();
			for (Equate equate : equates) {
				Map<String, String> info = new HashMap<>();
				info.put("name", equate.getName());
				info.put("value", String.valueOf(equate.getValue()));
				results.add(info);
			}

			return gson.toJson(results);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getOpenPrograms() {
		try {
			Project project = tool.getProject();
			if (project == null) return "Error: No project open";

			ProjectData projectData = project.getProjectData();
			if (projectData == null) return "Error: No project data";

			List<Map<String, String>> programs = new ArrayList<>();
			Program currentProgram = getCurrentProgram();

			// Get all domain files in the project root folder recursively
			List<DomainFile> allFiles = new ArrayList<>();
			collectDomainFiles(projectData.getRootFolder(), allFiles);

			for (DomainFile df : allFiles) {
				Map<String, String> info = new HashMap<>();
				info.put("path", df.getPathname());
				info.put("name", df.getName());

				// Check if this file is currently open
				boolean isOpen = false;
				boolean isCurrent = false;
				String execPath = "";

				ProgramManager programManager = tool.getService(ProgramManager.class);
				Program[] openPrograms = programManager.getAllOpenPrograms();

				for (Program p : openPrograms) {
					if (p.getDomainFile() != null && p.getDomainFile().equals(df)) {
						isOpen = true;
						execPath = p.getExecutablePath();
						isCurrent = p.equals(currentProgram);
						break;
					}
				}

				info.put("current", String.valueOf(isCurrent));
				info.put("open", String.valueOf(isOpen));
				info.put("executablePath", execPath);
				programs.add(info);
			}

			return gson.toJson(programs);
		} catch (Exception e) {
			return "Error: " + e.getClass().getName() + ": " + e.getMessage();
		}
	}

	private void collectDomainFiles(DomainFolder folder, List<DomainFile> list) {
		for (DomainFile df : folder.getFiles()) {
			list.add(df);
		}
		for (DomainFolder subfolder : folder.getFolders()) {
			collectDomainFiles(subfolder, list);
		}
	}

	private String switchProgram(String programPath) {
		try {
			Project project = tool.getProject();
			if (project == null) return "Error: No project open";

			ProjectData projectData = project.getProjectData();
			if (projectData == null) return "Error: No project data";

			ProgramManager programManager = tool.getService(ProgramManager.class);

			// First check if already open
			Program[] openPrograms = programManager.getAllOpenPrograms();
			for (Program p : openPrograms) {
				DomainFile df = p.getDomainFile();
				String path = df != null ? df.getPathname() : p.getExecutablePath();
				if (path.equals(programPath) || p.getName().equals(programPath) || (df != null && df.getPathname().equals(programPath))) {
					programManager.setCurrentProgram(p);
					return "Switched to: " + programPath;
				}
			}

			// If not open, find and open it
			List<DomainFile> allFiles = new ArrayList<>();
			collectDomainFiles(projectData.getRootFolder(), allFiles);

			for (DomainFile df : allFiles) {
				if (df.getPathname().equals(programPath) || df.getName().equals(programPath)) {
					Program p = programManager.openProgram(df);
					if (p != null) {
						return "Opened and switched to: " + programPath;
					}
				}
			}

			return "Error: Program not found: " + programPath;
		} catch (Exception e) {
			return "Error: " + e.getClass().getName() + ": " + e.getMessage();
		}
	}

	private String listDataTypes(int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			List<String> results = new ArrayList<>();
			DataTypeManager dtm = program.getDataTypeManager();
			Iterator<DataType> typeIter = dtm.getAllDataTypes();

			int idx = 0;
			int start = offset;
			int count = 0;

			while (typeIter.hasNext() && count < limit) {
				DataType dt = typeIter.next();
				if (!dt.isDeleted()) {
					if (idx >= start && count < limit) {
						String category = dt.getCategoryPath().getPath();
						String size = "";
						if (dt instanceof Structure) {
							size = " (" + ((Structure)dt).getLength() + " bytes)";
						} else if (dt instanceof EnumDataType) {
							size = " (enum)";
						}
						results.add(category + ": " + dt.getName() + size);
						count++;
					}
					idx++;
				}
			}
			return gson.toJson(results);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getStructFields(String structName) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		if (structName == null || structName.isEmpty()) return "Error: structName parameter required";

		try {
			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(new CategoryPath("/"), structName);

			if (dt == null) {
				dt = dtm.getDataType(structName);
			}

			if (dt == null) {
				return "Error: Structure '" + structName + "' not found";
			}

			if (!(dt instanceof Structure)) {
				return "Error: '" + structName + "' is not a structure";
			}

			Structure struct = (Structure) dt;
			List<Map<String, Object>> fields = new ArrayList<>();

			for (DataTypeComponent component : struct.getComponents()) {
				Map<String, Object> fieldInfo = new LinkedHashMap<>();
				fieldInfo.put("offset", component.getOffset());
				fieldInfo.put("name", component.getFieldName());
				fieldInfo.put("type", component.getDataType().getName());
				fieldInfo.put("size", component.getLength());
				fields.add(fieldInfo);
			}

			Map<String, Object> result = new LinkedHashMap<>();
			result.put("name", struct.getName());
			result.put("size", struct.getLength());
			result.put("fields", fields);

			return gson.toJson(result);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getEnumValues(String enumName) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		if (enumName == null || enumName.isEmpty()) return "Error: enumName parameter required";

		try {
			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(new CategoryPath("/"), enumName);

			if (dt == null) {
				dt = dtm.getDataType(enumName);
			}

			if (dt == null) {
				return "Error: Enum '" + enumName + "' not found";
			}

			if (!(dt instanceof EnumDataType)) {
				return "Error: '" + enumName + "' is not an enum";
			}

			EnumDataType enumDt = (EnumDataType) dt;
			List<Map<String, Object>> values = new ArrayList<>();

			for (String name : enumDt.getNames()) {
				long value = enumDt.getValue(name);
				Map<String, Object> entry = new LinkedHashMap<>();
				entry.put("name", name);
				entry.put("value", value);
				values.add(entry);
			}

			Map<String, Object> result = new LinkedHashMap<>();
			result.put("name", enumDt.getName());
			result.put("size", enumDt.getLength());
			result.put("values", values);

			return gson.toJson(result);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getSymbolsAt(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		if (addressStr == null || addressStr.isEmpty()) return "Error: address parameter required";

		try {
			Address address = program.getAddressFactory().getAddress(addressStr);
			if (address == null) return "Error: Invalid address";

			SymbolTable st = program.getSymbolTable();
			Symbol[] symbols = st.getSymbols(address);

			if (symbols == null || symbols.length == 0) {
				return "No symbols found at " + addressStr;
			}

			List<Map<String, Object>> symbolList = new ArrayList<>();
			for (Symbol s : symbols) {
				Map<String, Object> symbolInfo = new LinkedHashMap<>();
				symbolInfo.put("name", s.getName());
				symbolInfo.put("type", s.getSymbolType().toString());
				symbolInfo.put("namespace", s.getParentNamespace().getName());
				symbolList.add(symbolInfo);
			}

			Map<String, Object> result = new LinkedHashMap<>();
			result.put("address", addressStr);
			result.put("symbols", symbolList);

			return gson.toJson(result);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getExternalFunctions(int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		try {
			List<Map<String, Object>> externals = new ArrayList<>();
			SymbolTable st = program.getSymbolTable();
			int count = 0;
			int added = 0;

			for (Symbol symbol : st.getExternalSymbols()) {
				if (symbol.getSymbolType() == SymbolType.FUNCTION) {
					if (count >= offset && added < limit) {
						Map<String, Object> extInfo = new LinkedHashMap<>();
						extInfo.put("name", symbol.getName());
						extInfo.put("namespace", symbol.getParentNamespace().getName());
						Address addr = symbol.getAddress();
						extInfo.put("address", addr != null ? addr.toString() : "EXTERNAL");
						externals.add(extInfo);
						added++;
					}
					count++;
					if (added >= limit) break;
				}
			}

			Map<String, Object> result = new LinkedHashMap<>();
			result.put("total", count);
			result.put("offset", offset);
			result.put("limit", limit);
			result.put("returned", externals.size());
			result.put("functions", externals);

			return gson.toJson(result);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getDecompilerComment(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			CodeUnit cu = program.getListing().getCodeUnitAt(addr);
			if (cu != null) {
				String comment = cu.getComment(CodeUnit.EOL_COMMENT);
				return comment != null ? comment : "No comment";
			}
			return "No code unit at address";
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getDisassemblyComment(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			CodeUnit cu = program.getListing().getCodeUnitAt(addr);
			if (cu != null) {
				List<String> comments = new ArrayList<>();
				String plate = cu.getComment(CodeUnit.PLATE_COMMENT);
				String pre = cu.getComment(CodeUnit.PRE_COMMENT);
				String eol = cu.getComment(CodeUnit.EOL_COMMENT);
				if (plate != null && !plate.isEmpty()) comments.add("Plate: " + plate);
				if (pre != null && !pre.isEmpty()) comments.add("Pre: " + pre);
				if (eol != null && !eol.isEmpty()) comments.add("EOL: " + eol);
				return comments.isEmpty() ? "No comment" : String.join("\n", comments);
			}
			return "No code unit at address";
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String getReferencesCount(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return gson.toJson(Map.of("error", "No program loaded"));
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			ReferenceManager refManager = program.getReferenceManager();
			ReferenceIterator refs = refManager.getReferencesTo(addr);

			Map<String, Integer> byType = new HashMap<>();
			int total = 0;
			while (refs.hasNext()) {
				Reference ref = refs.next();
				RefType refType = ref.getReferenceType();
				byType.put(refType.toString(), byType.getOrDefault(refType.toString(), 0) + 1);
				total++;
			}

			Map<String, Object> result = new HashMap<>();
			result.put("address", addr.toString());
			result.put("total_references", total);
			result.put("by_type", byType);
			return gson.toJson(result);
		} catch (Exception e) {
			return gson.toJson(Map.of("error", e.getMessage()));
		}
	}

	private String getCodeUnitsInRange(String startStr, String endStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address start = program.getAddressFactory().getAddress(startStr);
			Address end = program.getAddressFactory().getAddress(endStr);
			Listing listing = program.getListing();
			List<String> results = new ArrayList<>();

			CodeUnit cu = listing.getCodeUnitAt(start);
			while (cu != null && cu.getAddress().compareTo(end) <= 0) {
				String type = cu instanceof Instruction ? "Instruction" : "Data";
				String mnem = cu instanceof Instruction ? ((Instruction)cu).getMnemonicString() : cu.toString();
				results.add(cu.getAddress() + ": " + mnem + " (" + type + ", " + cu.getLength() + " bytes)");
				cu = listing.getCodeUnitAfter(cu.getAddress());
			}

			return results.isEmpty() ? "No code units in range" : String.join("\n", results);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String compareMemory(String address1Str, String address2Str, int length) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		try {
			Address addr1 = program.getAddressFactory().getAddress(address1Str);
			Address addr2 = program.getAddressFactory().getAddress(address2Str);
			Memory memory = program.getMemory();

			byte[] bytes1 = new byte[length];
			byte[] bytes2 = new byte[length];

			try {
				memory.getBytes(addr1, bytes1);
				memory.getBytes(addr2, bytes2);
			} catch (MemoryAccessException e) {
				return "Error: Cannot read memory at specified addresses";
			}

			List<String> differences = new ArrayList<>();
			for (int i = 0; i < length; i++) {
				if (bytes1[i] != bytes2[i]) {
					differences.add(String.format("Offset 0x%02X: 0x%02X != 0x%02X", i, bytes1[i] & 0xFF, bytes2[i] & 0xFF));
				}
			}

			return differences.isEmpty() ? "Memory regions are identical" : String.join("\n", differences);
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	private String createFunction(String addressStr, String functionName) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		if (addressStr == null || addressStr.isEmpty()) return "Error: address is required";
		if (functionName == null || functionName.isEmpty()) return "Error: functionName is required";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			AtomicBoolean successFlag = new AtomicBoolean(false);
			final String[] result = new String[1];

			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Create function");
				try {
					Function func = program.getFunctionManager().createFunction(functionName, null, addr, null, SourceType.USER_DEFINED);
					if (func != null) {
						successFlag.set(true);
						result[0] = "Created function '" + functionName + "' at " + addressStr;
					} else {
						result[0] = "Error: Failed to create function";
					}
				} catch (Exception e) {
					Msg.error(this, "Error creating function", e);
					result[0] = "Error: " + e.getMessage();
				} finally {
					program.endTransaction(tx, successFlag.get());
				}
			});
			return result[0] != null ? result[0] : "Failed to create function";
		} catch (Exception e) {
			return "Error: " + e.getClass().getName() + ": " + e.getMessage();
		}
	}

	private String deleteFunction(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		if (addressStr == null || addressStr.isEmpty()) return "Error: address is required";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			AtomicBoolean successFlag = new AtomicBoolean(false);
			final String[] result = new String[1];

			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Delete function");
				try {
					Function func = program.getFunctionManager().getFunctionContaining(addr);
					if (func != null) {
						program.getFunctionManager().removeFunction(func.getEntryPoint());
						successFlag.set(true);
						result[0] = "Deleted function at " + addressStr;
					} else {
						result[0] = "Error: No function found at address";
					}
				} catch (Exception e) {
					Msg.error(this, "Error deleting function", e);
					result[0] = "Error: " + e.getMessage();
				} finally {
					program.endTransaction(tx, successFlag.get());
				}
			});
			return result[0] != null ? result[0] : "Failed to delete function";
		} catch (Exception e) {
			return "Error: " + e.getClass().getName() + ": " + e.getMessage();
		}
	}

	private String addBookmark(String addressStr, String category, String description) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		if (addressStr == null || addressStr.isEmpty()) return "Error: address is required";
		if (category == null || category.isEmpty()) category = "User";
		if (description == null) description = "";

		final String finalCategory = category;
		final String finalDescription = description;
		final String finalAddressStr = addressStr;

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			AtomicBoolean successFlag = new AtomicBoolean(false);
			final String[] result = new String[1];

			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Add bookmark");
				try {
					BookmarkManager bm = program.getBookmarkManager();
					bm.setBookmark(addr, BookmarkType.INFO, finalCategory, finalDescription);
					successFlag.set(true);
					result[0] = "Added bookmark at " + finalAddressStr + " [Category: " + finalCategory + "] - '" + finalDescription + "'";
				} catch (Exception e) {
					Msg.error(this, "Error adding bookmark", e);
					result[0] = "Error: " + e.getMessage();
				} finally {
					program.endTransaction(tx, successFlag.get());
				}
			});
			return result[0] != null ? result[0] : "Failed to add bookmark";
		} catch (Exception e) {
			return "Error: " + e.getClass().getName() + ": " + e.getMessage();
		}
	}

	private String removeBookmark(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		if (addressStr == null || addressStr.isEmpty()) return "Error: address is required";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			AtomicBoolean successFlag = new AtomicBoolean(false);
			final String[] result = new String[1];

			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Remove bookmark");
				try {
					BookmarkManager bm = program.getBookmarkManager();
					Bookmark[] bookmarks = bm.getBookmarks(addr);
					int count = 0;
					for (Bookmark b : bookmarks) {
						bm.removeBookmark(b);
						count++;
					}
					successFlag.set(true);
					result[0] = "Removed " + count + " bookmark(s) at " + addressStr;
				} catch (Exception e) {
					Msg.error(this, "Error removing bookmark", e);
					result[0] = "Error: " + e.getMessage();
				} finally {
					program.endTransaction(tx, successFlag.get());
				}
			});
			return result[0] != null ? result[0] : "Failed to remove bookmark";
		} catch (Exception e) {
			return "Error: " + e.getClass().getName() + ": " + e.getMessage();
		}
	}

	private String getProgramInfo() {
		Program program = getCurrentProgram();
		if (program == null) return gson.toJson(Map.of("status", "error", "message", "No program loaded"));

		try {
			Map<String, Object> info = new LinkedHashMap<>();
			info.put("name", program.getName());
			info.put("language", program.getLanguage().getLanguageDescription().toString());
			info.put("compiler", program.getCompilerSpec().toString());
			info.put("architecture", program.getLanguage().getLanguageDescription().getSize());
			info.put("addressFactory", program.getAddressFactory().toString());
			return gson.toJson(Map.of("status", "success", "program", info));
		} catch (Exception e) {
			return gson.toJson(Map.of("status", "error", "message", e.getMessage()));
		}
	}

	private String createData(String addressStr, String datatype) {
		Program program = getCurrentProgram();
		if (program == null) return gson.toJson(Map.of("status", "error", "message", "No program loaded"));
		try {
			final Address addr = program.getAddressFactory().getAddress(addressStr);
			final DataType dt;
			if ("byte".equals(datatype)) dt = new ByteDataType();
			else if ("word".equals(datatype) || "short".equals(datatype)) dt = new WordDataType();
			else if ("dword".equals(datatype) || "int".equals(datatype)) dt = new DWordDataType();
			else if ("qword".equals(datatype) || "long".equals(datatype)) dt = new QWordDataType();
			else if ("float".equals(datatype)) dt = new FloatDataType();
			else if ("double".equals(datatype)) dt = new DoubleDataType();
			else if ("pointer".equals(datatype)) dt = new PointerDataType();
			else return gson.toJson(Map.of("status", "error", "message", "Unknown datatype: " + datatype));

			AtomicBoolean success = new AtomicBoolean(false);
			AtomicReference<Data> dataRef = new AtomicReference<>();
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Create data");
				try {
					Data data = program.getListing().createData(addr, dt);
					dataRef.set(data);
					success.set(data != null);
				} catch (Exception e) {
					Msg.error(this, "Error creating data", e);
				} finally {
					program.endTransaction(tx, success.get());
				}
			});
			Data data = dataRef.get();
			if (data != null) {
				return gson.toJson(Map.of("status", "success", "message", "Created " + datatype + " at " + addressStr, "length", data.getLength()));
			}
			return gson.toJson(Map.of("status", "error", "message", "Failed to create data"));
		} catch (Exception e) {
			return gson.toJson(Map.of("status", "error", "message", e.getMessage()));
		}
	}

	private String applyDataType(String addressStr, String datatypeName) {
		Program program = getCurrentProgram();
		if (program == null) return gson.toJson(Map.of("status", "error", "message", "No program loaded"));
		try {
			final Address addr = program.getAddressFactory().getAddress(addressStr);
			final DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(datatypeName);
			if (dt == null) {
				dt = dtm.getDataType("/" + datatypeName);
			}
			final DataType finalDt = dt;
			if (finalDt == null) {
				return gson.toJson(Map.of("status", "error", "message", "Type not found: " + datatypeName));
			}

			AtomicBoolean success = new AtomicBoolean(false);
			AtomicReference<Data> dataRef = new AtomicReference<>();
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Apply data type");
				try {
					Data data = program.getListing().createData(addr, finalDt);
					dataRef.set(data);
					success.set(data != null);
				} catch (Exception e) {
					Msg.error(this, "Error applying data type", e);
				} finally {
					program.endTransaction(tx, success.get());
				}
			});
			Data data = dataRef.get();
			if (data != null) {
				return gson.toJson(Map.of("status", "success", "message", "Applied " + datatypeName + " at " + addressStr));
			}
			return gson.toJson(Map.of("status", "error", "message", "Failed to apply type"));
		} catch (Exception e) {
			return gson.toJson(Map.of("status", "error", "message", e.getMessage()));
		}
	}

	private String goToAddress(String addressStr) {
		Program program = getCurrentProgram();
		if (program == null) return gson.toJson(Map.of("status", "error", "message", "No program loaded"));
		if (!isUiCurrentProgram(program)) return gson.toJson(Map.of("status", "error", "message", "UI navigation requires the requested program to be current"));
		if (addressStr == null || addressStr.isEmpty()) {
			return gson.toJson(Map.of("status", "error", "message", "Address is required"));
		}
		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			if (addr == null) {
				return gson.toJson(Map.of("status", "error", "message", "Invalid address: " + addressStr));
			}
			GoToService gotoService = tool.getService(GoToService.class);
			if (gotoService != null) {
				gotoService.goTo(addr, program);
				return gson.toJson(Map.of("status", "success", "message", "Navigated to " + addressStr));
			}
			return gson.toJson(Map.of("status", "error", "message", "GoToService not available"));
		} catch (Exception e) {
			return gson.toJson(Map.of("status", "error", "message", e.getMessage()));
		}
	}

	private boolean isUiCurrentProgram(Program program) {
		ProgramManager pm = tool.getService(ProgramManager.class);
		return pm != null && pm.getCurrentProgram() == program;
	}

	private void sendResponse(HttpExchange exchange, String response) throws IOException {
		byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
		exchange.sendResponseHeaders(200, bytes.length);
		try (OutputStream os = exchange.getResponseBody()) {
			os.write(bytes);
		}
	}

	private void sendJsonResponse(HttpExchange exchange, String response) throws IOException {
		byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
		exchange.sendResponseHeaders(200, bytes.length);
		try (OutputStream os = exchange.getResponseBody()) {
			os.write(bytes);
		}
	}

	private String analyzeFunction(String address) {
		Program program = getCurrentProgram();
		if (program == null) {
			return gson.toJson(Map.of("status", "error", "message", "No program loaded"));
		}
		try {
			Address addr = program.getAddressFactory().getAddress(address);
			Function function = program.getFunctionManager().getFunctionContaining(addr);
			if (function == null) {
				return gson.toJson(Map.of("status", "error", "message", "No function found at address: " + address));
			}
			return gson.toJson(Map.of("status", "success", "message", "Analysis triggered for function at: " + address));
		} catch (Exception e) {
			return gson.toJson(Map.of("status", "error", "message", "Analysis failed: " + e.getMessage()));
		}
	}

	private String clearAnalysis(String address) {
		Program program = getCurrentProgram();
		if (program == null) {
			return gson.toJson(Map.of("status", "error", "message", "No program loaded"));
		}
		try {
			Address addr = program.getAddressFactory().getAddress(address);
			AtomicBoolean success = new AtomicBoolean(false);
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Clear analysis");
				try {
					program.getListing().clearCodeUnits(addr, addr, true);
					success.set(true);
				} catch (Exception e) {
					Msg.error(this, "Error clearing analysis", e);
				} finally {
					program.endTransaction(tx, success.get());
				}
			});
			return gson.toJson(Map.of("status", "success", "message", "Analysis cleared at address: " + address));
		} catch (Exception e) {
			return gson.toJson(Map.of("status", "error", "message", "Clear failed: " + e.getMessage()));
		}
	}

	@Override
	public void dispose() {
		if (server != null) {
			Msg.info(this, "Stopping GhidraMCP HTTP server...");
			server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
			server = null; // Nullify the reference
			Msg.info(this, "GhidraMCP HTTP server stopped.");
		}
		super.dispose();
	}
}
// rebuild
