/* ###
 * IP: GHIDRA
 */
package codexghidrabridge;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.swing.Timer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnicodeDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

class CodexBridgeService {

	private static final Gson GSON =
		new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

	private static final List<String> CAPABILITIES = Collections.unmodifiableList(Arrays.asList(
		"/health",
		"/session",
		"/context",
		"/analyze/target",
		"/functions/search",
		"/function",
		"/decompile",
		"/references",
		"/data/get",
		"/strings/search",
		"/symbols/get",
		"/symbols/xrefs",
		"/memory/range",
		"/variables",
		"/datatypes/search",
		"/objc/selector-trace",
		"/navigate",
		"/program/save",
		"/edit/rename",
		"/edit/comment",
		"/edit/bookmark",
		"/edit/function-signature",
		"/edit/variable",
		"/edit/datatype",
		"/patch/bytes",
		"/patch/instruction",
		"/listing/clear",
		"/listing/disassemble",
		"/function/create",
		"/function/delete",
		"/function/fixup",
		"/data/create",
		"/data/delete"));

	private static final int MAX_BYTES_IN_LOG = 4096;
	private static final int MAX_RESULTS = 50;

	private final CodexBridgePlugin plugin;
	private final CodexBridgeProvider provider;
	private final File configDir;
	private final File sessionsDir;
	private final File requestsDir;
	private final File legacyControlFile;

	private HttpServer server;
	private ExecutorService executor;
	private Timer controlTimer;
	private boolean armed;
	private final String sessionId;
	private String bridgeUrl = "";
	private String token = "";
	private String startedAt = "";
	private long lastHeartbeatMillis = 0L;

	CodexBridgeService(CodexBridgePlugin plugin, CodexBridgeProvider provider) {
		this.plugin = plugin;
		this.provider = provider;
		this.configDir = new File(new File(System.getProperty("user.home"), ".config"), "ghidra-re");
		this.sessionsDir = new File(configDir, "bridge-sessions");
		this.requestsDir = new File(configDir, "bridge-requests");
		this.legacyControlFile = new File(configDir, "bridge-control.json");
		this.sessionId = UUID.randomUUID().toString();
	}

	void start() {
		if (controlTimer != null) {
			return;
		}
		controlTimer = new Timer(1000, event -> pollControlRequests());
		controlTimer.setRepeats(true);
		controlTimer.start();
	}

	void dispose() {
		if (controlTimer != null) {
			controlTimer.stop();
			controlTimer = null;
		}
		disarm("dispose");
	}

	synchronized void arm(String reason) throws IOException {
		ensureConfigDir();
		if (armed && server != null) {
			writeSessionFile();
			log("bridge already armed (" + reason + ")");
			return;
		}
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/", this::handleExchange);
		executor = Executors.newCachedThreadPool();
		server.setExecutor(executor);
		server.start();
		armed = true;
		token = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");
		bridgeUrl = "http://127.0.0.1:" + server.getAddress().getPort();
		startedAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
		lastHeartbeatMillis = System.currentTimeMillis();
		writeSessionFile();
		log("bridge armed (" + reason + ") at " + bridgeUrl);
	}

	synchronized void disarm(String reason) {
		if (server != null) {
			server.stop(0);
			server = null;
		}
		if (executor != null) {
			executor.shutdownNow();
			executor = null;
		}
		if (armed) {
			log("bridge disarmed (" + reason + ")");
		}
		armed = false;
		bridgeUrl = "";
		token = "";
		startedAt = "";
		lastHeartbeatMillis = 0L;
		File sessionFile = sessionFile();
		if (sessionFile.exists()) {
			sessionFile.delete();
		}
	}

	boolean isArmed() {
		return armed;
	}

	String getBridgeUrl() {
		return bridgeUrl;
	}

	void onProgramOpened(Program program) {
		updateSessionIfArmed();
	}

	void onProgramActivated(Program program) {
		updateSessionIfArmed();
		pollControlRequests();
	}

	void onProgramDeactivated(Program program) {
		updateSessionIfArmed();
	}

	void onProgramClosed(Program program) {
		updateSessionIfArmed();
	}

	void onContextChanged() {
		updateSessionIfArmed();
	}

	void onProgramMutated() {
		updateSessionIfArmed();
	}

	void log(String message) {
		provider.appendLog(DateTimeFormatter.ISO_INSTANT.format(Instant.now()) + " " + message);
		Msg.info(plugin, "CodexBridge " + message);
	}

	String describeProgram(Program program) {
		if (program == null) {
			return "";
		}
		DomainFile domainFile = program.getDomainFile();
		if (domainFile == null) {
			return program.getName();
		}
		return program.getName() + " [" + domainFile.getPathname() + "]";
	}

	RepositoryState repositoryStateFor(Program program) {
		RepositoryState state = new RepositoryState();
		if (program == null) {
			return state;
		}
		state.programName = program.getName();
		DomainFile domainFile = program.getDomainFile();
		if (domainFile == null) {
			return state;
		}
		state.hasProgram = true;
		state.domainPath = domainFile.getPathname();
		state.versioned = domainFile.isVersioned();
		state.readOnly = domainFile.isReadOnly();
		state.checkedOut = domainFile.isCheckedOut();
		state.exclusiveCheckout = domainFile.isCheckedOutExclusive();
		state.modifiedSinceCheckout = domainFile.modifiedSinceCheckout();
		state.writableProject = domainFile.isInWritableProject();
		state.changed = domainFile.isChanged();
		state.canSave = domainFile.canSave();
		ProjectLocator locator = domainFile.getProjectLocator();
		if (locator != null) {
			state.projectLocation = locator.getLocation();
			state.projectName = locator.getName();
			File marker = locator.getMarkerFile();
			state.projectMarkerPath = marker == null ? "" : marker.getAbsolutePath();
		}
		return state;
	}

	String describeRepository(RepositoryState state) {
		if (state == null || !state.hasProgram) {
			return "no active program";
		}
		List<String> bits = new ArrayList<>();
		if (state.versioned) {
			bits.add(state.checkedOut ? "versioned+checked-out" : "versioned+read-only");
		}
		else {
			bits.add(state.readOnly ? "read-only" : "local-writable");
		}
		if (state.modifiedSinceCheckout) {
			bits.add("modified");
		}
		if (state.exclusiveCheckout) {
			bits.add("exclusive");
		}
		return String.join(", ", bits);
	}

	private void ensureConfigDir() throws IOException {
		if (!configDir.exists() && !configDir.mkdirs()) {
			throw new IOException("failed to create " + configDir);
		}
		if (!sessionsDir.exists() && !sessionsDir.mkdirs()) {
			throw new IOException("failed to create " + sessionsDir);
		}
		if (!requestsDir.exists() && !requestsDir.mkdirs()) {
			throw new IOException("failed to create " + requestsDir);
		}
	}

	private void updateSessionIfArmed() {
		if (!armed) {
			return;
		}
		try {
			writeSessionFile();
		}
		catch (IOException e) {
			log("session update failed: " + e.getMessage());
		}
	}

	private void writeSessionFile() throws IOException {
		ensureConfigDir();
		RepositoryState repository = repositoryStateFor(plugin.getCurrentProgram());
		JsonObject session = new JsonObject();
		session.addProperty("version", 1);
		session.addProperty("session_id", sessionId);
		session.addProperty("bridge_url", bridgeUrl);
		session.addProperty("token", token);
		session.addProperty("pid", ProcessHandle.current().pid());
		session.addProperty("tool_name", plugin.getTool().getToolName());
		session.addProperty("project_name", repository.projectName);
		session.addProperty("project_path", repository.projectMarkerPath);
		session.addProperty("program_name", repository.programName);
		session.addProperty("program_path", repository.domainPath);
		session.addProperty("started_at", startedAt);
		session.addProperty("last_heartbeat", DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
		session.addProperty("armed", armed);
		JsonArray capabilities = new JsonArray();
		for (String capability : CAPABILITIES) {
			capabilities.add(capability);
		}
		session.add("capabilities", capabilities);
		session.add("repository", repositoryToJson(repository));
		writeJson(sessionFile(), session);
	}

	private File sessionFile() {
		return new File(sessionsDir, sessionId + ".json");
	}

	private void pollLegacyControlFile() throws Exception {
		if (!legacyControlFile.exists()) {
			return;
		}
		JsonObject request = readJsonObject(legacyControlFile);
		if (requestMatches(request)) {
			processRequest(request, "legacy-control");
			legacyControlFile.delete();
		}
	}

	private void processRequestFile(File requestFile) throws Exception {
		JsonObject request = readJsonObject(requestFile);
		if (!requestMatches(request)) {
			return;
		}
		processRequest(request, requestFile.getName());
		requestFile.delete();
	}

	private void processRequest(JsonObject request, String source) throws Exception {
		String command = optString(request, "command");
		if (command.isEmpty()) {
			return;
		}
		if ("arm".equalsIgnoreCase(command)) {
			arm("request:" + source);
			return;
		}
		if ("disarm".equalsIgnoreCase(command)) {
			disarm("request:" + source);
		}
	}

	private boolean requestMatches(JsonObject request) {
		String requestedSession = optString(request, "session_id");
		String requestedProject = optString(request, "project_name");
		String requestedProgram = optString(request, "program_name");
		if (!requestedSession.isEmpty() && !sessionId.equals(requestedSession)) {
			return false;
		}
		String activeProject = activeProjectName();
		if (!requestedProject.isEmpty() && !requestedProject.equals(activeProject)) {
			return false;
		}
		if (requestedProgram.isEmpty()) {
			return true;
		}
		Program program = plugin.getCurrentProgram();
		if (program == null) {
			return !requestedProject.isEmpty() && requestedProject.equals(activeProject);
		}
		String activeProgramName = program.getName();
		String activeProgramPath = programPath(program);
		return requestedProgram.equals(activeProgramName) ||
			requestedProgram.equals(activeProgramPath) ||
			activeProgramPath.endsWith("/" + requestedProgram);
	}

	private void pollControlRequests() {
		try {
			pollLegacyControlFile();
			File[] requestFiles =
				requestsDir.listFiles((dir, name) -> name != null && name.endsWith(".json"));
			if (requestFiles != null) {
				Arrays.sort(requestFiles, Comparator.comparing(File::getName));
				for (File requestFile : requestFiles) {
					processRequestFile(requestFile);
				}
			}
			if (armed && (System.currentTimeMillis() - lastHeartbeatMillis) >= 1000L) {
				lastHeartbeatMillis = System.currentTimeMillis();
				writeSessionFile();
			}
		}
		catch (Exception e) {
			log("request processing error: " + e.getMessage());
		}
	}

	private void handleExchange(HttpExchange exchange) throws IOException {
		String path = exchange.getRequestURI().getPath();
		JsonObject body = new JsonObject();
		try {
			if (!armed) {
				sendJson(exchange, 503, null, "bridge is not armed");
				return;
			}
			if (!isAuthorized(exchange.getRequestHeaders())) {
				sendJson(exchange, 401, null, "missing or invalid bearer token");
				return;
			}
			body = readBody(exchange);
			JsonElement result = dispatch(path, body);
			sendJson(exchange, 200, result, null);
		}
		catch (BridgeException e) {
			sendJson(exchange, e.statusCode, null, e.getMessage());
		}
		catch (Exception e) {
			log("request failed " + path + ": " + e.getMessage());
			sendJson(exchange, 500, null, e.toString());
		}
	}

	private JsonElement dispatch(String path, JsonObject body) throws Exception {
		switch (path) {
			case "/health":
				return handleHealth();
			case "/session":
				return handleSession();
			case "/context":
				return handleContext();
			case "/analyze/target":
				return handleAnalyzeTarget(body);
			case "/functions/search":
				return handleFunctionSearch(body);
			case "/function":
				return handleFunction(body);
			case "/decompile":
				return handleDecompile(body);
			case "/references":
				return handleReferences(body);
			case "/data/get":
				return handleDataGet(body);
			case "/strings/search":
				return handleStringsSearch(body);
			case "/symbols/get":
				return handleSymbolsGet(body);
			case "/symbols/xrefs":
				return handleSymbolXrefs(body);
			case "/memory/range":
				return handleMemoryRange(body);
			case "/variables":
				return handleVariables(body);
			case "/datatypes/search":
				return handleDatatypeSearch(body);
			case "/objc/selector-trace":
				return handleObjcSelectorTrace(body);
			case "/navigate":
				return handleNavigate(body);
			case "/program/save":
				return handleProgramSave(body);
			case "/edit/rename":
				return handleEditRename(body);
			case "/edit/comment":
				return handleEditComment(body);
			case "/edit/bookmark":
				return handleEditBookmark(body);
			case "/edit/function-signature":
				return handleEditFunctionSignature(body);
			case "/edit/variable":
				return handleEditVariable(body);
			case "/edit/datatype":
				return handleEditDatatype(body);
			case "/patch/bytes":
				return handlePatchBytes(body);
			case "/patch/instruction":
				return handlePatchInstruction(body);
			case "/listing/clear":
				return handleListingClear(body);
			case "/listing/disassemble":
				return handleListingDisassemble(body);
			case "/function/create":
				return handleFunctionCreate(body);
			case "/function/delete":
				return handleFunctionDelete(body);
			case "/function/fixup":
				return handleFunctionFixup(body);
			case "/data/create":
				return handleDataCreate(body);
			case "/data/delete":
				return handleDataDelete(body);
			default:
				throw new BridgeException(404, "unknown endpoint: " + path);
		}
	}

	private String activeProjectName() {
		if (plugin.getCurrentProgram() != null) {
			RepositoryState repository = repositoryStateFor(plugin.getCurrentProgram());
			if (repository.projectName != null && !repository.projectName.isEmpty()) {
				return repository.projectName;
			}
		}
		if (plugin.getTool().getProject() != null && plugin.getTool().getProject().getName() != null) {
			return plugin.getTool().getProject().getName();
		}
		return "";
	}

	private JsonElement handleHealth() {
		JsonObject result = new JsonObject();
		result.addProperty("armed", armed);
		result.addProperty("bridge_url", bridgeUrl);
		result.addProperty("state_version", plugin.getStateVersion());
		return result;
	}

	private JsonElement handleSession() {
		JsonObject result = new JsonObject();
		result.addProperty("armed", armed);
		result.addProperty("session_id", sessionId);
		result.addProperty("bridge_url", bridgeUrl);
		result.addProperty("tool_name", plugin.getTool().getToolName());
		result.addProperty("started_at", startedAt);
		result.add("repository", repositoryToJson(repositoryStateFor(plugin.getCurrentProgram())));
		result.add("current_context", handleContext());
		return result;
	}

	private JsonObject handleContext() {
		JsonObject result = new JsonObject();
		Program program = plugin.getCurrentProgram();
		result.addProperty("has_program", program != null);
		if (program != null) {
			result.addProperty("program_name", program.getName());
			result.addProperty("program_path", programPath(program));
			result.addProperty("executable_path", empty(program.getExecutablePath()));
		}
		Address currentAddress = plugin.getCurrentAddress();
		if (currentAddress != null) {
			result.add("location_ref", locationRef(program, currentAddress));
			result.addProperty("address", currentAddress.toString());
		}
		Function currentFunction = plugin.getCurrentFunction();
		if (currentFunction != null) {
			result.add("function_ref", functionRef(currentFunction));
			result.addProperty("function_name", currentFunction.getName());
		}
		ProgramLocation location = plugin.getProgramLocation();
		if (location != null) {
			result.addProperty("location_class", location.getClass().getName());
		}
		JsonArray selection = selectionToJson(plugin.getProgramSelection(), 32);
		JsonArray highlight = selectionToJson(plugin.getProgramHighlight(), 32);
		result.add("selection", selection);
		result.add("highlight", highlight);
		return result;
	}

	private JsonElement handleAnalyzeTarget(JsonObject body) throws Exception {
		Program program = requireProgram();
		boolean navigate = optBoolean(body, "navigate", true);
		boolean hasExplicitTarget = optObject(body, "function_ref") != null ||
			hasAny(body, "address", "entry", "start", "function", "function_name");
		String query = optString(body, "query", "name");
		Address explicitAddress = hasExplicitAddressSelector(body) ?
			resolveExactAddress(program, body, true) : null;
		Function function = hasExplicitTarget ? resolveFunction(program, body, true) : null;
		JsonObject search = new JsonObject();
		boolean includeSearch = false;
		if (function == null && explicitAddress == null) {
			if (query.isEmpty()) {
				function = resolveFunction(program, body, true);
			}
			if (function == null && query.isEmpty()) {
				throw new BridgeException(400, "missing query or address/function");
			}
			if (function == null) {
				int limit = Math.max(1, Math.min(optInt(body, "limit", 5), 25));
				boolean exact = optBoolean(body, "exact", false);
				boolean caseSensitive = optBoolean(body, "case_sensitive", false);
				String field = optString(body, "field");
				if (field.isEmpty()) {
					field = "both";
				}
				search = buildFunctionSearchResult(program, query, limit, exact, caseSensitive, field);
				includeSearch = true;
				JsonArray matches = search.getAsJsonArray("matches");
				if (matches.size() == 0) {
					throw new BridgeException(404, "no function matches for query: " + query);
				}
				String entry =
					matches.get(0).getAsJsonObject().get("entry").getAsString();
				function = program.getFunctionManager().getFunctionAt(parseAddress(program, entry));
				if (function == null) {
					throw new BridgeException(404, "resolved search hit no longer maps to a function");
				}
			}
		}
		Address address = function != null ? function.getEntryPoint() : explicitAddress;
		if (address == null) {
			throw new BridgeException(404, "unable to resolve analysis target");
		}
		if (navigate) {
			if (!plugin.navigateTo(address)) {
				throw new BridgeException(500, "failed to navigate to " + address);
			}
		}
		JsonObject targetBody = new JsonObject();
		targetBody.addProperty("address", address.toString());
		if (function != null) {
			targetBody.add("function_ref", functionRef(function));
		}
		JsonObject result = new JsonObject();
		if (includeSearch) {
			result.add("search", search);
		}
		result.add("context", handleContext());
		result.add("function", function == null ? JsonNull.INSTANCE : functionToJson(function, true));
		result.add("references", handleReferences(targetBody));
		result.add("decompile", handleDecompile(targetBody));
		return result;
	}

	private JsonElement handleFunction(JsonObject body) throws Exception {
		Program program = requireProgram();
		Function function = resolveFunction(program, body);
		return functionToJson(function, true);
	}

	private JsonElement handleFunctionSearch(JsonObject body) throws Exception {
		Program program = requireProgram();
		String query = optString(body, "query", "name", "function", "function_name");
		if (query.isEmpty()) {
			throw new BridgeException(400, "missing query");
		}
		int limit = Math.max(1, Math.min(optInt(body, "limit", MAX_RESULTS), 250));
		boolean exact = optBoolean(body, "exact", false);
		boolean caseSensitive = optBoolean(body, "case_sensitive", false);
		String field = optString(body, "field");
		if (field.isEmpty()) {
			field = "both";
		}
		if (!"name".equalsIgnoreCase(field) && !"signature".equalsIgnoreCase(field) &&
			!"both".equalsIgnoreCase(field)) {
			throw new BridgeException(400, "unsupported field: " + field);
		}
		return buildFunctionSearchResult(program, query, limit, exact, caseSensitive, field);
	}

	private JsonObject buildFunctionSearchResult(Program program, String query, int limit,
			boolean exact, boolean caseSensitive, String field) {
		JsonObject result = new JsonObject();
		result.addProperty("query", query);
		result.addProperty("field", field);
		result.addProperty("exact", exact);
		result.addProperty("case_sensitive", caseSensitive);

		String normalizedQuery = normalizeForSearch(query, caseSensitive);
		List<FunctionSearchHit> hits = new ArrayList<>();
		Set<String> seenEntries = new LinkedHashSet<>();
		for (ghidra.program.model.listing.FunctionIterator iterator =
			program.getFunctionManager().getFunctions(true); iterator.hasNext();) {
			Function function = iterator.next();
			FunctionSearchHit hit = matchFunctionSearch(function, query, normalizedQuery, exact,
				caseSensitive, field);
			if (hit == null) {
				continue;
			}
			if (!seenEntries.add(function.getEntryPoint().toString())) {
				continue;
			}
			hits.add(hit);
		}

		hits.sort(Comparator
			.comparingInt((FunctionSearchHit hit) -> hit.rank)
			.thenComparing(hit -> hit.function.getName(), String.CASE_INSENSITIVE_ORDER)
			.thenComparing(hit -> hit.function.getEntryPoint().toString()));
		result.addProperty("total_matches", hits.size());
		JsonArray matches = new JsonArray();
		for (int i = 0; i < hits.size() && i < limit; i++) {
			FunctionSearchHit hit = hits.get(i);
			JsonObject match = functionToJson(hit.function, false);
			match.addProperty("match_kind", hit.matchKind);
			match.addProperty("match_field", hit.matchField);
			match.addProperty("match_value", hit.matchValue);
			matches.add(match);
		}
		result.add("matches", matches);
		return result;
	}

	private JsonElement handleObjcSelectorTrace(JsonObject body) throws Exception {
		Program program = requireProgram();
		String selector = optString(body, "selector", "query", "name");
		if (selector.isEmpty()) {
			throw new BridgeException(400, "missing selector");
		}
		int limit = Math.max(1, Math.min(optInt(body, "limit", 25), 100));
		boolean exact = optBoolean(body, "exact", false);
		boolean caseSensitive = optBoolean(body, "case_sensitive", false);
		String normalizedSelector = normalizeForSearch(selector, caseSensitive);

		JsonObject result = new JsonObject();
		result.addProperty("selector", selector);
		result.addProperty("exact", exact);
		result.addProperty("case_sensitive", caseSensitive);
		result.add("implementations",
			buildFunctionSearchResult(program, selector, limit, exact, caseSensitive, "name")
				.getAsJsonArray("matches"));

		JsonArray selectorStrings = new JsonArray();
		JsonArray senderCallsites = new JsonArray();
		Map<String, Function> senderFunctions = new LinkedHashMap<>();
		FlatProgramAPI flat = new FlatProgramAPI(program, TaskMonitor.DUMMY);
		DataIterator iterator = program.getListing().getDefinedData(true);
		while (iterator.hasNext()) {
			Data data = iterator.next();
			String candidate = candidateDataString(data);
			if (candidate.isEmpty()) {
				continue;
			}
			String normalizedCandidate = normalizeForSearch(candidate, caseSensitive);
			boolean matched = exact ? normalizedCandidate.equals(normalizedSelector) :
				normalizedCandidate.contains(normalizedSelector);
			if (!matched) {
				continue;
			}
			JsonObject stringHit = new JsonObject();
			stringHit.add("location_ref", locationRef(program, data.getAddress()));
			stringHit.addProperty("address", data.getAddress().toString());
			stringHit.addProperty("value", candidate);
			JsonArray sampleReferences = new JsonArray();
			Reference[] refs = flat.getReferencesTo(data.getAddress());
			stringHit.addProperty("reference_count", refs.length);
			for (int i = 0; i < refs.length && i < limit; i++) {
				Reference ref = refs[i];
				JsonObject refJson = referenceToJson(ref);
				Function sender = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
				if (sender != null) {
					refJson.add("function_ref", functionRef(sender));
					refJson.addProperty("function_name", sender.getName());
					senderFunctions.putIfAbsent(sender.getEntryPoint().toString(), sender);
				}
				sampleReferences.add(refJson);
				if (senderCallsites.size() < limit) {
					senderCallsites.add(refJson.deepCopy());
				}
			}
			stringHit.add("sample_references", sampleReferences);
			selectorStrings.add(stringHit);
			if (selectorStrings.size() >= limit) {
				break;
			}
		}

		List<Function> sortedSenderFunctions = new ArrayList<>(senderFunctions.values());
		sortedSenderFunctions.sort(
			Comparator.comparing((Function function) -> function.getName(),
				String.CASE_INSENSITIVE_ORDER)
				.thenComparing(function -> function.getEntryPoint().toString()));
		JsonArray senders = new JsonArray();
		for (int i = 0; i < sortedSenderFunctions.size() && i < limit; i++) {
			senders.add(functionToJson(sortedSenderFunctions.get(i), false));
		}

		result.add("selector_string_matches", selectorStrings);
		result.add("sender_functions", senders);
		result.add("sender_callsites", senderCallsites);
		return result;
	}

	private JsonElement handleDecompile(JsonObject body) throws Exception {
		Program program = requireProgram();
		Function function = resolveFunction(program, body, true);
		if (function == null) {
			Address address = resolveExactAddress(program, body, true);
			if (address == null) {
				throw new BridgeException(404, "unable to resolve function from explicit target");
			}
			return buildAddressDecompileFallback(program, address);
		}
		DecompInterface decompiler = new DecompInterface();
		try {
			if (!decompiler.openProgram(program)) {
				throw new BridgeException(500, "failed to open program in decompiler");
			}
			DecompileResults results = decompiler.decompileFunction(function, 60, TaskMonitor.DUMMY);
			if (!results.decompileCompleted() || results.getDecompiledFunction() == null) {
				throw new BridgeException(500, "decompilation failed: " + results.getErrorMessage());
			}
			JsonObject payload = new JsonObject();
			String cText = results.getDecompiledFunction().getC();
			payload.add("function_ref", functionRef(function));
			payload.addProperty("signature", function.getPrototypeString(false, false));
			payload.addProperty("c", cText);
			if (isLowSignalDecompile(function, cText)) {
				payload.addProperty("signal", "low");
				payload.add("enrichment", buildLowSignalFunctionContext(program, function, 12));
			}
			return payload;
		}
		finally {
			decompiler.dispose();
		}
	}

	private JsonObject buildAddressDecompileFallback(Program program, Address address)
			throws Exception {
		JsonObject payload = new JsonObject();
		payload.addProperty("requested_address", address.toString());
		payload.addProperty("available", false);
		payload.addProperty("reason", "no containing function");
		payload.add("location_ref", locationRef(program, address));
		Function containing = program.getFunctionManager().getFunctionContaining(address);
		payload.add("containing_function",
			containing == null ? JsonNull.INSTANCE : functionToJson(containing, false));
		Instruction instruction = program.getListing().getInstructionContaining(address);
		if (instruction != null) {
			payload.add("instruction",
				instructionSnapshot(program, instruction, instruction.getAddress(),
					instructionBytes(new FlatProgramAPI(program, TaskMonitor.DUMMY), instruction)));
		}
		Data data = program.getListing().getDefinedDataContaining(address);
		if (data != null) {
			payload.add("data", dataToJson(program, data, 10));
		}
		Address start = address;
		Address end = address;
		try {
			end = address.add(31);
		}
		catch (Exception ignored) {
			end = address;
		}
		payload.add("range", rangeSnapshot(program, start, end));
		return payload;
	}

	private JsonElement handleReferences(JsonObject body) throws Exception {
		Program program = requireProgram();
		JsonObject result = new JsonObject();
		boolean rawAddressRequested = hasExplicitAddressSelector(body);
		Function function = null;
		Address address;
		if (rawAddressRequested) {
			address = resolveExactAddress(program, body, false);
			Function containing = program.getFunctionManager().getFunctionContaining(address);
			if (containing != null) {
				result.add("containing_function", functionToJson(containing, false));
			}
		}
		else {
			try {
				function = resolveFunction(program, body);
			}
			catch (BridgeException ignored) {
				// Fall through and try raw address resolution.
			}
			address = function == null ? resolveExactAddress(program, body, true) : function.getEntryPoint();
		}
		if (function != null) {
			result.add("function_ref", functionRef(function));
			JsonArray callers = new JsonArray();
			List<Function> sortedCallers = new ArrayList<>(function.getCallingFunctions(TaskMonitor.DUMMY));
			sortedCallers.sort(Comparator.comparing(f -> f.getEntryPoint().toString()));
			for (Function caller : sortedCallers) {
				callers.add(functionToJson(caller, false));
			}
			result.add("callers", callers);

			JsonArray callees = new JsonArray();
			List<Function> sortedCallees = new ArrayList<>(function.getCalledFunctions(TaskMonitor.DUMMY));
			sortedCallees.sort(Comparator.comparing(f -> f.getEntryPoint().toString()));
			for (Function callee : sortedCallees) {
				callees.add(functionToJson(callee, false));
			}
			result.add("callees", callees);
		}
		result.addProperty("address", address.toString());
		result.add("references_to", referencesToJson(new FlatProgramAPI(program), address, MAX_RESULTS));
		result.add("references_from", referencesFromJson(new FlatProgramAPI(program), address, MAX_RESULTS));
		Data data = program.getListing().getDefinedDataContaining(address);
		if (data != null) {
			result.add("data", dataToJson(program, data, 10));
		}
		return result;
	}

	private JsonElement handleDataGet(JsonObject body) throws Exception {
		Program program = requireProgram();
		Address address = resolveExactAddress(program, body, false);
		Data data = program.getListing().getDefinedDataContaining(address);
		if (data == null) {
			throw new BridgeException(404, "no defined data at or containing " + address);
		}
		JsonObject result = dataToJson(program, data, MAX_RESULTS);
		result.addProperty("requested_address", address.toString());
		return result;
	}

	private JsonElement handleStringsSearch(JsonObject body) throws Exception {
		Program program = requireProgram();
		String query = optString(body, "query", "value", "string");
		if (query.isEmpty()) {
			throw new BridgeException(400, "missing query");
		}
		int limit = Math.max(1, Math.min(optInt(body, "limit", MAX_RESULTS), 250));
		boolean exact = optBoolean(body, "exact", false);
		boolean caseSensitive = optBoolean(body, "case_sensitive", false);
		String normalizedQuery = normalizeForSearch(query, caseSensitive);
		JsonObject result = new JsonObject();
		result.addProperty("query", query);
		result.addProperty("exact", exact);
		result.addProperty("case_sensitive", caseSensitive);
		JsonArray matches = new JsonArray();
		DataIterator iterator = program.getListing().getDefinedData(true);
		while (iterator.hasNext()) {
			Data data = iterator.next();
			String candidate = candidateDataString(data);
			if (candidate.isEmpty()) {
				continue;
			}
			String normalizedCandidate = normalizeForSearch(candidate, caseSensitive);
			boolean matched = exact ? normalizedCandidate.equals(normalizedQuery) :
				normalizedCandidate.contains(normalizedQuery);
			if (!matched) {
				continue;
			}
			matches.add(dataToJson(program, data, 10));
			if (matches.size() >= limit) {
				break;
			}
		}
		result.addProperty("match_count", matches.size());
		result.add("matches", matches);
		return result;
	}

	private JsonElement handleSymbolsGet(JsonObject body) throws Exception {
		Program program = requireProgram();
		List<Symbol> symbols = resolveSymbols(program, body, false);
		JsonObject result = new JsonObject();
		JsonArray matches = new JsonArray();
		for (Symbol symbol : symbols) {
			matches.add(symbolToJson(program, symbol, 10));
		}
		result.addProperty("match_count", matches.size());
		result.add("matches", matches);
		if (!symbols.isEmpty()) {
			result.add("symbol", symbolToJson(program, symbols.get(0), 10));
		}
		return result;
	}

	private JsonElement handleSymbolXrefs(JsonObject body) throws Exception {
		Program program = requireProgram();
		List<Symbol> symbols = resolveSymbols(program, body, false);
		Symbol symbol = symbols.get(0);
		JsonObject result = new JsonObject();
		result.add("symbol", symbolToJson(program, symbol, 10));
		result.add("references_to",
			referencesToJson(new FlatProgramAPI(program), symbol.getAddress(), MAX_RESULTS));
		result.add("references_from",
			referencesFromJson(new FlatProgramAPI(program), symbol.getAddress(), MAX_RESULTS));
		return result;
	}

	private JsonElement handleMemoryRange(JsonObject body) throws Exception {
		Program program = requireProgram();
		Address start = resolveExactAddress(program, body, false);
		Address end = resolveEndAddress(program, body, start);
		long lengthLong = end.subtract(start) + 1L;
		int length = (int) Math.max(1L, Math.min(lengthLong, MAX_BYTES_IN_LOG));
		byte[] bytes;
		try {
			bytes = new FlatProgramAPI(program, TaskMonitor.DUMMY).getBytes(start, length);
		}
		catch (Exception e) {
			throw new BridgeException(500, "failed to read memory range: " + e.getMessage());
		}
		JsonObject result = rangeSnapshot(program, start, end);
		result.addProperty("ascii", bytesToAscii(bytes));
		result.addProperty("effective_length", length);
		MemoryBlock block = program.getMemory().getBlock(start);
		if (block != null) {
			result.addProperty("block", block.getName());
			result.addProperty("source_name", block.getSourceName());
		}
		return result;
	}

	private JsonElement handleVariables(JsonObject body) throws Exception {
		Program program = requireProgram();
		Function function = resolveFunction(program, body);
		JsonObject result = new JsonObject();
		result.add("function_ref", functionRef(function));
		JsonArray params = new JsonArray();
		for (Parameter parameter : function.getParameters()) {
			params.add(variableToJson(parameter));
		}
		result.add("parameters", params);
		JsonArray locals = new JsonArray();
		for (Variable local : function.getLocalVariables()) {
			locals.add(variableToJson(local));
		}
		result.add("locals", locals);
		result.add("return", variableToJson(function.getReturn()));
		return result;
	}

	private JsonElement handleDatatypeSearch(JsonObject body) throws Exception {
		Program program = requireProgram();
		String query = optString(body, "query", "name", "type");
		if (query.isEmpty()) {
			throw new BridgeException(400, "missing query");
		}
		int limit = optInt(body, "limit", MAX_RESULTS);
		DataTypeManager manager = program.getDataTypeManager();
		List<DataType> matches = new ArrayList<>();
		manager.findDataTypes(query, matches);
		matches.sort(Comparator.comparing(DataType::getPathName));
		JsonArray result = new JsonArray();
		Set<String> seen = new LinkedHashSet<>();
		for (DataType dataType : matches) {
			if (dataType == null) {
				continue;
			}
			if (!seen.add(dataType.getPathName())) {
				continue;
			}
			result.add(dataTypeToJson(dataType));
			if (result.size() >= limit) {
				break;
			}
		}
		return result;
	}

	private JsonElement handleNavigate(JsonObject body) throws Exception {
		Program program = requireProgram();
		Address address = resolveAddress(program, body, false);
		if (!plugin.navigateTo(address)) {
			throw new BridgeException(500, "failed to navigate to " + address);
		}
		JsonObject result = new JsonObject();
		result.add("location_ref", locationRef(program, address));
		result.add("context", handleContext());
		return result;
	}

	private JsonElement handleProgramSave(JsonObject body) throws Exception {
		Program program = requireProgram();
		requireWriteFlags(body, false);
		ensureWritable(program);
		RepositoryState before = repositoryStateFor(program);
		String description = optString(body, "description", "comment", "message");
		if (description.isEmpty()) {
			description = "CodexBridge: program-save";
		}
		try {
			if (before.canSave && before.changed) {
				program.save(description, TaskMonitor.DUMMY);
			}
		}
		catch (Exception e) {
			throw new BridgeException(500, "program save failed: " + e.getMessage());
		}
		plugin.incrementState("program-save");
		updateSessionIfArmed();
		RepositoryState after = repositoryStateFor(program);
		JsonObject result = new JsonObject();
		result.addProperty("saved", !after.changed);
		result.addProperty("changed_before", before.changed);
		result.addProperty("changed_after", after.changed);
		result.addProperty("description", description);
		result.add("repository", repositoryToJson(after));
		return result;
	}

	private JsonElement handleEditRename(JsonObject body) throws Exception {
		return executeMutation("edit-rename", body, false, (program, flat) -> {
			String newName = optString(body, "rename", "new_name", "name");
			if (newName.isEmpty()) {
				throw new BridgeException(400, "missing rename/new_name");
			}
			MutationResult mutation = new MutationResult();
			Variable variable = resolveVariable(program, body, true);
			if (variable != null) {
				mutation.before = variableToJson(variable);
				variable.setName(newName, SourceType.USER_DEFINED);
				mutation.result = variableToJson(variable);
				mutation.targets.add(variableRef(variable));
				return mutation;
			}
			Function function = resolveFunction(program, body, true);
			if (function != null) {
				mutation.before = functionToJson(function, false);
				function.setName(newName, SourceType.USER_DEFINED);
				mutation.result = functionToJson(function, false);
				mutation.targets.add(functionRef(function));
				return mutation;
			}
			Address address = resolveAddress(program, body, false);
			Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
			if (symbol == null) {
				throw new BridgeException(404, "no symbol at " + address);
			}
			mutation.before = symbolToJson(program, symbol, 10);
			symbol.setName(newName, SourceType.USER_DEFINED);
			mutation.result = symbolToJson(program, symbol, 10);
			mutation.targets.add(locationRef(program, address));
			return mutation;
		});
	}

	private JsonElement handleEditComment(JsonObject body) throws Exception {
		return executeMutation("edit-comment", body, false, (program, flat) -> {
			String comment = optString(body, "comment", "text");
			if (comment.isEmpty()) {
				throw new BridgeException(400, "missing comment");
			}
			Address address = resolveAddress(program, body, false);
			String type = optString(body, "comment_type", "type");
			if (type.isEmpty()) {
				type = "plate";
			}
			MutationResult mutation = new MutationResult();
			mutation.before = commentSnapshot(program, address);
			switch (type.toLowerCase(Locale.ROOT)) {
				case "plate":
					flat.setPlateComment(address, comment);
					break;
				case "pre":
					flat.setPreComment(address, comment);
					break;
				case "post":
					flat.setPostComment(address, comment);
					break;
				case "eol":
					flat.setEOLComment(address, comment);
					break;
				case "repeatable":
					flat.setRepeatableComment(address, comment);
					break;
				case "function":
					Function function = resolveFunction(program, body);
					function.setComment(comment);
					function.setRepeatableComment(comment);
					mutation.targets.add(functionRef(function));
					break;
				default:
					throw new BridgeException(400, "unsupported comment_type: " + type);
			}
			if (mutation.targets.size() == 0) {
				mutation.targets.add(locationRef(program, address));
			}
			mutation.result = commentSnapshot(program, address);
			return mutation;
		});
	}

	private JsonElement handleEditBookmark(JsonObject body) throws Exception {
		return executeMutation("edit-bookmark", body, false, (program, flat) -> {
			Address address = resolveAddress(program, body, false);
			String category = optString(body, "bookmark_category", "category");
			String comment = optString(body, "message", "comment", "title");
			if (category.isEmpty()) {
				category = "codex";
			}
			MutationResult mutation = new MutationResult();
			mutation.before = bookmarksToJson(flat.getBookmarks(address));
			flat.createBookmark(address, category, comment);
			mutation.result = bookmarksToJson(flat.getBookmarks(address));
			mutation.targets.add(locationRef(program, address));
			return mutation;
		});
	}

	private JsonElement handleEditFunctionSignature(JsonObject body) throws Exception {
		return executeMutation("edit-function-signature", body, false, (program, flat) -> {
			Function function = resolveFunction(program, body);
			MutationResult mutation = new MutationResult();
			mutation.before = functionToJson(function, true);

			String rename = optString(body, "rename", "new_name");
			if (!rename.isEmpty()) {
				function.setName(rename, SourceType.USER_DEFINED);
			}

			String returnTypeName = optString(body, "return_type");
			if (!returnTypeName.isEmpty()) {
				DataType returnType = resolveDataType(program, returnTypeName, true);
				function.setReturnType(returnType, SourceType.USER_DEFINED);
			}

			String callingConvention = optString(body, "calling_convention");
			if (!callingConvention.isEmpty()) {
				function.setCallingConvention(callingConvention);
			}

			if (hasAny(body, "inline", "is_inline")) {
				boolean inline = optBoolean(body, "inline",
					optBoolean(body, "is_inline", function.isInline()));
				function.setInline(inline);
			}

			if (hasAny(body, "no_return")) {
				function.setNoReturn(optBoolean(body, "no_return", function.hasNoReturn()));
			}

			if (hasAny(body, "has_var_args", "var_args")) {
				boolean hasVarArgs = optBoolean(body, "has_var_args",
					optBoolean(body, "var_args", function.hasVarArgs()));
				function.setVarArgs(hasVarArgs);
			}

			JsonArray params = optArray(body, "params", "parameters");
			if (params != null) {
				List<Variable> replacement = new ArrayList<>();
				for (JsonElement element : params) {
					JsonObject paramObject = element.getAsJsonObject();
					String paramName = optString(paramObject, "name");
					if (paramName.isEmpty()) {
						paramName = "param_" + replacement.size();
					}
					String typeName = optString(paramObject, "type", "datatype");
					DataType dataType = resolveDataType(program, typeName, true);
					ParameterImpl parameter =
						new ParameterImpl(paramName, dataType, program, SourceType.USER_DEFINED);
					String comment = optString(paramObject, "comment");
					if (!comment.isEmpty()) {
						parameter.setComment(comment);
					}
					replacement.add(parameter);
				}
				function.replaceParameters(replacement, FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
					true, SourceType.USER_DEFINED);
			}

			mutation.result = functionToJson(function, true);
			mutation.targets.add(functionRef(function));
			return mutation;
		});
	}

	private JsonElement handleEditVariable(JsonObject body) throws Exception {
		return executeMutation("edit-variable", body, false, (program, flat) -> {
			Variable variable = resolveVariable(program, body, false);
			MutationResult mutation = new MutationResult();
			mutation.before = variableToJson(variable);
			String rename = optString(body, "rename", "new_name");
			if (!rename.isEmpty()) {
				variable.setName(rename, SourceType.USER_DEFINED);
			}
			String comment = optString(body, "comment");
			if (!comment.isEmpty()) {
				variable.setComment(comment);
			}
			String typeName = optString(body, "type", "datatype");
			if (!typeName.isEmpty()) {
				DataType dataType = resolveDataType(program, typeName, true);
				variable.setDataType(dataType, SourceType.USER_DEFINED);
			}
			mutation.result = variableToJson(variable);
			mutation.targets.add(variableRef(variable));
			return mutation;
		});
	}

	private JsonElement handleEditDatatype(JsonObject body) throws Exception {
		return executeMutation("edit-datatype", body, false, (program, flat) -> {
			MutationResult mutation = new MutationResult();
			String action = optString(body, "action");
			if (action.isEmpty()) {
				action = "rename";
			}
			DataTypeManager manager = program.getDataTypeManager();
			switch (action) {
				case "create_struct":
					mutation.result = dataTypeToJson(createStruct(manager, body, program));
					break;
				case "create_enum":
					mutation.result = dataTypeToJson(createEnum(manager, body, program));
					break;
				case "create_typedef":
					mutation.result = dataTypeToJson(createTypedef(manager, body, program));
					break;
				case "rename":
				case "update_struct":
				case "update_enum":
					DataType dataType = resolveDataType(program, body, false);
					mutation.before = dataTypeToJson(dataType);
					updateDatatype(dataType, body, program);
					mutation.result = dataTypeToJson(dataType);
					break;
				default:
					throw new BridgeException(400, "unsupported datatype action: " + action);
			}
			mutation.targets.add(mutation.result.deepCopy());
			return mutation;
		});
	}

	private JsonElement handlePatchBytes(JsonObject body) throws Exception {
		return executeMutation("patch-bytes", body, true, (program, flat) -> {
			Address address = resolveAddress(program, body, false);
			byte[] newBytes = parseHexBytes(optString(body, "bytes", "hex"));
			if (newBytes.length == 0) {
				throw new BridgeException(400, "missing bytes/hex");
			}
			byte[] beforeBytes = flat.getBytes(address, newBytes.length);
			MutationResult mutation = new MutationResult();
			mutation.before = bytePatchSnapshot(program, address, beforeBytes);
			flat.setBytes(address, newBytes);
			mutation.result = bytePatchSnapshot(program, address, flat.getBytes(address, newBytes.length));
			mutation.targets.add(locationRef(program, address));
			mutation.inverse.addProperty("kind", "patch-bytes");
			mutation.inverse.addProperty("address", address.toString());
			mutation.inverse.addProperty("bytes", toHex(beforeBytes));
			return mutation;
		});
	}

	private JsonElement handlePatchInstruction(JsonObject body) throws Exception {
		return executeMutation("patch-instruction", body, true, (program, flat) -> {
			Address address = resolveAddress(program, body, false);
			String assembly = optString(body, "assembly", "instruction");
			if (assembly.isEmpty()) {
				throw new BridgeException(400, "missing assembly");
			}
			Instruction before = flat.getInstructionAt(address);
			byte[] beforeBytes = instructionBytes(flat, before);
			Assembler assembler = Assemblers.getAssembler(program);
			assembler.assemble(address, assembly);
			Instruction after = flat.getInstructionAt(address);
			MutationResult mutation = new MutationResult();
			mutation.before = instructionSnapshot(program, before, address, beforeBytes);
			mutation.result = instructionSnapshot(program, after, address, instructionBytes(flat, after));
			mutation.targets.add(locationRef(program, address));
			mutation.inverse.addProperty("kind", "patch-bytes");
			mutation.inverse.addProperty("address", address.toString());
			mutation.inverse.addProperty("bytes", toHex(beforeBytes));
			return mutation;
		});
	}

	private JsonElement handleListingClear(JsonObject body) throws Exception {
		return executeMutation("listing-clear", body, true, (program, flat) -> {
			Address start = resolveAddress(program, body, false);
			Address end = resolveEndAddress(program, body, start);
			String mode = optString(body, "mode");
			if (mode.isEmpty()) {
				mode = "all";
			}
			MutationResult mutation = new MutationResult();
			mutation.before = rangeSnapshot(program, start, end);
			Listing listing = program.getListing();
			if ("all".equalsIgnoreCase(mode)) {
				listing.clearCodeUnits(start, end, false);
			}
			else if ("code".equalsIgnoreCase(mode)) {
				InstructionIterator iterator =
					listing.getInstructions(new AddressSet(start, end), true);
				List<Address> addresses = new ArrayList<>();
				while (iterator.hasNext()) {
					addresses.add(iterator.next().getAddress());
				}
				for (Address address : addresses) {
					flat.removeInstructionAt(address);
				}
			}
			else if ("data".equalsIgnoreCase(mode)) {
				DataIterator iterator = listing.getDefinedData(new AddressSet(start, end), true);
				List<Address> addresses = new ArrayList<>();
				while (iterator.hasNext()) {
					addresses.add(iterator.next().getAddress());
				}
				for (Address address : addresses) {
					flat.removeDataAt(address);
				}
			}
			else {
				throw new BridgeException(400, "unsupported clear mode: " + mode);
			}
			mutation.result = rangeSnapshot(program, start, end);
			mutation.targets.add(locationRef(program, start));
			mutation.inverse.addProperty("kind", "range-snapshot");
			mutation.inverse.add("snapshot", mutation.before.deepCopy());
			return mutation;
		});
	}

	private JsonElement handleListingDisassemble(JsonObject body) throws Exception {
		return executeMutation("listing-disassemble", body, true, (program, flat) -> {
			Address start = resolveAddress(program, body, false);
			Address end = resolveEndAddress(program, body, start);
			AddressSet set = new AddressSet(start, end);
			MutationResult mutation = new MutationResult();
			mutation.before = rangeSnapshot(program, start, end);
			DisassembleCommand command = new DisassembleCommand(start, set, true);
			if (!command.applyTo(program, TaskMonitor.DUMMY)) {
				throw new BridgeException(500, "disassemble failed: " + command.getStatusMsg());
			}
			mutation.result = rangeSnapshot(program, start, end);
			mutation.targets.add(locationRef(program, start));
			mutation.inverse.addProperty("kind", "range-snapshot");
			mutation.inverse.add("snapshot", mutation.before.deepCopy());
			return mutation;
		});
	}

	private JsonElement handleFunctionCreate(JsonObject body) throws Exception {
		return executeMutation("function-create", body, true, (program, flat) -> {
			Address entry = resolveAddress(program, body, false);
			String name = optString(body, "name");
			Address bodyEnd = hasAny(body, "end", "body_end", "length") ? resolveEndAddress(program, body, entry) :
				null;
			MutationResult mutation = new MutationResult();
			mutation.before = rangeSnapshot(program, entry, bodyEnd == null ? entry : bodyEnd);
			Function function;
			if (bodyEnd != null && !entry.equals(bodyEnd)) {
				function = program.getListing().createFunction(name, entry, new AddressSet(entry, bodyEnd),
					SourceType.USER_DEFINED);
			}
			else {
				CreateFunctionCmd command = new CreateFunctionCmd(entry);
				if (!command.applyTo(program, TaskMonitor.DUMMY)) {
					throw new BridgeException(500, "create function failed");
				}
				function = command.getFunction();
				if (function != null && !name.isEmpty()) {
					function.setName(name, SourceType.USER_DEFINED);
				}
			}
			if (function == null) {
				throw new BridgeException(500, "function creation did not return a function");
			}
			mutation.result = functionToJson(function, true);
			mutation.targets.add(functionRef(function));
			mutation.inverse.addProperty("kind", "function-delete");
			mutation.inverse.addProperty("entry", function.getEntryPoint().toString());
			return mutation;
		});
	}

	private JsonElement handleFunctionDelete(JsonObject body) throws Exception {
		return executeMutation("function-delete", body, true, (program, flat) -> {
			Function function = resolveFunction(program, body);
			MutationResult mutation = new MutationResult();
			mutation.before = functionToJson(function, true);
			mutation.targets.add(functionRef(function));
			mutation.inverse.addProperty("kind", "function-create");
			mutation.inverse.addProperty("entry", function.getEntryPoint().toString());
			mutation.inverse.addProperty("name", function.getName());
			mutation.inverse.add("body", addressSetToJson(function.getBody(), 32));
			flat.removeFunction(function);
			mutation.result = new JsonObject();
			mutation.result.addProperty("deleted", true);
			return mutation;
		});
	}

	private JsonElement handleFunctionFixup(JsonObject body) throws Exception {
		return executeMutation("function-fixup", body, true, (program, flat) -> {
			Function function = resolveFunction(program, body);
			MutationResult mutation = new MutationResult();
			mutation.before = functionToJson(function, true);
			boolean fixed = CreateFunctionCmd.fixupFunctionBody(program, function, TaskMonitor.DUMMY);
			if (!fixed) {
				throw new BridgeException(500, "function fixup failed");
			}
			mutation.result = functionToJson(function, true);
			mutation.targets.add(functionRef(function));
			mutation.inverse.addProperty("kind", "range-snapshot");
			mutation.inverse.add("snapshot", mutation.before.deepCopy());
			return mutation;
		});
	}

	private JsonElement handleDataCreate(JsonObject body) throws Exception {
		return executeMutation("data-create", body, true, (program, flat) -> {
			Address address = resolveAddress(program, body, false);
			DataType dataType = resolveDataType(program, body, true);
			int length = Math.max(dataType.getLength(), 1);
			Address end = address.add(length - 1L);
			MutationResult mutation = new MutationResult();
			mutation.before = rangeSnapshot(program, address, end);
			program.getListing().clearCodeUnits(address, end, false);
			Data data = flat.createData(address, dataType);
			mutation.result = dataToJson(program, data, 10);
			mutation.targets.add(locationRef(program, address));
			mutation.inverse.addProperty("kind", "data-delete");
			mutation.inverse.addProperty("address", address.toString());
			return mutation;
		});
	}

	private JsonElement handleDataDelete(JsonObject body) throws Exception {
		return executeMutation("data-delete", body, true, (program, flat) -> {
			Address start = resolveAddress(program, body, false);
			Address end = resolveEndAddress(program, body, start);
			Listing listing = program.getListing();
			MutationResult mutation = new MutationResult();
			mutation.before = rangeSnapshot(program, start, end);
			DataIterator iterator = listing.getDefinedData(new AddressSet(start, end), true);
			List<Address> addresses = new ArrayList<>();
			while (iterator.hasNext()) {
				addresses.add(iterator.next().getAddress());
			}
			for (Address address : addresses) {
				flat.removeDataAt(address);
			}
			mutation.result = rangeSnapshot(program, start, end);
			mutation.targets.add(locationRef(program, start));
			mutation.inverse.addProperty("kind", "range-snapshot");
			mutation.inverse.add("snapshot", mutation.before.deepCopy());
			return mutation;
		});
	}

	private JsonElement executeMutation(String opName, JsonObject body, boolean destructive,
			MutationAction action) throws Exception {
		Program program = requireProgram();
		requireWriteFlags(body, destructive);
		ensureWritable(program);

		FlatProgramAPI flat = new FlatProgramAPI(program, TaskMonitor.DUMMY);
		int tx = program.startTransaction("CodexBridge:" + opName);
		boolean commit = false;
		MutationResult mutation = null;
		try {
			mutation = action.apply(program, flat);
			commit = true;
		}
		finally {
			program.endTransaction(tx, commit);
		}
		plugin.incrementState(opName);
		updateSessionIfArmed();
		if (destructive && mutation != null) {
			writeOperationLog(opName, body, mutation);
		}
		return mutation == null ? JsonNull.INSTANCE : mutation.result;
	}

	private void writeOperationLog(String opName, JsonObject request, MutationResult mutation) {
		try {
			Program program = plugin.getCurrentProgram();
			RepositoryState repository = repositoryStateFor(program);
			String projectName = repository.projectName.isEmpty() ? "unknown-project" : repository.projectName;
			File logDir =
				new File(new File(new File(System.getProperty("user.home"), "ghidra-projects"), "logs"),
					projectName + "/bridge-ops");
			if (!logDir.exists()) {
				logDir.mkdirs();
			}
			File output =
				new File(logDir, DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(java.time.ZoneId.systemDefault()).format(Instant.now()) +
					"-" + slug(opName) + ".json");
			JsonObject payload = new JsonObject();
			payload.addProperty("operation_kind", opName);
			payload.add("request_body", request.deepCopy());
			payload.add("before_state", mutation.before == null ? JsonNull.INSTANCE : mutation.before.deepCopy());
			payload.add("after_state_summary",
				mutation.result == null ? JsonNull.INSTANCE : mutation.result.deepCopy());
			payload.add("target_refs", mutation.targets.deepCopy());
			payload.add("inverse", mutation.inverse.deepCopy());
			payload.addProperty("tool_name", plugin.getTool().getToolName());
			payload.addProperty("program_path", repository.domainPath);
			payload.addProperty("project_path", repository.projectMarkerPath);
			payload.addProperty("pid", ProcessHandle.current().pid());
			payload.addProperty("created_at", DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
			payload.add("repository", repositoryToJson(repository));
			writeJson(output, payload);
		}
		catch (Exception e) {
			log("operation log failure: " + e.getMessage());
		}
	}

	private Program requireProgram() throws BridgeException {
		Program program = plugin.getCurrentProgram();
		if (program == null) {
			throw new BridgeException(409, "no active program in the GUI session");
		}
		return program;
	}

	private void ensureWritable(Program program) throws BridgeException {
		RepositoryState state = repositoryStateFor(program);
		if (!state.hasProgram) {
			throw new BridgeException(409, "no active program");
		}
		if (state.readOnly) {
			throw new BridgeException(409, "program is read-only");
		}
		if (state.versioned && !state.checkedOut) {
			throw new BridgeException(409, "versioned program is not checked out for write");
		}
		if (!state.writableProject) {
			throw new BridgeException(409, "program is not in a writable project");
		}
	}

	private void requireWriteFlags(JsonObject body, boolean destructive) throws BridgeException {
		if (!optBoolean(body, "write", false)) {
			throw new BridgeException(400, "mutating requests require write=true");
		}
		if (destructive && !optBoolean(body, "destructive", false)) {
			throw new BridgeException(400, "destructive requests require destructive=true");
		}
	}

	private boolean isAuthorized(Headers headers) {
		String authorization = headers.getFirst("Authorization");
		return authorization != null && authorization.equals("Bearer " + token);
	}

	private JsonObject readBody(HttpExchange exchange) throws IOException {
		try (InputStream inputStream = exchange.getRequestBody()) {
			String text = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8).trim();
			if (text.isEmpty()) {
				return new JsonObject();
			}
			JsonElement element = JsonParser.parseString(text);
			if (!element.isJsonObject()) {
				throw new IOException("request body must be a JSON object");
			}
			return element.getAsJsonObject();
		}
	}

	private void sendJson(HttpExchange exchange, int statusCode, JsonElement result, String error)
			throws IOException {
		JsonObject envelope = new JsonObject();
		envelope.addProperty("ok", error == null);
		envelope.add("result", result == null ? JsonNull.INSTANCE : result);
		envelope.addProperty("error", error);
		envelope.addProperty("state_version", plugin.getStateVersion());
		envelope.addProperty("program_path", programPath(plugin.getCurrentProgram()));
		envelope.addProperty("tool_name", plugin.getTool().getToolName());
		byte[] bytes = GSON.toJson(envelope).getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
		exchange.sendResponseHeaders(statusCode, bytes.length);
		try (OutputStream outputStream = exchange.getResponseBody()) {
			outputStream.write(bytes);
		}
	}

	private JsonObject repositoryToJson(RepositoryState state) {
		JsonObject object = new JsonObject();
		object.addProperty("has_program", state.hasProgram);
		object.addProperty("program_name", state.programName);
		object.addProperty("project_name", state.projectName);
		object.addProperty("project_location", state.projectLocation);
		object.addProperty("project_path", state.projectMarkerPath);
		object.addProperty("program_path", state.domainPath);
		object.addProperty("versioned", state.versioned);
		object.addProperty("read_only", state.readOnly);
		object.addProperty("checked_out", state.checkedOut);
		object.addProperty("checked_out_exclusive", state.exclusiveCheckout);
		object.addProperty("modified_since_checkout", state.modifiedSinceCheckout);
		object.addProperty("writable_project", state.writableProject);
		object.addProperty("can_save", state.canSave);
		object.addProperty("changed", state.changed);
		return object;
	}

	private JsonObject functionToJson(Function function, boolean includeVariables) {
		JsonObject object = new JsonObject();
		object.add("function_ref", functionRef(function));
		object.addProperty("name", function.getName());
		object.addProperty("entry", function.getEntryPoint().toString());
		object.addProperty("signature", function.getPrototypeString(false, false));
		object.addProperty("calling_convention", empty(function.getCallingConventionName()));
		object.addProperty("comment", empty(function.getComment()));
		object.addProperty("repeatable_comment", empty(function.getRepeatableComment()));
		object.addProperty("thunk", function.isThunk());
		object.addProperty("external", function.isExternal());
		object.addProperty("is_inline", function.isInline());
		object.addProperty("has_var_args", function.hasVarArgs());
		object.addProperty("no_return", function.hasNoReturn());
		object.add("body", addressSetToJson(function.getBody(), 32));
		if (includeVariables) {
			JsonArray parameters = new JsonArray();
			for (Parameter parameter : function.getParameters()) {
				parameters.add(variableToJson(parameter));
			}
			object.add("parameters", parameters);
			JsonArray locals = new JsonArray();
			for (Variable local : function.getLocalVariables()) {
				locals.add(variableToJson(local));
			}
			object.add("locals", locals);
			object.add("return", variableToJson(function.getReturn()));
		}
		return object;
	}

	private FunctionSearchHit matchFunctionSearch(Function function, String query,
			String normalizedQuery, boolean exact, boolean caseSensitive, String field) {
		FunctionSearchHit best = null;
		if ("name".equalsIgnoreCase(field) || "both".equalsIgnoreCase(field)) {
			best = betterFunctionSearchHit(best,
				matchFunctionSearchCandidate(function, "name", function.getName(), query,
					normalizedQuery, exact, caseSensitive));
		}
		if ("signature".equalsIgnoreCase(field) || "both".equalsIgnoreCase(field)) {
			best = betterFunctionSearchHit(best,
				matchFunctionSearchCandidate(function, "signature",
					function.getPrototypeString(false, false), query, normalizedQuery, exact,
					caseSensitive));
		}
		return best;
	}

	private FunctionSearchHit betterFunctionSearchHit(FunctionSearchHit current,
			FunctionSearchHit candidate) {
		if (candidate == null) {
			return current;
		}
		if (current == null || candidate.rank < current.rank) {
			return candidate;
		}
		return current;
	}

	private FunctionSearchHit matchFunctionSearchCandidate(Function function, String field,
			String candidateValue, String query, String normalizedQuery, boolean exact,
			boolean caseSensitive) {
		if (candidateValue == null || candidateValue.isEmpty()) {
			return null;
		}
		String normalizedCandidate = normalizeForSearch(candidateValue, caseSensitive);
		boolean matched = exact ? normalizedCandidate.equals(normalizedQuery) :
			normalizedCandidate.contains(normalizedQuery);
		if (!matched) {
			matched = matchesNormalizedQuery(candidateValue, query, exact, caseSensitive);
		}
		if (!matched) {
			return null;
		}
		String matchKind;
		int rank;
		if (normalizedCandidate.equals(normalizedQuery)) {
			matchKind = "exact";
			rank = "name".equals(field) ? 0 : 1;
		}
		else if (normalizedCandidate.startsWith(normalizedQuery)) {
			matchKind = "prefix";
			rank = "name".equals(field) ? 2 : 3;
		}
		else {
			matchKind = "substring";
			rank = "name".equals(field) ? 4 : 5;
		}
		return new FunctionSearchHit(function, field, candidateValue, matchKind, rank);
	}

	private String normalizeForSearch(String value, boolean caseSensitive) {
		if (value == null) {
			return "";
		}
		return caseSensitive ? value : value.toLowerCase(Locale.ROOT);
	}

	private String normalizeFunctionLookupValue(String value, boolean caseSensitive) {
		String normalized = normalizeForSearch(value, caseSensitive).trim();
		if (normalized.isEmpty()) {
			return normalized;
		}
		normalized = normalized.replaceAll("\\s+", " ");
		if (normalized.startsWith("-[") || normalized.startsWith("+[")) {
			int closeIndex = normalized.indexOf(']');
			int spaceIndex = normalized.indexOf(' ');
			if (spaceIndex < 0 || (closeIndex > 0 && spaceIndex > closeIndex)) {
				int separatorIndex = normalized.indexOf('_', 2);
				if (separatorIndex > 2 && (closeIndex < 0 || separatorIndex < closeIndex)) {
					normalized = normalized.substring(0, separatorIndex) + " " +
						normalized.substring(separatorIndex + 1);
				}
			}
			normalized = normalized.replace("[ ", "[");
			normalized = normalized.replace(" ]", "]");
			normalized = normalized.replace(" :", ":");
			normalized = normalized.replace("( ", "(");
			normalized = normalized.replace(" )", ")");
		}
		return normalized;
	}

	private boolean matchesNormalizedQuery(String candidate, String query, boolean exact,
			boolean caseSensitive) {
		String normalizedCandidate = normalizeFunctionLookupValue(candidate, caseSensitive);
		String normalizedQuery = normalizeFunctionLookupValue(query, caseSensitive);
		if (normalizedCandidate.isEmpty() || normalizedQuery.isEmpty()) {
			return false;
		}
		return exact ? normalizedCandidate.equals(normalizedQuery) :
			normalizedCandidate.contains(normalizedQuery);
	}

	private JsonObject variableToJson(Variable variable) {
		JsonObject object = new JsonObject();
		if (variable == null) {
			return object;
		}
		object.add("variable_ref", variableRef(variable));
		object.addProperty("name", variable.getName());
		object.addProperty("datatype", pathName(variable.getDataType()));
		object.addProperty("comment", empty(variable.getComment()));
		object.addProperty("storage", variable.getVariableStorage().toString());
		object.addProperty("kind", variableKind(variable));
		object.addProperty("stack_offset", variable.hasStackStorage() ? variable.getStackOffset() : 0);
		object.addProperty("first_use_offset", variable.getFirstUseOffset());
		return object;
	}

	private JsonObject dataTypeToJson(DataType dataType) {
		JsonObject object = new JsonObject();
		object.add("datatype_ref", dataTypeRef(dataType));
		object.addProperty("name", dataType.getName());
		object.addProperty("display_name", dataType.getDisplayName());
		object.addProperty("path_name", dataType.getPathName());
		object.addProperty("category_path", dataType.getCategoryPath().getPath());
		object.addProperty("length", dataType.getLength());
		object.addProperty("description", empty(dataType.getDescription()));
		object.addProperty("kind", dataType.getClass().getSimpleName());
		return object;
	}

	private JsonObject dataToJson(Program program, Data data, int xrefLimit) {
		JsonObject object = new JsonObject();
		object.add("location_ref", locationRef(program, data.getAddress()));
		object.addProperty("address", data.getAddress().toString());
		object.addProperty("datatype", data.getDataType().getPathName());
		object.addProperty("length", data.getLength());
		object.addProperty("value", safeValue(data));
		MemoryBlock block = program.getMemory().getBlock(data.getAddress());
		String blockName = block == null ? "" : empty(block.getName());
		object.addProperty("block", blockName);
		object.addProperty("artifact_type", classifyDataArtifact(data, blockName));
		String candidate = candidateDataString(data);
		if (!candidate.isEmpty()) {
			object.addProperty("string_value", candidate);
		}
		object.add("references_to",
			referencesToJson(new FlatProgramAPI(program, TaskMonitor.DUMMY), data.getAddress(),
				xrefLimit));
		return object;
	}

	private JsonObject dataRef(Program program, Data data) {
		JsonObject object = new JsonObject();
		object.addProperty("program_path", programPath(program));
		object.addProperty("address", data == null ? "" : data.getAddress().toString());
		object.addProperty("datatype",
			data == null || data.getDataType() == null ? "" : data.getDataType().getPathName());
		return object;
	}

	private String safeValue(Data data) {
		try {
			Object value = data.getValue();
			return value == null ? "" : value.toString();
		}
		catch (Exception ignored) {
			return "";
		}
	}

	private String candidateDataString(Data data) {
		String value = safeValue(data).trim();
		if (value.isEmpty()) {
			return "";
		}
		if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
			value = value.substring(1, value.length() - 1);
		}
		return value;
	}

	private String classifyDataArtifact(Data data, String blockName) {
		String lowerBlock = blockName == null ? "" : blockName.toLowerCase(Locale.ROOT);
		String dataType = data.getDataType() == null ? "" : data.getDataType().getPathName().toLowerCase(Locale.ROOT);
		if (lowerBlock.contains("objc_methname")) {
			return "objc_selector";
		}
		if (lowerBlock.contains("objc_classname")) {
			return "objc_classname";
		}
		if (lowerBlock.contains("cfstring")) {
			return "cfstring";
		}
		if (lowerBlock.contains("classref")) {
			return "objc_classref";
		}
		if (lowerBlock.contains("selref")) {
			return "objc_selref";
		}
		if (lowerBlock.contains("ivar")) {
			return "objc_ivar";
		}
		if (lowerBlock.contains("protocol")) {
			return "objc_protocol";
		}
		if (dataType.contains("string")) {
			return "string";
		}
		return "data";
	}

	private boolean isLowSignalDecompile(Function function, String cText) {
		String name = function == null ? "" : empty(function.getName());
		String c = cText == null ? "" : cText;
		if (name.startsWith("_OUTLINED_FUNCTION_")) {
			return true;
		}
		if (name.startsWith("FUN_") && function != null && function.getBody().getNumAddresses() <= 16) {
			return true;
		}
		return c.contains("_OUTLINED_FUNCTION_") || c.contains("/* WARNING:") ||
			(function != null && function.getBody().getNumAddresses() <= 12);
	}

	private JsonObject buildLowSignalFunctionContext(Program program, Function function, int limit) {
		JsonObject payload = new JsonObject();
		payload.addProperty("name", function.getName());
		payload.addProperty("entry", function.getEntryPoint().toString());
		payload.addProperty("body_size", function.getBody().getNumAddresses());
		MemoryBlock block = program.getMemory().getBlock(function.getEntryPoint());
		payload.addProperty("section", block == null ? "" : empty(block.getName()));

		Set<String> nearbyStrings = new LinkedHashSet<>();
		Set<String> nearbySelectors = new LinkedHashSet<>();
		Set<String> nearbySymbols = new LinkedHashSet<>();
		Set<String> calledSymbols = new LinkedHashSet<>();
		Listing listing = program.getListing();
		SymbolTable symbolTable = program.getSymbolTable();
		InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
		while (iterator.hasNext()) {
			Instruction instruction = iterator.next();
			for (Reference reference : instruction.getReferencesFrom()) {
				Address toAddress = reference.getToAddress();
				if (toAddress == null) {
					continue;
				}
				Data data = listing.getDefinedDataContaining(toAddress);
				if (data != null) {
					String value = candidateDataString(data);
					if (!value.isEmpty()) {
						MemoryBlock dataBlock = program.getMemory().getBlock(data.getAddress());
						String blockName =
							dataBlock == null ? "" : empty(dataBlock.getName()).toLowerCase(Locale.ROOT);
						if (blockName.contains("objc_methname") || blockName.contains("selref")) {
							nearbySelectors.add(value);
						}
						else {
							nearbyStrings.add(value);
						}
					}
				}
				Symbol symbol = symbolTable.getPrimarySymbol(toAddress);
				if (symbol != null) {
					String name = empty(symbol.getName());
					if (!name.isEmpty()) {
						nearbySymbols.add(name);
						if (reference.getReferenceType().isCall()) {
							calledSymbols.add(name);
						}
					}
				}
			}
		}
		payload.add("nearby_strings", toJsonArray(nearbyStrings, limit));
		payload.add("nearby_selectors", toJsonArray(nearbySelectors, limit));
		payload.add("nearby_symbols", toJsonArray(nearbySymbols, limit));
		payload.add("called_symbols", toJsonArray(calledSymbols, limit));
		return payload;
	}

	private JsonArray toJsonArray(Collection<String> values, int limit) {
		JsonArray array = new JsonArray();
		int count = 0;
		for (String value : values) {
			if (value == null || value.isEmpty()) {
				continue;
			}
			array.add(value);
			count++;
			if (count >= limit) {
				break;
			}
		}
		return array;
	}

	private String classifySymbolArtifact(Symbol symbol) {
		String name = symbol.getName();
		String lower = name.toLowerCase(Locale.ROOT);
		if (name.startsWith("-[") || name.startsWith("+[")) {
			return "objc_method";
		}
		if (name.startsWith("_OBJC_CLASS_$_")) {
			return "objc_class";
		}
		if (name.startsWith("_OBJC_METACLASS_$_")) {
			return "objc_metaclass";
		}
		if (name.startsWith("_OBJC_PROTOCOL_$_")) {
			return "objc_protocol";
		}
		if (name.startsWith("_OBJC_CATEGORY_$_")) {
			return "objc_category";
		}
		if (name.startsWith("selRef_")) {
			return "objc_selref";
		}
		if (lower.contains("classref")) {
			return "objc_classref";
		}
		if (lower.contains("ivar")) {
			return "objc_ivar";
		}
		if (name.startsWith("$s") || name.startsWith("_$s") || lower.contains("swift")) {
			return "swift_symbol";
		}
		return "symbol";
	}

	private int referenceCount(Program program, Address address) {
		int count = 0;
		ReferenceIterator iterator = program.getReferenceManager().getReferencesTo(address);
		while (iterator.hasNext()) {
			iterator.next();
			count++;
		}
		return count;
	}

	private String bytesToAscii(byte[] bytes) {
		StringBuilder builder = new StringBuilder();
		for (byte value : bytes) {
			int unsigned = value & 0xff;
			if (unsigned >= 32 && unsigned <= 126) {
				builder.append((char) unsigned);
			}
			else {
				builder.append('.');
			}
		}
		return builder.toString();
	}

	private JsonArray referencesToJson(FlatProgramAPI flat, Address address, int limit) {
		JsonArray array = new JsonArray();
		Reference[] references = flat.getReferencesTo(address);
		for (int i = 0; i < references.length && i < limit; i++) {
			array.add(referenceToJson(references[i]));
		}
		return array;
	}

	private JsonArray referencesFromJson(FlatProgramAPI flat, Address address, int limit) {
		JsonArray array = new JsonArray();
		Reference[] references = flat.getReferencesFrom(address);
		for (int i = 0; i < references.length && i < limit; i++) {
			array.add(referenceToJson(references[i]));
		}
		return array;
	}

	private JsonObject referenceToJson(Reference reference) {
		JsonObject object = new JsonObject();
		object.addProperty("from_address", reference.getFromAddress().toString());
		object.addProperty("to_address", reference.getToAddress().toString());
		object.addProperty("reference_type", reference.getReferenceType().toString());
		object.addProperty("operand_index", reference.getOperandIndex());
		object.addProperty("primary", reference.isPrimary());
		return object;
	}

	private JsonArray selectionToJson(ProgramSelection selection, int maxRanges) {
		if (selection == null || selection.isEmpty()) {
			return new JsonArray();
		}
		return addressSetToJson(selection, maxRanges);
	}

	private JsonArray addressSetToJson(AddressSetView view, int maxRanges) {
		JsonArray array = new JsonArray();
		if (view == null) {
			return array;
		}
		AddressRangeIterator iterator = view.getAddressRanges();
		int count = 0;
		while (iterator.hasNext() && count < maxRanges) {
			AddressRange range = iterator.next();
			JsonObject item = new JsonObject();
			item.addProperty("start", range.getMinAddress().toString());
			item.addProperty("end", range.getMaxAddress().toString());
			item.addProperty("length", range.getLength());
			array.add(item);
			count++;
		}
		return array;
	}

	private JsonObject locationRef(Program program, Address address) {
		JsonObject object = new JsonObject();
		object.addProperty("program_path", programPath(program));
		object.addProperty("address", address == null ? "" : address.toString());
		return object;
	}

	private JsonObject functionRef(Function function) {
		JsonObject object = new JsonObject();
		object.addProperty("program_path", programPath(function == null ? null : function.getProgram()));
		object.addProperty("entry", function == null ? "" : function.getEntryPoint().toString());
		return object;
	}

	private String namespacePath(Namespace namespace) {
		if (namespace == null) {
			return "";
		}
		List<String> names = new ArrayList<>();
		Namespace current = namespace;
		while (current != null && !current.isGlobal()) {
			names.add(0, current.getName());
			current = current.getParentNamespace();
		}
		return String.join("::", names);
	}

	private JsonObject variableRef(Variable variable) {
		JsonObject object = new JsonObject();
		object.addProperty("program_path",
			programPath(variable == null ? null : variable.getProgram()));
		object.addProperty("function_entry",
			variable != null && variable.getFunction() != null ?
				variable.getFunction().getEntryPoint().toString() :
				"");
		object.addProperty("name", variable == null ? "" : variable.getName());
		object.addProperty("kind", variableKind(variable));
		object.addProperty("storage", variable == null ? "" : variable.getVariableStorage().toString());
		return object;
	}

	private JsonObject dataTypeRef(DataType dataType) {
		JsonObject object = new JsonObject();
		object.addProperty("program_path", programPath(plugin.getCurrentProgram()));
		object.addProperty("category_path",
			dataType == null ? "" : dataType.getCategoryPath().getPath());
		object.addProperty("name", dataType == null ? "" : dataType.getName());
		object.addProperty("kind", dataType == null ? "" : dataType.getClass().getSimpleName());
		return object;
	}

	private JsonObject symbolToJson(Program program, Symbol symbol, int xrefLimit) {
		JsonObject object = new JsonObject();
		object.addProperty("name", symbol.getName());
		object.addProperty("address", symbol.getAddress().toString());
		object.addProperty("kind", symbol.getSymbolType().toString());
		object.addProperty("source", symbol.getSource().toString());
		object.addProperty("namespace", namespacePath(symbol.getParentNamespace()));
		object.addProperty("artifact_type", classifySymbolArtifact(symbol));
		object.add("location_ref", locationRef(program, symbol.getAddress()));
		object.addProperty("xref_count",
			referenceCount(program, symbol.getAddress()));
		object.add("sample_xrefs",
			referencesToJson(new FlatProgramAPI(program, TaskMonitor.DUMMY), symbol.getAddress(),
				xrefLimit));
		return object;
	}

	private JsonObject commentSnapshot(Program program, Address address) {
		JsonObject object = new JsonObject();
		object.addProperty("address", address.toString());
		Listing listing = program.getListing();
		object.addProperty("plate", empty(listing.getComment(CommentType.PLATE, address)));
		object.addProperty("pre", empty(listing.getComment(CommentType.PRE, address)));
		object.addProperty("post", empty(listing.getComment(CommentType.POST, address)));
		object.addProperty("eol", empty(listing.getComment(CommentType.EOL, address)));
		object.addProperty("repeatable", empty(listing.getComment(CommentType.REPEATABLE, address)));
		return object;
	}

	private JsonObject bookmarksToJson(ghidra.program.model.listing.Bookmark[] bookmarks) {
		JsonObject object = new JsonObject();
		JsonArray array = new JsonArray();
		for (ghidra.program.model.listing.Bookmark bookmark : bookmarks) {
			JsonObject item = new JsonObject();
			item.addProperty("type", bookmark.getTypeString());
			item.addProperty("category", bookmark.getCategory());
			item.addProperty("comment", bookmark.getComment());
			array.add(item);
		}
		object.add("bookmarks", array);
		return object;
	}

	private JsonObject bytePatchSnapshot(Program program, Address address, byte[] bytes) {
		JsonObject object = new JsonObject();
		object.addProperty("address", address.toString());
		object.addProperty("length", bytes.length);
		object.addProperty("bytes", toHex(bytes));
		Instruction instruction = program.getListing().getInstructionAt(address);
		if (instruction != null) {
			object.addProperty("instruction", instruction.toString());
		}
		return object;
	}

	private JsonObject instructionSnapshot(Program program, Instruction instruction, Address address,
			byte[] bytes) {
		JsonObject object = new JsonObject();
		object.addProperty("address", address.toString());
		object.addProperty("bytes", toHex(bytes));
		object.addProperty("instruction", instruction == null ? "" : instruction.toString());
		object.addProperty("length", instruction == null ? bytes.length : instruction.getLength());
		return object;
	}

	private JsonObject rangeSnapshot(Program program, Address start, Address end) {
		JsonObject object = new JsonObject();
		object.addProperty("start", start.toString());
		object.addProperty("end", end.toString());
		int length = (int) Math.min(end.subtract(start) + 1L, MAX_BYTES_IN_LOG);
		object.addProperty("captured_length", length);
		try {
			object.addProperty("bytes",
				toHex(new FlatProgramAPI(program, TaskMonitor.DUMMY).getBytes(start, length)));
		}
		catch (Exception e) {
			object.addProperty("bytes", "");
		}
		object.addProperty("instructions",
			program.getListing().getInstructions(new AddressSet(start, end), true).hasNext());
		object.addProperty("data",
			program.getListing().getDefinedData(new AddressSet(start, end), true).hasNext());
		return object;
	}

	private byte[] instructionBytes(FlatProgramAPI flat, Instruction instruction) throws Exception {
		if (instruction == null) {
			return new byte[0];
		}
		return flat.getBytes(instruction.getAddress(), instruction.getLength());
	}

	private boolean hasExplicitSessionSelector(JsonObject body) {
		return hasAny(body, "session", "session_id", "project", "project_name", "program",
			"program_name");
	}

	private boolean hasExplicitFunctionSelector(JsonObject body) {
		return optObject(body, "function_ref") != null || hasAny(body, "function", "function_name");
	}

	private boolean hasExplicitAddressSelector(JsonObject body) {
		return optObject(body, "location_ref") != null || hasAny(body, "address", "entry", "start");
	}

	private boolean hasAnyExplicitTargetSelector(JsonObject body) {
		return hasExplicitSessionSelector(body) || hasExplicitFunctionSelector(body) ||
			hasExplicitAddressSelector(body);
	}

	private Function resolveFunction(Program program, JsonObject body) throws Exception {
		return resolveFunction(program, body, false);
	}

	private Function resolveFunction(Program program, JsonObject body, boolean allowMissing)
			throws Exception {
		JsonObject functionRef = optObject(body, "function_ref");
		if (functionRef != null) {
			String entry = optString(functionRef, "entry");
			if (!entry.isEmpty()) {
				Function function = program.getFunctionManager().getFunctionAt(parseAddress(program, entry));
				if (function != null) {
					return function;
				}
			}
		}
		String functionName = optString(body, "function", "function_name");
		if (!functionName.isEmpty()) {
			Function byName = resolveFunctionByName(program, functionName);
			if (byName != null) {
				return byName;
			}
			Address parsed = tryParseAddress(program, functionName);
			if (parsed != null) {
				Function byAddress = program.getFunctionManager().getFunctionContaining(parsed);
				if (byAddress != null) {
					return byAddress;
				}
			}
		}
		String addressString = optString(body, "address", "entry");
		if (!addressString.isEmpty()) {
			Address address = parseAddress(program, addressString);
			Function byAddress = program.getFunctionManager().getFunctionContaining(address);
			if (byAddress != null) {
				return byAddress;
			}
		}
		if (hasAnyExplicitTargetSelector(body)) {
			if (allowMissing) {
				return null;
			}
			throw new BridgeException(404, "unable to resolve function from explicit target");
		}
		Function current = plugin.getCurrentFunction();
		if (current != null) {
			return current;
		}
		if (allowMissing) {
			return null;
		}
		throw new BridgeException(404, "unable to resolve function");
	}

	private Function resolveFunctionByName(Program program, String name) {
		String normalizedName = normalizeFunctionLookupValue(name, false);
		Function exact = null;
		Function normalizedExact = null;
		Function caseInsensitive = null;
		Function contains = null;
		for (Function function : program.getListing().getGlobalFunctions(name)) {
			return function;
		}
		for (ghidra.program.model.listing.FunctionIterator iterator =
			program.getFunctionManager().getFunctions(true); iterator.hasNext();) {
			Function function = iterator.next();
			String functionName = function.getName();
			String signature = function.getPrototypeString(false, false);
			if (name.equals(functionName) || name.equals(signature)) {
				exact = function;
				break;
			}
			if (normalizedExact == null && (normalizedName.equals(
				normalizeFunctionLookupValue(functionName, false)) || normalizedName.equals(
					normalizeFunctionLookupValue(signature, false)))) {
				normalizedExact = function;
			}
			if (caseInsensitive == null &&
				(functionName.equalsIgnoreCase(name) || signature.equalsIgnoreCase(name))) {
				caseInsensitive = function;
			}
			if (contains == null &&
				(matchesNormalizedQuery(functionName, name, false, false) ||
					matchesNormalizedQuery(signature, name, false, false))) {
				contains = function;
			}
		}
		return exact != null ? exact :
			normalizedExact != null ? normalizedExact :
				caseInsensitive != null ? caseInsensitive : contains;
	}

	private Variable resolveVariable(Program program, JsonObject body, boolean allowMissing)
			throws Exception {
		JsonObject ref = optObject(body, "variable_ref");
		Function function = null;
		String variableName = "";
		String kind = "";
		String storage = "";
		if (ref != null) {
			String functionEntry = optString(ref, "function_entry");
			if (!functionEntry.isEmpty()) {
				function = program.getFunctionManager().getFunctionAt(parseAddress(program, functionEntry));
			}
			variableName = optString(ref, "name");
			kind = optString(ref, "kind");
			storage = optString(ref, "storage");
		}
		if (function == null) {
			function = resolveFunction(program, body, true);
		}
		if (variableName.isEmpty()) {
			variableName = optString(body, "variable", "name");
		}
		if (kind.isEmpty()) {
			kind = optString(body, "kind");
		}
		if (storage.isEmpty()) {
			storage = optString(body, "storage");
		}
		if (function != null) {
			if ("return".equals(kind)) {
				return function.getReturn();
			}
			for (Parameter parameter : function.getParameters()) {
				if (matchesVariable(parameter, variableName, kind, storage)) {
					return parameter;
				}
			}
			for (Variable local : function.getLocalVariables()) {
				if (matchesVariable(local, variableName, kind, storage)) {
					return local;
				}
			}
		}
		if (allowMissing) {
			return null;
		}
		throw new BridgeException(404, "unable to resolve variable");
	}

	private boolean matchesVariable(Variable variable, String name, String kind, String storage) {
		if (!name.isEmpty() && !name.equals(variable.getName())) {
			return false;
		}
		if (!kind.isEmpty() && !kind.equalsIgnoreCase(variableKind(variable))) {
			return false;
		}
		if (!storage.isEmpty() && !storage.equals(variable.getVariableStorage().toString())) {
			return false;
		}
		return true;
	}

	private Address resolveAddress(Program program, JsonObject body, boolean allowMissing)
			throws Exception {
		Address explicit = resolveExactAddress(program, body, true);
		if (explicit != null) {
			return explicit;
		}
		if (hasAnyExplicitTargetSelector(body)) {
			if (allowMissing) {
				return null;
			}
			throw new BridgeException(404, "unable to resolve address from explicit target");
		}
		Function function = resolveFunction(program, body, true);
		if (function != null) {
			return function.getEntryPoint();
		}
		Address current = plugin.getCurrentAddress();
		if (current != null) {
			return current;
		}
		if (allowMissing) {
			return null;
		}
		throw new BridgeException(404, "unable to resolve address");
	}

	private Address resolveExactAddress(Program program, JsonObject body, boolean allowMissing)
			throws Exception {
		JsonObject locationRef = optObject(body, "location_ref");
		if (locationRef != null) {
			String address = optString(locationRef, "address");
			if (!address.isEmpty()) {
				return parseAddress(program, address);
			}
		}
		String address = optString(body, "address", "entry", "start");
		if (!address.isEmpty()) {
			return parseAddress(program, address);
		}
		if (allowMissing) {
			return null;
		}
		throw new BridgeException(404, "unable to resolve exact address");
	}

	private List<Symbol> resolveSymbols(Program program, JsonObject body, boolean allowMissing)
			throws Exception {
		List<Symbol> matches = new ArrayList<>();
		JsonObject symbolRef = optObject(body, "symbol_ref");
		String query = optString(body, "symbol", "name", "query");
		String addressText = optString(body, "address");
		if (symbolRef != null) {
			if (query.isEmpty()) {
				query = optString(symbolRef, "name");
			}
			if (addressText.isEmpty()) {
				addressText = optString(symbolRef, "address");
			}
		}
		if (!addressText.isEmpty()) {
			Address address = parseAddress(program, addressText);
			for (Symbol symbol : program.getSymbolTable().getSymbols(address)) {
				matches.add(symbol);
			}
		}
		if (!query.isEmpty()) {
			String normalizedQuery = normalizeForSearch(query, false);
			for (SymbolIterator iterator = program.getSymbolTable().getAllSymbols(true); iterator
					.hasNext();) {
				Symbol symbol = iterator.next();
				String name = symbol.getName();
				if (name.equals(query) || name.equalsIgnoreCase(query) ||
					normalizeForSearch(name, false).contains(normalizedQuery)) {
					matches.add(symbol);
				}
			}
		}
		if (matches.isEmpty() && !allowMissing) {
			throw new BridgeException(404, "unable to resolve symbol");
		}
		List<Symbol> unique = new ArrayList<>();
		Set<String> seen = new LinkedHashSet<>();
		for (Symbol symbol : matches) {
			String key = symbol.getAddress().toString() + "|" + symbol.getName() + "|" +
				symbol.getSymbolType();
			if (seen.add(key)) {
				unique.add(symbol);
			}
		}
		final String requestedQuery = query;
		unique.sort(Comparator
			.comparing((Symbol symbol) -> !symbol.getName().equals(requestedQuery))
			.thenComparing(symbol -> !symbol.getName().equalsIgnoreCase(requestedQuery))
			.thenComparing(Symbol::isExternal)
			.thenComparing((Symbol symbol) -> -referenceCount(program, symbol.getAddress()))
			.thenComparing(Symbol::getName, String.CASE_INSENSITIVE_ORDER)
			.thenComparing(symbol -> symbol.getAddress().toString()));
		return unique;
	}

	private Address resolveEndAddress(Program program, JsonObject body, Address start) throws Exception {
		String endString = optString(body, "end", "body_end");
		if (!endString.isEmpty()) {
			return parseAddress(program, endString);
		}
		if (body.has("length")) {
			long length = body.get("length").getAsLong();
			return start.add(Math.max(length - 1L, 0L));
		}
		return start;
	}

	private DataType resolveDataType(Program program, JsonObject body, boolean allowBuiltin)
			throws Exception {
		JsonObject datatypeRef = optObject(body, "datatype_ref");
		if (datatypeRef != null) {
			DataType byRef = resolveDataType(program, optString(datatypeRef, "category_path"),
				optString(datatypeRef, "name"));
			if (byRef != null) {
				return byRef;
			}
		}
		String typeName = optString(body, "datatype", "type", "base_type");
		return resolveDataType(program, typeName, allowBuiltin);
	}

	private DataType resolveDataType(Program program, String typeName, boolean allowBuiltin)
			throws Exception {
		if (typeName == null || typeName.isEmpty()) {
			throw new BridgeException(400, "missing datatype");
		}
		DataTypeManager manager = program.getDataTypeManager();
		DataType exact = manager.getDataType(typeName);
		if (exact != null) {
			return exact;
		}
		exact = manager.findDataType(typeName);
		if (exact != null) {
			return exact;
		}
		List<DataType> matches = new ArrayList<>();
		manager.findDataTypes(typeName, matches);
		if (!matches.isEmpty()) {
			return matches.get(0);
		}
		if (allowBuiltin) {
			DataType builtin = builtinType(typeName);
			if (builtin != null) {
				return builtin;
			}
		}
		throw new BridgeException(404, "unable to resolve datatype: " + typeName);
	}

	private DataType resolveDataType(Program program, String categoryPath, String name) {
		if (name == null || name.isEmpty()) {
			return null;
		}
		DataTypeManager manager = program.getDataTypeManager();
		if (categoryPath != null && !categoryPath.isEmpty()) {
			return manager.getDataType(new CategoryPath(categoryPath), name);
		}
		return manager.findDataType(name);
	}

	private DataType builtinType(String name) {
		String normalized = name.trim().toLowerCase(Locale.ROOT);
		switch (normalized) {
			case "byte":
			case "u8":
			case "uint8":
			case "int8":
				return ByteDataType.dataType;
			case "word":
			case "u16":
			case "uint16":
			case "short":
				return WordDataType.dataType;
			case "dword":
			case "u32":
			case "uint32":
			case "int":
			case "int32":
				return DWordDataType.dataType;
			case "qword":
			case "u64":
			case "uint64":
			case "longlong":
			case "int64":
				return QWordDataType.dataType;
			case "char":
				return CharDataType.dataType;
			case "float":
				return FloatDataType.dataType;
			case "double":
				return DoubleDataType.dataType;
			case "string":
			case "ascii":
				return StringDataType.dataType;
			case "unicode":
			case "utf16":
				return UnicodeDataType.dataType;
			case "pointer":
			case "void*":
				return PointerDataType.dataType;
			case "void":
				return DataType.VOID;
			default:
				return null;
		}
	}

	private DataType createStruct(DataTypeManager manager, JsonObject body, Program program)
			throws Exception {
		String name = optString(body, "name");
		if (name.isEmpty()) {
			throw new BridgeException(400, "missing datatype name");
		}
		String categoryPath = optString(body, "category_path");
		int length = optInt(body, "length", 0);
		StructureDataType structure =
			new StructureDataType(new CategoryPath(defaultCategory(categoryPath)), name, length, manager);
		JsonArray members = optArray(body, "members");
		if (members != null) {
			for (JsonElement element : members) {
				JsonObject member = element.getAsJsonObject();
				String memberName = optString(member, "name");
				String memberTypeName = optString(member, "type", "datatype");
				DataType memberType = resolveDataType(program, memberTypeName, true);
				int memberLength = optInt(member, "length", Math.max(memberType.getLength(), 1));
				structure.add(memberType, memberLength, memberName, optString(member, "comment"));
			}
		}
		String description = optString(body, "description");
		if (!description.isEmpty()) {
			structure.setDescription(description);
		}
		return manager.addDataType(structure, DataTypeConflictHandler.DEFAULT_HANDLER);
	}

	private DataType createEnum(DataTypeManager manager, JsonObject body, Program program)
			throws Exception {
		String name = optString(body, "name");
		if (name.isEmpty()) {
			throw new BridgeException(400, "missing datatype name");
		}
		String categoryPath = optString(body, "category_path");
		int length = optInt(body, "length", 4);
		EnumDataType dataType =
			new EnumDataType(new CategoryPath(defaultCategory(categoryPath)), name, length, manager);
		JsonArray members = optArray(body, "members");
		if (members != null) {
			for (JsonElement element : members) {
				JsonObject member = element.getAsJsonObject();
				String memberName = optString(member, "name");
				long value = member.get("value").getAsLong();
				String comment = optString(member, "comment");
				if (comment.isEmpty()) {
					dataType.add(memberName, value);
				}
				else {
					dataType.add(memberName, value, comment);
				}
			}
		}
		String description = optString(body, "description");
		if (!description.isEmpty()) {
			dataType.setDescription(description);
		}
		return manager.addDataType(dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
	}

	private DataType createTypedef(DataTypeManager manager, JsonObject body, Program program)
			throws Exception {
		String name = optString(body, "name");
		if (name.isEmpty()) {
			throw new BridgeException(400, "missing datatype name");
		}
		String categoryPath = optString(body, "category_path");
		DataType baseType = resolveDataType(program, optString(body, "base_type", "type"), true);
		TypedefDataType type =
			new TypedefDataType(new CategoryPath(defaultCategory(categoryPath)), name, baseType, manager);
		String description = optString(body, "description");
		if (!description.isEmpty()) {
			type.setDescription(description);
		}
		return manager.addDataType(type, DataTypeConflictHandler.DEFAULT_HANDLER);
	}

	private void updateDatatype(DataType dataType, JsonObject body, Program program)
			throws Exception {
		String newName = optString(body, "new_name", "rename");
		String categoryPath = optString(body, "new_category_path", "category_path");
		String description = optString(body, "description");
		if (!newName.isEmpty() && !categoryPath.isEmpty()) {
			dataType.setNameAndCategory(new CategoryPath(defaultCategory(categoryPath)), newName);
		}
		else if (!newName.isEmpty()) {
			dataType.setName(newName);
		}
		else if (!categoryPath.isEmpty()) {
			dataType.setCategoryPath(new CategoryPath(defaultCategory(categoryPath)));
		}
		if (!description.isEmpty()) {
			dataType.setDescription(description);
		}
		JsonArray members = optArray(body, "members");
		if (members != null && dataType instanceof Structure) {
			Structure structure = (Structure) dataType;
			structure.deleteAll();
			for (JsonElement element : members) {
				JsonObject member = element.getAsJsonObject();
				DataType memberType =
					resolveDataType(program, optString(member, "type", "datatype"), true);
				int memberLength = optInt(member, "length", Math.max(memberType.getLength(), 1));
				structure.add(memberType, memberLength, optString(member, "name"),
					optString(member, "comment"));
			}
		}
		if (members != null && dataType instanceof Enum) {
			Enum enumType = (Enum) dataType;
			for (String name : enumType.getNames()) {
				enumType.remove(name);
			}
			for (JsonElement element : members) {
				JsonObject member = element.getAsJsonObject();
				String name = optString(member, "name");
				long value = member.get("value").getAsLong();
				String comment = optString(member, "comment");
				if (comment.isEmpty()) {
					enumType.add(name, value);
				}
				else {
					enumType.add(name, value, comment);
				}
			}
		}
	}

	private JsonObject readJsonObject(File path) throws IOException {
		try (Reader reader =
			new InputStreamReader(new FileInputStream(path), StandardCharsets.UTF_8)) {
			JsonElement element = JsonParser.parseReader(reader);
			if (!element.isJsonObject()) {
				throw new IOException("expected JSON object in " + path);
			}
			return element.getAsJsonObject();
		}
	}

	private void writeJson(File path, JsonObject payload) throws IOException {
		File parent = path.getParentFile();
		if (parent != null && !parent.exists() && !parent.mkdirs()) {
			throw new IOException("failed to create " + parent);
		}
		File tempFile = File.createTempFile(path.getName(), ".tmp", parent);
		try (Writer writer =
			new OutputStreamWriter(new FileOutputStream(tempFile), StandardCharsets.UTF_8)) {
			GSON.toJson(payload, writer);
		}
		try {
			Files.move(tempFile.toPath(), path.toPath(), StandardCopyOption.REPLACE_EXISTING,
				StandardCopyOption.ATOMIC_MOVE);
		}
		catch (AtomicMoveNotSupportedException e) {
			Files.move(tempFile.toPath(), path.toPath(), StandardCopyOption.REPLACE_EXISTING);
		}
	}

	private Address parseAddress(Program program, String text) throws BridgeException {
		Address address = tryParseAddress(program, text);
		if (address == null) {
			throw new BridgeException(404, "unable to resolve address: " + text);
		}
		return address;
	}

	private Address tryParseAddress(Program program, String text) {
		if (text == null || text.isEmpty()) {
			return null;
		}
		Address[] parsed = program.parseAddress(text);
		if (parsed != null && parsed.length > 0) {
			return parsed[0];
		}
		try {
			return new FlatProgramAPI(program, TaskMonitor.DUMMY).toAddr(text);
		}
		catch (Exception ignored) {
			return null;
		}
	}

	private String programPath(Program program) {
		if (program == null || program.getDomainFile() == null) {
			return "";
		}
		return program.getDomainFile().getPathname();
	}

	private String variableKind(Variable variable) {
		if (variable == null) {
			return "";
		}
		if (variable instanceof Parameter) {
			Parameter parameter = (Parameter) variable;
			if (parameter.getOrdinal() < 0 || variable.getName().equals("RETURN")) {
				return "return";
			}
			return "parameter";
		}
		return "local";
	}

	private String pathName(DataType dataType) {
		return dataType == null ? "" : dataType.getPathName();
	}

	private String empty(String value) {
		return value == null ? "" : value;
	}

	private String defaultCategory(String categoryPath) {
		return categoryPath == null || categoryPath.isEmpty() ? "/" : categoryPath;
	}

	private String toHex(byte[] bytes) {
		if (bytes == null) {
			return "";
		}
		StringBuilder builder = new StringBuilder(bytes.length * 2);
		for (byte value : bytes) {
			builder.append(String.format("%02x", value));
		}
		return builder.toString();
	}

	private byte[] parseHexBytes(String text) {
		String normalized = text.replace("0x", "").replaceAll("[^0-9A-Fa-f]", "");
		if (normalized.isEmpty()) {
			return new byte[0];
		}
		if ((normalized.length() % 2) != 0) {
			normalized = "0" + normalized;
		}
		byte[] output = new byte[normalized.length() / 2];
		for (int i = 0; i < output.length; i++) {
			int offset = i * 2;
			output[i] = (byte) Integer.parseInt(normalized.substring(offset, offset + 2), 16);
		}
		return output;
	}

	private String slug(String value) {
		return value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-");
	}

	private String optString(JsonObject object, String... keys) {
		for (String key : keys) {
			if (object.has(key) && object.get(key).isJsonPrimitive()) {
				return object.get(key).getAsString();
			}
		}
		return "";
	}

	private int optInt(JsonObject object, String key, int defaultValue) {
		if (!object.has(key)) {
			return defaultValue;
		}
		try {
			return object.get(key).getAsInt();
		}
		catch (Exception ignored) {
			return defaultValue;
		}
	}

	private boolean optBoolean(JsonObject object, String key, boolean defaultValue) {
		if (!object.has(key)) {
			return defaultValue;
		}
		try {
			return object.get(key).getAsBoolean();
		}
		catch (Exception ignored) {
			return defaultValue;
		}
	}

	private JsonObject optObject(JsonObject object, String key) {
		if (!object.has(key) || !object.get(key).isJsonObject()) {
			return null;
		}
		return object.getAsJsonObject(key);
	}

	private JsonArray optArray(JsonObject object, String... keys) {
		for (String key : keys) {
			if (object.has(key) && object.get(key).isJsonArray()) {
				return object.getAsJsonArray(key);
			}
		}
		return null;
	}

	private boolean hasAny(JsonObject object, String... keys) {
		for (String key : keys) {
			if (object.has(key)) {
				return true;
			}
		}
		return false;
	}

	@FunctionalInterface
	private interface MutationAction {
		MutationResult apply(Program program, FlatProgramAPI flat) throws Exception;
	}

	private static class MutationResult {
		JsonObject before = new JsonObject();
		JsonObject result = new JsonObject();
		JsonArray targets = new JsonArray();
		JsonObject inverse = new JsonObject();
	}

	static class RepositoryState {
		boolean hasProgram;
		boolean versioned;
		boolean readOnly;
		boolean checkedOut;
		boolean exclusiveCheckout;
		boolean modifiedSinceCheckout;
		boolean writableProject;
		boolean canSave;
		boolean changed;
		String programName = "";
		String projectName = "";
		String projectLocation = "";
		String projectMarkerPath = "";
		String domainPath = "";
	}

	private static class FunctionSearchHit {
		final Function function;
		final String matchField;
		final String matchValue;
		final String matchKind;
		final int rank;

		FunctionSearchHit(Function function, String matchField, String matchValue,
				String matchKind, int rank) {
			this.function = function;
			this.matchField = matchField;
			this.matchValue = matchValue;
			this.matchKind = matchKind;
			this.rank = rank;
		}
	}

	private static class BridgeException extends Exception {
		final int statusCode;

		BridgeException(int statusCode, String message) {
			super(message);
			this.statusCode = statusCode;
		}
	}
}
