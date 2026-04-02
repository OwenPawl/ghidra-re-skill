/* ###
 * IP: GHIDRA
 */
//@category Export

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.DefinedStringIterator;

public class ExportAppleBundle extends GhidraScript {

	private static final Pattern OBJC_METHOD_PATTERN = Pattern.compile("^([+-])\\[(.+?) (.+)\\]$");
	private static final Pattern SWIFT_TYPE_PATTERN = Pattern.compile(
		"(?:type metadata accessor for |nominal type descriptor for |type metadata for )(.+)$");
	private static final Pattern SWIFT_PROTOCOL_PATTERN = Pattern.compile(
		"(?:protocol conformance descriptor for |protocol witness for )(.+)$");

	private final Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

	@Override
	protected void run() throws Exception {
		Map<String, String> args = parseArgs();
		String outdirValue = requireArg(args, "outdir");
		File outdir = new File(outdirValue);
		if (!outdir.exists() && !outdir.mkdirs()) {
			throw new IOException("failed to create output directory: " + outdir);
		}

		writeJson(new File(outdir, "program_summary.json"), buildProgramSummary());
		writeJson(new File(outdir, "objc_metadata.json"), buildObjcMetadata());
		writeJson(new File(outdir, "swift_metadata.json"), buildSwiftMetadata());
		writeJson(new File(outdir, "function_inventory.json"), buildFunctionInventory());
		writeJson(new File(outdir, "symbols.json"), buildSymbols());
		writeJson(new File(outdir, "strings.json"), buildStrings(16));
		println("Wrote export bundle to " + outdir.getAbsolutePath());
	}

	private Map<String, String> parseArgs() {
		Map<String, String> args = new LinkedHashMap<>();
		for (String arg : getScriptArgs()) {
			int index = arg.indexOf('=');
			if (index > 0) {
				args.put(arg.substring(0, index).trim().toLowerCase().replace('-', '_'),
					arg.substring(index + 1));
			}
		}
		return args;
	}

	private String requireArg(Map<String, String> args, String key) {
		String value = args.get(key);
		if (value == null || value.isEmpty()) {
			throw new IllegalArgumentException("missing required argument: " + key + "=...");
		}
		return value;
	}

	private void writeJson(File file, JsonElement payload) throws IOException {
		File parent = file.getParentFile();
		if (parent != null && !parent.exists() && !parent.mkdirs()) {
			throw new IOException("failed to create directory " + parent);
		}
		try (Writer writer =
			new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8)) {
			gson.toJson(payload, writer);
		}
	}

	private JsonObject baseProgramMetadata() {
		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("executable_format", currentProgram.getExecutableFormat());
		payload.addProperty("language_id", String.valueOf(currentProgram.getLanguageID()));
		payload.addProperty("compiler_spec_id",
			String.valueOf(currentProgram.getCompilerSpec().getCompilerSpecID()));
		payload.addProperty("processor",
			String.valueOf(currentProgram.getLanguage().getProcessor()));
		payload.addProperty("pointer_size", currentProgram.getDefaultPointerSize());
		payload.addProperty("image_base", String.valueOf(currentProgram.getImageBase()));
		payload.addProperty("min_address", String.valueOf(currentProgram.getMinAddress()));
		payload.addProperty("max_address", String.valueOf(currentProgram.getMaxAddress()));
		payload.addProperty("executable_md5", empty(currentProgram.getExecutableMD5()));

		String executablePath = empty(currentProgram.getExecutablePath());
		payload.addProperty("executable_path", executablePath);
		payload.addProperty("source_image_path", inferSourceImagePath(executablePath));
		payload.addProperty("binary_sha256", sha256ForPath(executablePath));
		payload.addProperty("binary_size", fileSizeForPath(executablePath));
		payload.addProperty("binary_identity",
			currentProgram.getName() + "|" + currentProgram.getExecutableFormat() + "|" +
				empty(currentProgram.getExecutableMD5()) + "|" + sha256ForPath(executablePath));

		DomainFile domainFile = currentProgram.getDomainFile();
		payload.addProperty("program_path", domainFile == null ? "" : empty(domainFile.getPathname()));

		JsonObject metadata = new JsonObject();
		if (domainFile != null && domainFile.getMetadata() != null) {
			for (Map.Entry<String, String> entry : domainFile.getMetadata().entrySet()) {
				metadata.addProperty(entry.getKey(), entry.getValue());
			}
		}
		payload.add("metadata", metadata);

		JsonArray blocks = new JsonArray();
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			JsonObject blockJson = new JsonObject();
			blockJson.addProperty("name", block.getName());
			blockJson.addProperty("start", String.valueOf(block.getStart()));
			blockJson.addProperty("end", String.valueOf(block.getEnd()));
			blockJson.addProperty("size", block.getSize());
			blockJson.addProperty("read", block.isRead());
			blockJson.addProperty("write", block.isWrite());
			blockJson.addProperty("execute", block.isExecute());
			blockJson.addProperty("volatile", block.isVolatile());
			blockJson.addProperty("initialized", block.isInitialized());
			blockJson.addProperty("source_name", empty(block.getSourceName()));
			blocks.add(blockJson);
		}
		payload.add("memory_blocks", blocks);
		return payload;
	}

	private JsonObject buildProgramSummary() {
		JsonObject payload = baseProgramMetadata();
		int functionCount = currentProgram.getFunctionManager().getFunctionCount();
		int functionInventoryCount = countProgramFunctions();
		payload.addProperty("function_count", functionCount);
		payload.addProperty("function_inventory_count", functionInventoryCount);
		if (functionCount >= functionInventoryCount) {
			payload.addProperty("non_inventory_function_count",
				functionCount - functionInventoryCount);
		}
		int symbolCount = 0;
		int externalSymbolCount = 0;
		for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true); iterator
				.hasNext();) {
			Symbol symbol = iterator.next();
			symbolCount++;
			if (symbol.isExternal()) {
				externalSymbolCount++;
			}
		}
		payload.addProperty("symbol_count", symbolCount);
		payload.addProperty("external_symbol_count", externalSymbolCount);
		return payload;
	}

	private JsonObject buildObjcMetadata() {
		Set<String> classes = new TreeSet<>();
		Set<String> metaclasses = new TreeSet<>();
		Set<String> protocols = new TreeSet<>();
		Set<String> categories = new TreeSet<>();
		Set<String> selectors = new TreeSet<>();
		Set<String> objcSections = new TreeSet<>();
		Set<String> ivars = new TreeSet<>();
		JsonArray methods = new JsonArray();
		JsonArray selectorRefs = new JsonArray();
		JsonArray classRefs = new JsonArray();
		JsonArray protocolRefs = new JsonArray();
		JsonArray classNames = new JsonArray();
		JsonArray selectorStrings = new JsonArray();
		Set<String> seenMethods = new LinkedHashSet<>();
		Set<String> seenRefAddresses = new LinkedHashSet<>();

		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (block.getName() != null && block.getName().toLowerCase(Locale.ROOT).contains("objc")) {
				objcSections.add(block.getName());
			}
		}

		for (FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true); iterator
				.hasNext();) {
			Function function = iterator.next();
			addObjcMethod(methods, seenMethods, function.getName(),
				String.valueOf(function.getEntryPoint()), "function", classes, selectors);
		}

		for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true); iterator
				.hasNext();) {
			Symbol symbol = iterator.next();
			String name = symbol.getName();
			String lower = name.toLowerCase(Locale.ROOT);
			if (name.startsWith("_OBJC_CLASS_$_")) {
				classes.add(name.substring("_OBJC_CLASS_$_".length()));
			}
			if (name.startsWith("_OBJC_METACLASS_$_")) {
				metaclasses.add(name.substring("_OBJC_METACLASS_$_".length()));
			}
			if (name.startsWith("_OBJC_PROTOCOL_$_")) {
				protocols.add(name.substring("_OBJC_PROTOCOL_$_".length()));
			}
			if (name.startsWith("_OBJC_CATEGORY_$_")) {
				categories.add(name.substring("_OBJC_CATEGORY_$_".length()));
			}
			if (name.startsWith("selRef_")) {
				selectors.add(name.substring("selRef_".length()));
				addAddressRef(selectorRefs, seenRefAddresses, symbol.getAddress(), name, "symbol");
			}
			if (lower.contains("classref")) {
				addAddressRef(classRefs, seenRefAddresses, symbol.getAddress(), name, "symbol");
			}
			if (lower.contains("protocol")) {
				addAddressRef(protocolRefs, seenRefAddresses, symbol.getAddress(), name, "symbol");
			}
			if (lower.contains("ivar")) {
				ivars.add(name);
			}
			addObjcMethod(methods, seenMethods, name, String.valueOf(symbol.getAddress()), "symbol",
				classes, selectors);
		}

		DefinedStringIterator strings = DefinedStringIterator.forProgram(currentProgram, currentSelection);
		for (Data data : strings) {
			if (monitor.isCancelled()) {
				break;
			}
			StringDataInstance stringData = StringDataInstance.getStringDataInstance(data);
			String value = stringData == null ? "" : empty(stringData.getStringValue());
			if (value.isEmpty()) {
				continue;
			}
			MemoryBlock block = currentProgram.getMemory().getBlock(data.getAddress());
			String blockName = block == null ? "" : empty(block.getName()).toLowerCase(Locale.ROOT);
			if (blockName.contains("objc_methname")) {
				selectors.add(value);
				addStringArtifact(selectorStrings, data.getAddress(), value, blockName, "data");
			}
			if (blockName.contains("objc_classname")) {
				classes.add(value);
				addStringArtifact(classNames, data.getAddress(), value, blockName, "data");
			}
			if (blockName.contains("classref")) {
				addAddressRef(classRefs, seenRefAddresses, data.getAddress(), value, "data");
			}
			if (blockName.contains("selref")) {
				addAddressRef(selectorRefs, seenRefAddresses, data.getAddress(), value, "data");
			}
			if (blockName.contains("protocol")) {
				addAddressRef(protocolRefs, seenRefAddresses, data.getAddress(), value, "data");
			}
			if (blockName.contains("ivar")) {
				ivars.add(value);
			}
		}

		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.add("objc_sections", toJsonArray(objcSections));
		payload.add("classes", toJsonArray(classes));
		payload.add("metaclasses", toJsonArray(metaclasses));
		payload.add("protocols", toJsonArray(protocols));
		payload.add("categories", toJsonArray(categories));
		payload.add("selectors", toJsonArray(selectors));
		payload.add("ivars", toJsonArray(ivars));
		payload.add("methods", methods);
		payload.add("class_refs", classRefs);
		payload.add("selector_refs", selectorRefs);
		payload.add("protocol_refs", protocolRefs);
		payload.add("class_names", classNames);
		payload.add("selector_strings", selectorStrings);
		return payload;
	}

	private JsonObject buildSwiftMetadata() {
		Set<String> types = new TreeSet<>();
		Set<String> protocolConformances = new TreeSet<>();
		Set<String> metadataAccessors = new TreeSet<>();
		Set<String> asyncEntrypoints = new TreeSet<>();
		JsonArray symbols = new JsonArray();
		Set<String> seen = new LinkedHashSet<>();

		for (FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true); iterator
				.hasNext();) {
			Function function = iterator.next();
			String name = function.getName();
			if (!isSwiftSymbol(name)) {
				continue;
			}
			if (!seen.add("function|" + name + "|" + function.getEntryPoint())) {
				continue;
			}
			symbols.add(swiftSymbolToJson(name, String.valueOf(function.getEntryPoint()), "function"));
			classifySwiftName(name, types, protocolConformances, metadataAccessors, asyncEntrypoints);
		}

		for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true); iterator
				.hasNext();) {
			Symbol symbol = iterator.next();
			String name = symbol.getName();
			if (!isSwiftSymbol(name)) {
				continue;
			}
			if (!seen.add("symbol|" + name + "|" + symbol.getAddress())) {
				continue;
			}
			symbols.add(swiftSymbolToJson(name, String.valueOf(symbol.getAddress()), "symbol"));
			classifySwiftName(name, types, protocolConformances, metadataAccessors, asyncEntrypoints);
		}

		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.add("symbols", symbols);
		payload.add("types", toJsonArray(types));
		payload.add("protocol_conformances", toJsonArray(protocolConformances));
		payload.add("metadata_accessors", toJsonArray(metadataAccessors));
		payload.add("async_entrypoints", toJsonArray(asyncEntrypoints));
		payload.addProperty("symbol_count", symbols.size());
		return payload;
	}

	private JsonObject buildFunctionInventory() {
		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("scope", "program_functions");
		payload.addProperty("includes_external_functions", false);
		JsonArray functions = new JsonArray();
		for (FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true); iterator
				.hasNext();) {
			if (monitor.isCancelled()) {
				break;
			}
			functions.add(functionToJson(iterator.next()));
		}
		payload.addProperty("function_count", functions.size());
		payload.add("functions", functions);
		return payload;
	}

	private JsonObject functionToJson(Function function) {
		JsonObject object = new JsonObject();
		object.addProperty("name", function.getName());
		object.addProperty("entry", String.valueOf(function.getEntryPoint()));
		object.addProperty("namespace", namespacePath(function.getParentNamespace()));
		object.addProperty("signature", function.getPrototypeString(false, false));
		object.addProperty("return_type", String.valueOf(function.getReturnType()));
		object.addProperty("calling_convention", function.getCallingConventionName());
		object.addProperty("is_thunk", function.isThunk());
		object.addProperty("is_external", function.isExternal());
		object.addProperty("is_inline", function.isInline());
		object.addProperty("has_var_args", function.hasVarArgs());
		object.addProperty("no_return", function.hasNoReturn());
		object.addProperty("body_size", function.getBody().getNumAddresses());
		object.addProperty("caller_count", function.getCallingFunctions(monitor).size());
		object.addProperty("callee_count", function.getCalledFunctions(monitor).size());
		object.addProperty("artifact_type", classifyFunctionArtifact(function));
		MemoryBlock block = currentProgram.getMemory().getBlock(function.getEntryPoint());
		object.addProperty("block", block == null ? "" : empty(block.getName()));
		JsonObject refs = sampleReferences(function.getEntryPoint(), 8);
		object.addProperty("xref_count", refs.get("count").getAsInt());
		object.add("sample_xrefs", refs.getAsJsonArray("items"));
		JsonArray params = new JsonArray();
		for (Parameter parameter : function.getParameters()) {
			JsonObject param = new JsonObject();
			param.addProperty("name", parameter.getName());
			param.addProperty("data_type", String.valueOf(parameter.getDataType()));
			param.addProperty("storage", String.valueOf(parameter.getVariableStorage()));
			param.addProperty("source", String.valueOf(parameter.getSource()));
			params.add(param);
		}
		object.addProperty("parameter_count", params.size());
		object.add("parameters", params);
		Matcher matcher = OBJC_METHOD_PATTERN.matcher(function.getName());
		if (matcher.matches()) {
			JsonObject objcMethod = new JsonObject();
			objcMethod.addProperty("kind", "+".equals(matcher.group(1)) ? "class" : "instance");
			objcMethod.addProperty("class_name", matcher.group(2));
			objcMethod.addProperty("selector", matcher.group(3));
			object.add("objc_method", objcMethod);
		}
		if (isSwiftSymbol(function.getName())) {
			object.addProperty("swift_symbol", true);
		}
		return object;
	}

	private JsonObject buildSymbols() {
		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		JsonArray symbols = new JsonArray();
		JsonArray imports = new JsonArray();
		JsonArray exports = new JsonArray();
		JsonArray objcRelated = new JsonArray();
		JsonArray swiftRelated = new JsonArray();

		for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true); iterator
				.hasNext();) {
			if (monitor.isCancelled()) {
				break;
			}
			Symbol symbol = iterator.next();
			boolean keep = symbol.isExternal() || symbol.isExternalEntryPoint()
				|| !"DEFAULT".equals(String.valueOf(symbol.getSource()));
			JsonObject symbolJson = symbolToJson(symbol, 12);
			if (keep) {
				symbols.add(symbolJson);
			}
			if (symbol.isExternal()) {
				imports.add(symbolJson);
			}
			if (symbol.isExternalEntryPoint() && !symbol.isExternal()) {
				exports.add(symbolJson);
			}
			String artifactType = symbolJson.get("artifact_type").getAsString();
			if (artifactType.startsWith("objc_")) {
				objcRelated.add(symbolJson);
			}
			if ("swift_symbol".equals(artifactType)) {
				swiftRelated.add(symbolJson);
			}
		}

		payload.addProperty("symbol_count", symbols.size());
		payload.addProperty("import_count", imports.size());
		payload.addProperty("export_count", exports.size());
		payload.add("symbols", symbols);
		payload.add("imports", imports);
		payload.add("exports", exports);
		payload.add("objc_related", objcRelated);
		payload.add("swift_related", swiftRelated);
		return payload;
	}

	private JsonObject symbolToJson(Symbol symbol, int xrefLimit) {
		JsonObject object = new JsonObject();
		object.addProperty("name", symbol.getName());
		object.addProperty("address", String.valueOf(symbol.getAddress()));
		object.addProperty("symbol_type", String.valueOf(symbol.getSymbolType()));
		object.addProperty("namespace", namespacePath(symbol.getParentNamespace()));
		object.addProperty("source", String.valueOf(symbol.getSource()));
		object.addProperty("external", symbol.isExternal());
		object.addProperty("external_entry_point", symbol.isExternalEntryPoint());
		object.addProperty("primary", symbol.isPrimary());
		object.addProperty("artifact_type", classifySymbolArtifact(symbol));
		JsonObject refs = sampleReferences(symbol.getAddress(), xrefLimit);
		object.addProperty("xref_count", refs.get("count").getAsInt());
		object.add("sample_xrefs", refs.getAsJsonArray("items"));
		Matcher matcher = OBJC_METHOD_PATTERN.matcher(symbol.getName());
		if (matcher.matches()) {
			JsonObject objcMethod = new JsonObject();
			objcMethod.addProperty("kind", "+".equals(matcher.group(1)) ? "class" : "instance");
			objcMethod.addProperty("class_name", matcher.group(2));
			objcMethod.addProperty("selector", matcher.group(3));
			object.add("objc_method", objcMethod);
		}
		return object;
	}

	private JsonObject buildStrings(int xrefLimit) {
		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("xref_sample_limit", xrefLimit);
		JsonArray strings = new JsonArray();
		DefinedStringIterator iterator = DefinedStringIterator.forProgram(currentProgram, currentSelection);
		for (Data data : iterator) {
			if (monitor.isCancelled()) {
				break;
			}
			StringDataInstance stringData = StringDataInstance.getStringDataInstance(data);
			String value = stringData == null ? null : stringData.getStringValue();
			if (value == null) {
				continue;
			}
			strings.add(stringToJson(data, value, xrefLimit));
		}
		payload.addProperty("string_count", strings.size());
		payload.add("strings", strings);
		return payload;
	}

	private JsonObject stringToJson(Data data, String value, int xrefLimit) {
		JsonObject stringJson = new JsonObject();
		stringJson.addProperty("address", String.valueOf(data.getAddress()));
		stringJson.addProperty("length", value.length());
		stringJson.addProperty("value", value);
		MemoryBlock block = currentProgram.getMemory().getBlock(data.getAddress());
		String blockName = block == null ? "" : empty(block.getName());
		stringJson.addProperty("block", blockName);
		stringJson.addProperty("data_type", String.valueOf(data.getDataType()));
		stringJson.addProperty("artifact_type", classifyStringArtifact(blockName, value));
		stringJson.addProperty("metadata_group", classifyMetadataGroup(blockName, value));
		JsonObject refs = sampleReferences(data.getAddress(), xrefLimit);
		stringJson.addProperty("xref_count", refs.get("count").getAsInt());
		stringJson.add("xrefs", refs.getAsJsonArray("items"));
		return stringJson;
	}

	private JsonObject sampleReferences(Address address, int limit) {
		JsonObject payload = new JsonObject();
		JsonArray refs = new JsonArray();
		int count = 0;
		ReferenceIterator iterator = currentProgram.getReferenceManager().getReferencesTo(address);
		while (iterator.hasNext()) {
			Reference ref = iterator.next();
			count++;
			if (refs.size() >= limit) {
				continue;
			}
			JsonObject refJson = new JsonObject();
			refJson.addProperty("from_address", String.valueOf(ref.getFromAddress()));
			refJson.addProperty("to_address", String.valueOf(ref.getToAddress()));
			Function function = getFunctionContaining(ref.getFromAddress());
			refJson.addProperty("from_function", function == null ? null : function.getName());
			refJson.addProperty("ref_type", String.valueOf(ref.getReferenceType()));
			refJson.addProperty("operand_index", ref.getOperandIndex());
			refJson.addProperty("is_primary", ref.isPrimary());
			refs.add(refJson);
		}
		payload.addProperty("count", count);
		payload.add("items", refs);
		return payload;
	}

	private void addObjcMethod(JsonArray methods, Set<String> seenMethods, String name,
			String address, String source, Set<String> classes, Set<String> selectors) {
		Matcher matcher = OBJC_METHOD_PATTERN.matcher(name);
		if (!matcher.matches()) {
			return;
		}
		String key = name + "|" + address;
		if (!seenMethods.add(key)) {
			return;
		}
		JsonObject method = new JsonObject();
		method.addProperty("name", name);
		method.addProperty("address", address);
		method.addProperty("kind", "+".equals(matcher.group(1)) ? "class" : "instance");
		method.addProperty("class_name", matcher.group(2));
		method.addProperty("selector", matcher.group(3));
		method.addProperty("source", source);
		methods.add(method);
		classes.add(matcher.group(2));
		selectors.add(matcher.group(3));
	}

	private void addAddressRef(JsonArray array, Set<String> seen, Address address, String name,
			String source) {
		String key = String.valueOf(address) + "|" + name;
		if (!seen.add(key)) {
			return;
		}
		JsonObject object = new JsonObject();
		object.addProperty("address", String.valueOf(address));
		object.addProperty("name", name);
		object.addProperty("source", source);
		array.add(object);
	}

	private void addStringArtifact(JsonArray array, Address address, String value, String blockName,
			String source) {
		JsonObject object = new JsonObject();
		object.addProperty("address", String.valueOf(address));
		object.addProperty("value", value);
		object.addProperty("block", blockName);
		object.addProperty("source", source);
		array.add(object);
	}

	private JsonObject swiftSymbolToJson(String name, String address, String source) {
		JsonObject object = new JsonObject();
		object.addProperty("name", name);
		object.addProperty("address", address);
		object.addProperty("source", source);
		object.addProperty("mangled", name.startsWith("$s") || name.startsWith("_$s"));
		object.addProperty("async_like", isSwiftAsyncLike(name));
		object.addProperty("metadata_accessor", isSwiftMetadataAccessor(name));
		object.addProperty("protocol_conformance_like", isSwiftProtocolConformanceLike(name));
		return object;
	}

	private void classifySwiftName(String name, Set<String> types,
			Set<String> protocolConformances, Set<String> metadataAccessors,
			Set<String> asyncEntrypoints) {
		Matcher typeMatcher = SWIFT_TYPE_PATTERN.matcher(name);
		if (typeMatcher.find()) {
			String typeName = typeMatcher.group(1).trim();
			if (!typeName.isEmpty()) {
				types.add(typeName);
				metadataAccessors.add(name);
			}
		}
		Matcher protocolMatcher = SWIFT_PROTOCOL_PATTERN.matcher(name);
		if (protocolMatcher.find()) {
			String value = protocolMatcher.group(1).trim();
			if (!value.isEmpty()) {
				protocolConformances.add(value);
			}
		}
		if (isSwiftMetadataAccessor(name)) {
			metadataAccessors.add(name);
		}
		if (isSwiftAsyncLike(name)) {
			asyncEntrypoints.add(name);
		}
	}

	private boolean isSwiftSymbol(String name) {
		String lower = name.toLowerCase(Locale.ROOT);
		return name.startsWith("$s") || name.startsWith("_$s") || lower.contains("swift") ||
			lower.contains("type metadata") || lower.contains("protocol conformance");
	}

	private boolean isSwiftMetadataAccessor(String name) {
		String lower = name.toLowerCase(Locale.ROOT);
		return lower.contains("type metadata accessor") || lower.contains("nominal type descriptor") ||
			name.endsWith("CMa") || name.endsWith("Mn");
	}

	private boolean isSwiftProtocolConformanceLike(String name) {
		String lower = name.toLowerCase(Locale.ROOT);
		return lower.contains("protocol conformance") || lower.contains("protocol witness");
	}

	private boolean isSwiftAsyncLike(String name) {
		String lower = name.toLowerCase(Locale.ROOT);
		return lower.contains("async") || lower.contains("resume partial function") ||
			lower.contains("suspend resume");
	}

	private String classifyFunctionArtifact(Function function) {
		String name = function.getName();
		if (OBJC_METHOD_PATTERN.matcher(name).matches()) {
			return "objc_method";
		}
		if (isSwiftSymbol(name)) {
			return "swift_function";
		}
		if (name.startsWith("_OUTLINED_FUNCTION_")) {
			return "outlined_function";
		}
		return "function";
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
		if (isSwiftSymbol(name)) {
			return "swift_symbol";
		}
		return "symbol";
	}

	private String classifyStringArtifact(String blockName, String value) {
		String lower = blockName == null ? "" : blockName.toLowerCase(Locale.ROOT);
		if (lower.contains("objc_methname")) {
			return "objc_selector";
		}
		if (lower.contains("objc_classname")) {
			return "objc_classname";
		}
		if (lower.contains("cfstring")) {
			return "cfstring";
		}
		if (lower.contains("classref")) {
			return "objc_classref";
		}
		if (lower.contains("selref")) {
			return "objc_selref";
		}
		if (lower.contains("ivar")) {
			return "objc_ivar";
		}
		if (value.startsWith("com.apple.") || value.startsWith("is.workflow.")) {
			return "service_string";
		}
		return "string";
	}

	private String classifyMetadataGroup(String blockName, String value) {
		String lower = blockName == null ? "" : blockName.toLowerCase(Locale.ROOT);
		if (lower.contains("objc")) {
			return "objc_runtime";
		}
		if (lower.contains("cfstring")) {
			return "corefoundation";
		}
		if (lower.contains("plist") || value.startsWith("<?xml") || value.startsWith("{") ||
			value.startsWith("<plist")) {
			return "plist_like";
		}
		if (isSwiftSymbol(value)) {
			return "swift_runtime";
		}
		return "generic";
	}

	private JsonArray toJsonArray(Set<String> values) {
		JsonArray array = new JsonArray();
		for (String value : values) {
			array.add(value);
		}
		return array;
	}

	private int countProgramFunctions() {
		int count = 0;
		for (FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true); iterator
				.hasNext();) {
			iterator.next();
			count++;
		}
		return count;
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

	private String empty(String value) {
		return value == null ? "" : value;
	}

	private String inferSourceImagePath(String executablePath) {
		if (executablePath == null || executablePath.isEmpty()) {
			return "";
		}
		if (executablePath.contains("/System/iOSSupport/")) {
			return executablePath.substring(executablePath.indexOf("/System/iOSSupport/") + 8);
		}
		int systemIndex = executablePath.indexOf("/System/");
		if (systemIndex >= 0) {
			return executablePath.substring(systemIndex);
		}
		return executablePath;
	}

	private long fileSizeForPath(String pathValue) {
		if (pathValue == null || pathValue.isEmpty()) {
			return 0L;
		}
		try {
			return Files.size(new File(pathValue).toPath());
		}
		catch (Exception ignored) {
			return 0L;
		}
	}

	private String sha256ForPath(String pathValue) {
		if (pathValue == null || pathValue.isEmpty()) {
			return "";
		}
		File file = new File(pathValue);
		if (!file.isFile()) {
			return "";
		}
		try (FileInputStream input = new FileInputStream(file)) {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] buffer = new byte[8192];
			int read;
			while ((read = input.read(buffer)) >= 0) {
				if (read == 0) {
					continue;
				}
				digest.update(buffer, 0, read);
			}
			StringBuilder builder = new StringBuilder();
			for (byte value : digest.digest()) {
				builder.append(String.format("%02x", value));
			}
			return builder.toString();
		}
		catch (Exception ignored) {
			return "";
		}
	}
}
