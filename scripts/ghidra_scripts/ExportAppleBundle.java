/* ###
 * IP: GHIDRA
 */
//@category Export

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
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
		writeJson(new File(outdir, "function_inventory.json"), buildFunctionInventory());
		writeJson(new File(outdir, "symbols.json"), buildSymbols());
		writeJson(new File(outdir, "strings.json"), buildStrings(10));
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
		payload.addProperty("image_base", String.valueOf(currentProgram.getImageBase()));
		payload.addProperty("min_address", String.valueOf(currentProgram.getMinAddress()));
		payload.addProperty("max_address", String.valueOf(currentProgram.getMaxAddress()));
		payload.addProperty("executable_md5", currentProgram.getExecutableMD5());

		JsonObject metadata = new JsonObject();
		if (currentProgram.getDomainFile() != null && currentProgram.getDomainFile().getMetadata() != null) {
			for (Map.Entry<String, String> entry : currentProgram.getDomainFile().getMetadata().entrySet()) {
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
			blockJson.addProperty("source_name", block.getSourceName());
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
		JsonArray methods = new JsonArray();

		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (block.getName() != null && block.getName().toLowerCase().contains("objc")) {
				objcSections.add(block.getName());
			}
		}

		for (FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true); iterator
				.hasNext();) {
			Function function = iterator.next();
			Matcher matcher = OBJC_METHOD_PATTERN.matcher(function.getName());
			if (!matcher.matches()) {
				continue;
			}
			JsonObject method = new JsonObject();
			method.addProperty("name", function.getName());
			method.addProperty("entry", String.valueOf(function.getEntryPoint()));
			method.addProperty("kind", "+".equals(matcher.group(1)) ? "class" : "instance");
			method.addProperty("class_name", matcher.group(2));
			method.addProperty("selector", matcher.group(3));
			methods.add(method);
			classes.add(matcher.group(2));
			selectors.add(matcher.group(3));
		}

		for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true); iterator
				.hasNext();) {
			Symbol symbol = iterator.next();
			String name = symbol.getName();
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
			}
		}

		DefinedStringIterator strings = DefinedStringIterator.forProgram(currentProgram, currentSelection);
		for (Data data : strings) {
			if (monitor.isCancelled()) {
				break;
			}
			StringDataInstance stringData = StringDataInstance.getStringDataInstance(data);
			String value = stringData.getStringValue();
			if (value == null) {
				continue;
			}
			MemoryBlock block = currentProgram.getMemory().getBlock(data.getAddress());
			String blockName = block == null ? "" : block.getName().toLowerCase();
			if (blockName.contains("objc_methname")) {
				selectors.add(value);
			}
			if (blockName.contains("objc_classname")) {
				classes.add(value);
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
		payload.add("methods", methods);
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
		JsonObject refs = sampleReferences(function.getEntryPoint(), 5);
		object.addProperty("xref_count", refs.get("count").getAsInt());
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
		return object;
	}

	private JsonObject buildSymbols() {
		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		JsonArray symbols = new JsonArray();
		JsonArray imports = new JsonArray();
		JsonArray exports = new JsonArray();
		JsonArray objcRelated = new JsonArray();

		for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true); iterator
				.hasNext();) {
			if (monitor.isCancelled()) {
				break;
			}
			Symbol symbol = iterator.next();
			boolean keep = symbol.isExternal() || symbol.isExternalEntryPoint()
				|| !"DEFAULT".equals(String.valueOf(symbol.getSource()));
			JsonObject symbolJson = symbolToJson(symbol);
			if (keep) {
				symbols.add(symbolJson);
			}
			if (symbol.isExternal()) {
				imports.add(symbolJson);
			}
			if (symbol.isExternalEntryPoint() && !symbol.isExternal()) {
				exports.add(symbolJson);
			}
			String name = symbol.getName().toLowerCase();
			if (name.contains("objc") || symbol.getName().startsWith("-[")
				|| symbol.getName().startsWith("+[")) {
				objcRelated.add(symbolJson);
			}
		}

		payload.addProperty("symbol_count", symbols.size());
		payload.addProperty("import_count", imports.size());
		payload.addProperty("export_count", exports.size());
		payload.add("symbols", symbols);
		payload.add("imports", imports);
		payload.add("exports", exports);
		payload.add("objc_related", objcRelated);
		return payload;
	}

	private JsonObject symbolToJson(Symbol symbol) {
		JsonObject object = new JsonObject();
		object.addProperty("name", symbol.getName());
		object.addProperty("address", String.valueOf(symbol.getAddress()));
		object.addProperty("symbol_type", String.valueOf(symbol.getSymbolType()));
		object.addProperty("namespace", namespacePath(symbol.getParentNamespace()));
		object.addProperty("source", String.valueOf(symbol.getSource()));
		object.addProperty("external", symbol.isExternal());
		object.addProperty("external_entry_point", symbol.isExternalEntryPoint());
		object.addProperty("primary", symbol.isPrimary());
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
			String value = stringData.getStringValue();
			if (value == null) {
				continue;
			}
			JsonObject stringJson = new JsonObject();
			stringJson.addProperty("address", String.valueOf(data.getAddress()));
			stringJson.addProperty("length", value.length());
			stringJson.addProperty("value", value);
			MemoryBlock block = currentProgram.getMemory().getBlock(data.getAddress());
			stringJson.addProperty("block", block == null ? null : block.getName());
			stringJson.addProperty("data_type", String.valueOf(data.getDataType()));
			JsonObject refs = sampleReferences(data.getAddress(), xrefLimit);
			stringJson.addProperty("xref_count", refs.get("count").getAsInt());
			stringJson.add("xrefs", refs.getAsJsonArray("items"));
			strings.add(stringJson);
		}
		payload.addProperty("string_count", strings.size());
		payload.add("strings", strings);
		return payload;
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
}
