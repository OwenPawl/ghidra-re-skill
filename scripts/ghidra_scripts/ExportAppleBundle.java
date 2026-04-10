/* ###
 * IP: GHIDRA
 */
//@category Export

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
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
import ghidra.program.model.listing.Instruction;
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
	private static final String[] SWIFT_METADATA_SECTION_NAMES = {
		"__swift5_types",
		"__swift5_typeref",
		"__swift5_fieldmd",
		"__swift5_proto",
		"__swift5_reflstr",
		"__swift5_assocty"
	};

	private final Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
	private final Map<String, String> swiftDemangleCache = new HashMap<>();
	private String swiftDemangleTool = null;
	private boolean swiftDemangleToolResolved = false;

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
		Set<String> interfaceClasses = new TreeSet<>();
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
		JsonArray recoveredProtocols = new JsonArray();
		JsonArray classNames = new JsonArray();
		JsonArray selectorStrings = new JsonArray();
		Set<String> seenMethods = new LinkedHashSet<>();
		Set<String> seenRefAddresses = new LinkedHashSet<>();
		Set<String> seenRecoveredProtocols = new LinkedHashSet<>();

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
				String className = name.substring("_OBJC_CLASS_$_".length());
				classes.add(className);
				addLikelyObjcRuntimeName(interfaceClasses, className);
			}
			if (name.startsWith("_OBJC_METACLASS_$_")) {
				String metaclassName = name.substring("_OBJC_METACLASS_$_".length());
				metaclasses.add(metaclassName);
			}
			if (name.startsWith("_OBJC_PROTOCOL_$_")) {
				String protocolName = name.substring("_OBJC_PROTOCOL_$_".length());
				protocols.add(protocolName);
				addRecoveredProtocol(recoveredProtocols, seenRecoveredProtocols, protocols,
					name, String.valueOf(symbol.getAddress()), "explicit_symbol");
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
				addRecoveredProtocol(recoveredProtocols, seenRecoveredProtocols, protocols,
					name, String.valueOf(symbol.getAddress()), "symbol");
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
				addLikelyObjcRuntimeName(interfaceClasses, value);
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
				addRecoveredProtocol(recoveredProtocols, seenRecoveredProtocols, protocols,
					value, String.valueOf(data.getAddress()), "data");
			}
			if (blockName.contains("ivar")) {
				ivars.add(value);
			}
		}

		Set<String> cleanClasses = filterLikelyObjcRuntimeNames(classes);
		Set<String> cleanMetaclasses = filterLikelyObjcRuntimeNames(metaclasses);
		if (interfaceClasses.isEmpty()) {
			interfaceClasses.addAll(cleanClasses);
		}
		else {
			interfaceClasses.addAll(cleanClasses);
		}

		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.add("objc_sections", toJsonArray(objcSections));
		payload.add("classes", toJsonArray(cleanClasses));
		payload.add("interface_classes", toJsonArray(interfaceClasses));
		payload.addProperty("class_source_preference", "interface_classes");
		payload.add("metaclasses", toJsonArray(cleanMetaclasses));
		payload.add("protocols", toJsonArray(protocols));
		payload.add("recovered_protocols", recoveredProtocols);
		payload.addProperty("protocol_source_preference",
			recoveredProtocols.size() > 0 ? "protocols+recovered_protocols" : "protocols");
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
		Set<String> typeDescriptors = new TreeSet<>();
		Set<String> dispatchThunks = new TreeSet<>();
		Set<String> protocolWitnesses = new TreeSet<>();
		Set<String> outlinedHelpers = new TreeSet<>();
		JsonArray symbols = new JsonArray();
		JsonArray metadataMethods = new JsonArray();
		JsonArray protocolRequirements = new JsonArray();
		JsonArray associatedConformanceRecords = new JsonArray();
		JsonArray codeCandidates = new JsonArray();
		JsonArray asyncRelationships = new JsonArray();
		JsonObject aliasMap = new JsonObject();
		JsonArray aliases = new JsonArray();
		Set<String> seen = new LinkedHashSet<>();
		Set<String> seenMetadataMethodKeys = new LinkedHashSet<>();
		Set<String> seenProtocolRequirementKeys = new LinkedHashSet<>();
		Set<String> seenAssociatedConformanceKeys = new LinkedHashSet<>();
		Set<String> seenCodeCandidateKeys = new LinkedHashSet<>();
		List<JsonObject> swiftRecords = new ArrayList<>();

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
			JsonObject symbolJson = swiftFunctionToJson(function);
			symbols.add(symbolJson);
			swiftRecords.add(symbolJson);
			addSwiftAlias(aliasMap, aliases, symbolJson);
			classifySwiftJson(symbolJson, types, protocolConformances, metadataAccessors,
				asyncEntrypoints, typeDescriptors, dispatchThunks, protocolWitnesses,
				outlinedHelpers);
			if (shouldExposeAsMetadataMethod(symbolJson) &&
				seenMetadataMethodKeys.add(metadataMethodKey(symbolJson))) {
				metadataMethods.add(symbolJson.deepCopy());
			}
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
			JsonObject symbolJson = swiftSymbolToJson(name, String.valueOf(symbol.getAddress()), "symbol",
				null);
			symbols.add(symbolJson);
			swiftRecords.add(symbolJson);
			addSwiftAlias(aliasMap, aliases, symbolJson);
			classifySwiftJson(symbolJson, types, protocolConformances, metadataAccessors,
				asyncEntrypoints, typeDescriptors, dispatchThunks, protocolWitnesses,
				outlinedHelpers);
			if (shouldExposeAsMetadataMethod(symbolJson) &&
				seenMetadataMethodKeys.add(metadataMethodKey(symbolJson))) {
				metadataMethods.add(symbolJson.deepCopy());
			}
		}

		JsonObject sectionMetadata = buildSwiftMetadataSectionSummary();
		ingestSwiftSectionStrings(sectionMetadata, types, protocolConformances);
		collectSwiftMetadataArtifacts(types, metadataMethods, protocolRequirements,
			associatedConformanceRecords, codeCandidates, seenMetadataMethodKeys,
			seenProtocolRequirementKeys, seenAssociatedConformanceKeys, seenCodeCandidateKeys);
		asyncRelationships = buildSwiftAsyncRelationships(swiftRecords);

		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("demangle_tool", empty(resolveSwiftDemangleTool()));
		payload.add("symbols", symbols);
		payload.add("metadata_methods", metadataMethods);
		payload.add("protocol_requirements", protocolRequirements);
		payload.add("associated_conformances", associatedConformanceRecords);
		payload.add("code_candidates", codeCandidates);
		payload.add("async_relationships", asyncRelationships);
		payload.add("types", toJsonArray(types));
		payload.add("protocol_conformances", toJsonArray(protocolConformances));
		payload.add("metadata_accessors", toJsonArray(metadataAccessors));
		payload.add("async_entrypoints", toJsonArray(asyncEntrypoints));
		payload.add("type_descriptors", toJsonArray(typeDescriptors));
		payload.add("dispatch_thunks", toJsonArray(dispatchThunks));
		payload.add("protocol_witnesses", toJsonArray(protocolWitnesses));
		payload.add("outlined_helpers", toJsonArray(outlinedHelpers));
		payload.add("alias_map", aliasMap);
		payload.add("aliases", aliases);
		payload.add("metadata_sections", sectionMetadata);
		payload.addProperty("symbol_count", symbols.size());
		return payload;
	}

	private boolean shouldExposeAsMetadataMethod(JsonObject symbolJson) {
		String typeName = empty(symbolJson.get("type_name").getAsString());
		String memberName = empty(symbolJson.get("member_name").getAsString());
		String kind = empty(symbolJson.get("symbol_kind").getAsString());
		String displayName = empty(symbolJson.get("display_name").getAsString());
		if (typeName.isEmpty() || memberName.isEmpty()) {
			return false;
		}
		return looksLikeHighConfidenceSwiftMethod(displayName, memberName, kind);
	}

	private String metadataMethodKey(JsonObject symbolJson) {
		return empty(symbolJson.get("stable_alias").getAsString()) + "|" +
			empty(symbolJson.get("canonical_address").getAsString()) + "|" +
			empty(symbolJson.get("address").getAsString());
	}

	private void collectSwiftMetadataArtifacts(Set<String> knownTypes, JsonArray metadataMethods,
			JsonArray protocolRequirements, JsonArray associatedConformances,
			JsonArray codeCandidates, Set<String> seenMetadataMethodKeys,
			Set<String> seenProtocolRequirementKeys, Set<String> seenAssociatedConformanceKeys,
			Set<String> seenCodeCandidateKeys) {
		for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true); iterator
				.hasNext();) {
			Symbol symbol = iterator.next();
			ingestSwiftMetadataArtifact(symbol.getName(), symbol.getAddress(), "symbol", knownTypes,
				metadataMethods, protocolRequirements, associatedConformances, codeCandidates,
				seenMetadataMethodKeys, seenProtocolRequirementKeys, seenAssociatedConformanceKeys,
				seenCodeCandidateKeys);
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
			String blockName = block == null ? "" : empty(block.getName());
			if (!isSwiftMetadataArtifactValue(value, blockName)) {
				continue;
			}
			ingestSwiftMetadataArtifact(value, data.getAddress(), "string", knownTypes,
				metadataMethods, protocolRequirements, associatedConformances, codeCandidates,
				seenMetadataMethodKeys, seenProtocolRequirementKeys, seenAssociatedConformanceKeys,
				seenCodeCandidateKeys);
		}
	}

	private boolean isSwiftMetadataArtifactValue(String value, String blockName) {
		String lowerValue = empty(value).toLowerCase(Locale.ROOT);
		String lowerBlock = empty(blockName).toLowerCase(Locale.ROOT);
		if (lowerBlock.contains("swift5_typeref") || lowerBlock.contains("swift5_proto") ||
			lowerBlock.contains("swift5_assocty") || lowerBlock.contains("swift5_reflstr")) {
			return true;
		}
		return lowerValue.startsWith("_symbolic ") || lowerValue.startsWith("_symbolic_") ||
			lowerValue.startsWith("_associated conformance ") ||
			lowerValue.startsWith("_associated_conformance_");
	}

	private void ingestSwiftMetadataArtifact(String rawValue, Address sourceAddress, String source,
			Set<String> knownTypes, JsonArray metadataMethods, JsonArray protocolRequirements,
			JsonArray associatedConformances, JsonArray codeCandidates,
			Set<String> seenMetadataMethodKeys, Set<String> seenProtocolRequirementKeys,
			Set<String> seenAssociatedConformanceKeys, Set<String> seenCodeCandidateKeys) {
		if (rawValue == null || rawValue.isEmpty() || sourceAddress == null) {
			return;
		}
		JsonObject protocolRequirement = buildSwiftProtocolRequirementArtifact(rawValue,
			sourceAddress, source);
		if (protocolRequirement != null) {
			String key = empty(protocolRequirement.get("stable_alias").getAsString()) + "|" +
				empty(protocolRequirement.get("address").getAsString()) + "|" +
				empty(protocolRequirement.get("kind").getAsString());
			if (seenProtocolRequirementKeys.add(key)) {
				protocolRequirements.add(protocolRequirement);
			}
			addSwiftCodeCandidates(codeCandidates, seenCodeCandidateKeys,
				empty(protocolRequirement.get("type_name").getAsString()),
				empty(protocolRequirement.get("stable_alias").getAsString()),
				empty(protocolRequirement.get("kind").getAsString()), sourceAddress, rawValue);
		}

		JsonObject associatedConformance = buildSwiftAssociatedConformanceArtifact(rawValue,
			sourceAddress, source, knownTypes);
		if (associatedConformance != null) {
			String key = empty(associatedConformance.get("conforming_type").getAsString()) + "|" +
				empty(associatedConformance.get("type_name").getAsString()) + "|" +
				empty(associatedConformance.get("associated_type").getAsString()) + "|" +
				empty(associatedConformance.get("address").getAsString());
			if (seenAssociatedConformanceKeys.add(key)) {
				associatedConformances.add(associatedConformance);
			}
			addSwiftCodeCandidates(codeCandidates, seenCodeCandidateKeys,
				empty(associatedConformance.get("type_name").getAsString()),
				empty(associatedConformance.get("stable_alias").getAsString()),
				"associated_conformance", sourceAddress, rawValue);
		}

		JsonObject metadataMethod = buildSwiftMetadataMethodArtifact(rawValue, sourceAddress, source);
		if (metadataMethod != null) {
			String key = empty(metadataMethod.get("stable_alias").getAsString()) + "|" +
				empty(metadataMethod.get("canonical_address").getAsString()) + "|" +
				empty(metadataMethod.get("address").getAsString());
			if (seenMetadataMethodKeys.add(key)) {
				metadataMethods.add(metadataMethod);
			}
			addSwiftCodeCandidates(codeCandidates, seenCodeCandidateKeys,
				empty(metadataMethod.get("type_name").getAsString()),
				empty(metadataMethod.get("stable_alias").getAsString()),
				"metadata_method", sourceAddress, rawValue);
		}
	}

	private JsonObject buildSwiftMetadataMethodArtifact(String rawValue, Address sourceAddress,
			String source) {
		if (!isSwiftSymbol(rawValue)) {
			return null;
		}
		JsonObject artifact = swiftSymbolToJson(rawValue, String.valueOf(sourceAddress), source, null);
		String typeName = empty(artifact.get("type_name").getAsString());
		String memberName = empty(artifact.get("member_name").getAsString());
		String kind = empty(artifact.get("symbol_kind").getAsString());
		String displayName = empty(artifact.get("display_name").getAsString());
		if (typeName.isEmpty() || memberName.isEmpty() ||
			!looksLikeHighConfidenceSwiftMethod(displayName, memberName, kind)) {
			return null;
		}
		artifact.addProperty("artifact_role", "metadata_method");
		return artifact;
	}

	private JsonObject buildSwiftProtocolRequirementArtifact(String rawValue, Address sourceAddress,
			String source) {
		if (!looksLikeSwiftProtocolRequirement(rawValue)) {
			return null;
		}
		String associatedType = extractLeadingSwiftIdentifier(rawValue);
		String protocolName = extractProtocolNameFromAssociatedTypeRef(rawValue);
		if (associatedType.isEmpty() || protocolName.isEmpty()) {
			return null;
		}
		JsonObject object = new JsonObject();
		object.addProperty("kind", "associated_type");
		object.addProperty("type_name", protocolName);
		object.addProperty("protocol_name", protocolName);
		object.addProperty("associated_type", associatedType);
		object.addProperty("address", String.valueOf(sourceAddress));
		object.addProperty("source", source);
		object.addProperty("raw_name", rawValue);
		object.addProperty("stable_alias",
			protocolName + ".associatedtype." + associatedType);
		return object;
	}

	private JsonObject buildSwiftAssociatedConformanceArtifact(String rawValue, Address sourceAddress,
			String source, Set<String> knownTypes) {
		if (!looksLikeSwiftAssociatedConformance(rawValue)) {
			return null;
		}
		String normalized = normalizeAssociatedConformance(rawValue);
		String conformingType = extractLeadingSwiftPath(normalized);
		String associatedType = extractAssociatedTypeName(normalized);
		String demangled = demangleLooseSwiftSymbol(normalized);
		String protocolName = bestKnownTypeMatch(demangled, knownTypes, "");
		String concreteType = extractConcreteTypeFromAssociatedConformanceDemangle(demangled,
			protocolName, conformingType);
		JsonObject object = new JsonObject();
		object.addProperty("kind", "associated_conformance");
		object.addProperty("type_name", protocolName);
		object.addProperty("protocol_name", protocolName);
		object.addProperty("conforming_type", conformingType);
		object.addProperty("associated_type", associatedType);
		object.addProperty("concrete_type", concreteType);
		object.addProperty("address", String.valueOf(sourceAddress));
		object.addProperty("source", source);
		object.addProperty("raw_name", rawValue);
		object.addProperty("demangled", demangled);
		String aliasBase = protocolName.isEmpty() ? conformingType : protocolName;
		if (!aliasBase.isEmpty() && !associatedType.isEmpty() && !conformingType.isEmpty()) {
			object.addProperty("stable_alias",
				aliasBase + ".associatedconformance." + conformingType + "." + associatedType);
		}
		else {
			object.addProperty("stable_alias", rawValue);
		}
		return object;
	}

	private JsonArray buildSwiftAsyncRelationships(List<JsonObject> swiftRecords) {
		JsonArray relationships = new JsonArray();
		Map<String, JsonObject> primaryByAlias = new LinkedHashMap<>();
		for (JsonObject record : swiftRecords) {
			String alias = empty(record.get("stable_alias").getAsString());
			if (alias.isEmpty() || primaryByAlias.containsKey(alias)) {
				continue;
			}
			primaryByAlias.put(alias, record);
		}
		Set<String> seen = new LinkedHashSet<>();
		for (JsonObject record : swiftRecords) {
			boolean asyncLike = record.has("async_like") && record.get("async_like").getAsBoolean();
			boolean outlinedHelper = record.has("outlined_helper") &&
				record.get("outlined_helper").getAsBoolean();
			boolean resumePartial = record.has("resume_partial") &&
				record.get("resume_partial").getAsBoolean();
			if (!asyncLike && !outlinedHelper && !resumePartial) {
				continue;
			}
			String alias = empty(record.get("stable_alias").getAsString());
			String parentAlias = alias;
			if (!parentAlias.isEmpty() && !primaryByAlias.containsKey(parentAlias)) {
				parentAlias = empty(record.get("type_name").getAsString());
			}
			String key = parentAlias + "|" + alias + "|" +
				empty(record.get("canonical_address").getAsString());
			if (!seen.add(key)) {
				continue;
			}
			JsonObject entry = new JsonObject();
			entry.addProperty("type_name", empty(record.get("type_name").getAsString()));
			entry.addProperty("member_name", empty(record.get("member_name").getAsString()));
			entry.addProperty("parent_alias", parentAlias);
			entry.addProperty("child_alias", alias);
			entry.addProperty("address", empty(record.get("address").getAsString()));
			entry.addProperty("canonical_address", empty(record.get("canonical_address").getAsString()));
			entry.addProperty("raw_name", empty(record.get("raw_name").getAsString()));
			entry.addProperty("display_name", empty(record.get("display_name").getAsString()));
			entry.addProperty("relationship",
				resumePartial ? "resume_partial" : (outlinedHelper ? "outlined_helper" : "async_related"));
			relationships.add(entry);
		}
		return relationships;
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

	private void addLikelyObjcRuntimeName(Set<String> values, String rawName) {
		if (isLikelyObjcRuntimeName(rawName)) {
			values.add(rawName);
		}
	}

	private Set<String> filterLikelyObjcRuntimeNames(Set<String> values) {
		Set<String> filtered = new TreeSet<>();
		for (String value : values) {
			if (isLikelyObjcRuntimeName(value)) {
				filtered.add(value);
			}
		}
		return filtered;
	}

	private boolean isLikelyObjcRuntimeName(String rawName) {
		if (rawName == null) {
			return false;
		}
		String value = rawName.trim();
		if (value.isEmpty() || value.length() > 256 || value.length() == 1) {
			return false;
		}
		char first = value.charAt(0);
		if (!(Character.isLetter(first) || first == '_' || first == '$')) {
			return false;
		}
		for (int i = 0; i < value.length(); i++) {
			char ch = value.charAt(i);
			if (Character.isISOControl(ch)) {
				return false;
			}
			if (!(Character.isLetterOrDigit(ch) || ch == '_' || ch == '.' || ch == '$' ||
				ch == ':' || ch == '+' || ch == '-')) {
				return false;
			}
		}
		return true;
	}

	private void addRecoveredProtocol(JsonArray recoveredProtocols, Set<String> seenRecoveredProtocols,
			Set<String> protocols, String rawName, String address, String source) {
		String recoveredName = recoverObjcProtocolName(rawName);
		if (recoveredName.isEmpty()) {
			return;
		}
		String key = recoveredName + "|" + source + "|" + address;
		if (!seenRecoveredProtocols.add(key)) {
			return;
		}
		double confidence = recoveredProtocolConfidence(rawName);
		JsonObject object = new JsonObject();
		object.addProperty("name", recoveredName);
		object.addProperty("raw_name", empty(rawName));
		object.addProperty("address", empty(address));
		object.addProperty("source", source);
		object.addProperty("confidence", confidence);
		recoveredProtocols.add(object);
		if (confidence >= 0.55) {
			protocols.add(recoveredName);
		}
	}

	private String recoverObjcProtocolName(String rawName) {
		String value = empty(rawName);
		if (value.startsWith("_OBJC_PROTOCOL_$_")) {
			return value.substring("_OBJC_PROTOCOL_$_".length());
		}
		if (value.startsWith("_LNSystemEntityProtocolIdentifier")) {
			return value.substring("_LNSystemEntityProtocolIdentifier".length());
		}
		if (value.startsWith("_LNSystemProtocolIdentifier")) {
			return value.substring("_LNSystemProtocolIdentifier".length());
		}
		if (value.startsWith("_protocol_descriptor_for_")) {
			return value.substring("_protocol_descriptor_for_".length());
		}
		if (isLikelyObjcRuntimeName(value) && value.endsWith("Protocol")) {
			return value;
		}
		return "";
	}

	private double recoveredProtocolConfidence(String rawName) {
		String value = empty(rawName);
		if (value.startsWith("_OBJC_PROTOCOL_$_")) {
			return 1.0;
		}
		if (value.startsWith("_LNSystemEntityProtocolIdentifier") ||
			value.startsWith("_LNSystemProtocolIdentifier")) {
			return 0.7;
		}
		if (value.startsWith("_protocol_descriptor_for_")) {
			return 0.65;
		}
		if (isLikelyObjcRuntimeName(value) && value.endsWith("Protocol")) {
			return 0.5;
		}
		return 0.0;
	}

	private JsonObject swiftFunctionToJson(Function function) {
		JsonObject object = swiftSymbolToJson(function.getName(),
			String.valueOf(function.getEntryPoint()), "function", function);
		object.addProperty("thunk", function.isThunk());
		Function canonical = resolveCanonicalFunction(function);
		JsonArray chain = buildImplementationChain(function);
		object.add("implementation_chain", chain);
		if (canonical != null) {
			object.addProperty("canonical_address", String.valueOf(canonical.getEntryPoint()));
			object.addProperty("canonical_name", canonical.getName());
			String demangledCanonical = demangleSwiftName(canonical.getName());
			if (!demangledCanonical.isEmpty() && !demangledCanonical.equals(canonical.getName())) {
				object.addProperty("canonical_demangled", demangledCanonical);
			}
		}
		else {
			object.addProperty("canonical_address", String.valueOf(function.getEntryPoint()));
			object.addProperty("canonical_name", function.getName());
		}
		if (function.isThunk()) {
			Function thunkTarget = function.getThunkedFunction(true);
			if (thunkTarget != null) {
				object.addProperty("thunk_target_address", String.valueOf(thunkTarget.getEntryPoint()));
				object.addProperty("thunk_target_name", thunkTarget.getName());
				String demangledTarget = demangleSwiftName(thunkTarget.getName());
				if (!demangledTarget.isEmpty() && !demangledTarget.equals(thunkTarget.getName())) {
					object.addProperty("thunk_target_demangled", demangledTarget);
				}
			}
		}
		return object;
	}

	private JsonObject swiftSymbolToJson(String name, String address, String source,
			Function function) {
		JsonObject object = new JsonObject();
		object.addProperty("name", name);
		object.addProperty("raw_name", name);
		object.addProperty("address", address);
		object.addProperty("source", source);
		String demangled = demangleSwiftName(name);
		String display = demangled.isEmpty() ? name : demangled;
		object.addProperty("demangled", display);
		object.addProperty("display_name", display);
		object.addProperty("mangled", name.startsWith("$s") || name.startsWith("_$s"));
		object.addProperty("async_like", isSwiftAsyncLike(display));
		object.addProperty("metadata_accessor", isSwiftMetadataAccessor(display));
		object.addProperty("protocol_conformance_like", isSwiftProtocolConformanceLike(display));
		object.addProperty("dispatch_thunk", isSwiftDispatchThunk(display));
		object.addProperty("protocol_witness", isSwiftProtocolWitness(display));
		object.addProperty("outlined_helper", isSwiftOutlinedHelper(display));
		object.addProperty("resume_partial", isSwiftResumePartial(display));
		String typeName = extractSwiftTypeName(display);
		String memberName = extractSwiftMemberName(display, typeName);
		object.addProperty("type_name", typeName);
		object.addProperty("member_name", memberName);
		object.addProperty("stable_alias",
			buildStableSwiftAlias(typeName, memberName, display, name));
		object.addProperty("symbol_kind", classifySwiftSymbolKind(display, memberName));
		if (function != null) {
			object.addProperty("signature", function.getPrototypeString(false, false));
			object.addProperty("is_thunk", function.isThunk());
		}
		else {
			Function resolved = findFunctionForAddress(address);
			if (resolved != null) {
				object.addProperty("function_address", String.valueOf(resolved.getEntryPoint()));
				object.addProperty("function_name", resolved.getName());
				object.addProperty("is_thunk", resolved.isThunk());
				Function canonical = resolveCanonicalFunction(resolved);
				object.add("implementation_chain", buildImplementationChain(resolved));
				if (canonical != null) {
					object.addProperty("canonical_address", String.valueOf(canonical.getEntryPoint()));
					object.addProperty("canonical_name", canonical.getName());
					String demangledCanonical = demangleSwiftName(canonical.getName());
					if (!demangledCanonical.isEmpty() &&
						!demangledCanonical.equals(canonical.getName())) {
						object.addProperty("canonical_demangled", demangledCanonical);
					}
				}
			}
		}
		if (!object.has("canonical_address")) {
			object.addProperty("canonical_address", address);
		}
		return object;
	}

	private void classifySwiftJson(JsonObject symbolJson, Set<String> types,
			Set<String> protocolConformances, Set<String> metadataAccessors,
			Set<String> asyncEntrypoints, Set<String> typeDescriptors, Set<String> dispatchThunks,
			Set<String> protocolWitnesses, Set<String> outlinedHelpers) {
		String display = empty(symbolJson.get("display_name").getAsString());
		String typeName = empty(symbolJson.get("type_name").getAsString());
		String memberName = empty(symbolJson.get("member_name").getAsString());
		if (!typeName.isEmpty()) {
			types.add(typeName);
		}

		Matcher typeMatcher = SWIFT_TYPE_PATTERN.matcher(display);
		if (typeMatcher.find()) {
			String matchedTypeName = typeMatcher.group(1).trim();
			if (!matchedTypeName.isEmpty()) {
				types.add(matchedTypeName);
				metadataAccessors.add(display);
				typeDescriptors.add(matchedTypeName);
			}
		}
		Matcher protocolMatcher = SWIFT_PROTOCOL_PATTERN.matcher(display);
		if (protocolMatcher.find()) {
			String value = protocolMatcher.group(1).trim();
			if (!value.isEmpty()) {
				protocolConformances.add(value);
			}
		}
		if (isSwiftMetadataAccessor(display)) {
			metadataAccessors.add(display);
		}
		if (isSwiftAsyncLike(display)) {
			asyncEntrypoints.add(display);
			if (!memberName.isEmpty()) {
				asyncEntrypoints.add(buildStableSwiftAlias(typeName, memberName, display,
					empty(symbolJson.get("raw_name").getAsString())));
			}
		}
		if (isSwiftDispatchThunk(display)) {
			dispatchThunks.add(display);
		}
		if (isSwiftProtocolWitness(display)) {
			protocolWitnesses.add(display);
		}
		if (isSwiftOutlinedHelper(display)) {
			outlinedHelpers.add(display);
		}
	}

	private void addSwiftAlias(JsonObject aliasMap, JsonArray aliases, JsonObject symbolJson) {
		String rawName = empty(symbolJson.get("raw_name").getAsString());
		String stableAlias = empty(symbolJson.get("stable_alias").getAsString());
		if (rawName.isEmpty() || stableAlias.isEmpty() || aliasMap.has(rawName)) {
			return;
		}
		aliasMap.addProperty(rawName, stableAlias);
		JsonObject alias = new JsonObject();
		alias.addProperty("raw_name", rawName);
		alias.addProperty("stable_alias", stableAlias);
		alias.addProperty("demangled", empty(symbolJson.get("display_name").getAsString()));
		alias.addProperty("type_name", empty(symbolJson.get("type_name").getAsString()));
		alias.addProperty("member_name", empty(symbolJson.get("member_name").getAsString()));
		aliases.add(alias);
	}

	private JsonObject buildSwiftMetadataSectionSummary() {
		JsonObject sections = new JsonObject();
		for (String sectionName : SWIFT_METADATA_SECTION_NAMES) {
			MemoryBlock block = findBlockByName(sectionName);
			JsonObject sectionJson = new JsonObject();
			if (block == null) {
				sectionJson.addProperty("present", false);
				sections.add(sectionName, sectionJson);
				continue;
			}
			sectionJson.addProperty("present", true);
			sectionJson.addProperty("start", String.valueOf(block.getStart()));
			sectionJson.addProperty("end", String.valueOf(block.getEnd()));
			sectionJson.addProperty("size", block.getSize());
			JsonArray strings = new JsonArray();
			JsonArray demangledStrings = new JsonArray();
			for (String value : extractPrintableStringsFromBlock(block, 3)) {
				strings.add(value);
				String demangled = demangleSwiftMetadataString(value);
				if (!demangled.isEmpty() && !demangled.equals(value)) {
					demangledStrings.add(demangled);
				}
			}
			sectionJson.addProperty("string_count", strings.size());
			sectionJson.add("strings", strings);
			sectionJson.add("demangled_strings", demangledStrings);
			sections.add(sectionName, sectionJson);
		}
		return sections;
	}

	private boolean looksLikeSwiftProtocolRequirement(String rawValue) {
		return rawValue != null && !rawValue.isEmpty() &&
			(rawValue.startsWith("_symbolic ") || rawValue.startsWith("_symbolic_")) &&
			rawValue.contains("Qz") && rawValue.endsWith("P");
	}

	private boolean looksLikeSwiftAssociatedConformance(String rawValue) {
		if (rawValue == null || rawValue.isEmpty()) {
			return false;
		}
		return rawValue.startsWith("_associated conformance ") ||
			rawValue.startsWith("_associated_conformance_");
	}

	private String normalizeAssociatedConformance(String rawValue) {
		if (rawValue == null) {
			return "";
		}
		if (rawValue.startsWith("_associated conformance ")) {
			return rawValue.substring("_associated conformance ".length());
		}
		if (rawValue.startsWith("_associated_conformance_")) {
			return rawValue.substring("_associated_conformance_".length());
		}
		return rawValue;
	}

	private String extractLeadingSwiftIdentifier(String rawValue) {
		String normalized = normalizeSymbolicMetadata(rawValue);
		if (normalized.isEmpty()) {
			return "";
		}
		int index = 0;
		if (!Character.isDigit(normalized.charAt(index))) {
			return "";
		}
		while (index < normalized.length() && Character.isDigit(normalized.charAt(index))) {
			index++;
		}
		try {
			int length = Integer.parseInt(normalized.substring(0, index));
			if (length <= 0 || index + length > normalized.length()) {
				return "";
			}
			return normalized.substring(index, index + length);
		}
		catch (NumberFormatException ignored) {
			return "";
		}
	}

	private String extractLeadingSwiftPath(String rawValue) {
		return parseSwiftLengthEncodedPath(normalizeAssociatedConformance(rawValue));
	}

	private String extractProtocolNameFromAssociatedTypeRef(String rawValue) {
		String value = rawValue;
		int markerIndex = value.indexOf("Qz ");
		if (markerIndex >= 0) {
			value = value.substring(markerIndex + 3);
			return parseSwiftLengthEncodedPath(value);
		}
		markerIndex = value.indexOf("Qz_");
		if (markerIndex >= 0) {
			value = value.substring(markerIndex + 3);
			return parseSwiftLengthEncodedPath(value);
		}
		return "";
	}

	private String extractAssociatedTypeName(String rawValue) {
		Matcher matcher = Pattern.compile("(\\d+)([A-Za-z_][A-Za-z0-9_]*)").matcher(rawValue);
		while (matcher.find()) {
			try {
				int declaredLength = Integer.parseInt(matcher.group(1));
				String value = matcher.group(2);
				if (declaredLength == value.length() && value.endsWith("Type")) {
					return value;
				}
			}
			catch (NumberFormatException ignored) {
				return "";
			}
		}
		return "";
	}

	private String normalizeSymbolicMetadata(String rawValue) {
		if (rawValue == null) {
			return "";
		}
		if (rawValue.startsWith("_symbolic ")) {
			return rawValue.substring("_symbolic ".length()).trim();
		}
		if (rawValue.startsWith("_symbolic_")) {
			return rawValue.substring("_symbolic_".length()).trim();
		}
		return rawValue.trim();
	}

	private String parseSwiftLengthEncodedPath(String rawValue) {
		if (rawValue == null || rawValue.isEmpty()) {
			return "";
		}
		String value = rawValue.trim();
		if (value.startsWith("$s")) {
			value = value.substring(2);
		}
		else if (value.startsWith("_$s")) {
			value = value.substring(3);
		}
		List<String> parts = new ArrayList<>();
		int index = 0;
		while (index < value.length() && Character.isDigit(value.charAt(index))) {
			int start = index;
			while (index < value.length() && Character.isDigit(value.charAt(index))) {
				index++;
			}
			int length;
			try {
				length = Integer.parseInt(value.substring(start, index));
			}
			catch (NumberFormatException ignored) {
				break;
			}
			if (length <= 0 || index + length > value.length()) {
				break;
			}
			String part = value.substring(index, index + length);
			parts.add(part);
			index += length;
		}
		if (parts.isEmpty()) {
			return "";
		}
		return String.join(".", parts);
	}

	private String demangleLooseSwiftSymbol(String rawValue) {
		String normalized = normalizeAssociatedConformance(rawValue);
		if (normalized.isEmpty()) {
			return "";
		}
		String candidate = "$s" + normalized;
		String demangled = demangleSwiftName(candidate);
		if (!demangled.equals(candidate)) {
			return demangled;
		}
		return "";
	}

	private String bestKnownTypeMatch(String text, Set<String> knownTypes, String exclude) {
		if (text == null || text.isEmpty()) {
			return "";
		}
		String best = "";
		for (String knownType : knownTypes) {
			if (knownType == null || knownType.isEmpty() || knownType.equals(exclude)) {
				continue;
			}
			String shortName = knownType.contains(".") ?
				knownType.substring(knownType.lastIndexOf('.') + 1) : knownType;
			if (text.contains(knownType) || text.contains(shortName)) {
				if (knownType.length() > best.length()) {
					best = knownType;
				}
			}
		}
		return best;
	}

	private String extractConcreteTypeFromAssociatedConformanceDemangle(String demangled,
			String protocolName, String conformingType) {
		if (demangled == null || demangled.isEmpty()) {
			return "";
		}
		Pattern pattern = Pattern.compile("([A-Z][A-Za-z0-9_]+)$");
		Matcher matcher = pattern.matcher(demangled);
		if (!matcher.find()) {
			return "";
		}
		String candidate = matcher.group(1);
		if (candidate.equals(shortSwiftTypeName(protocolName)) ||
			candidate.equals(shortSwiftTypeName(conformingType))) {
			return "";
		}
		return candidate;
	}

	private String shortSwiftTypeName(String value) {
		if (value == null || value.isEmpty()) {
			return "";
		}
		int index = value.lastIndexOf('.');
		return index >= 0 ? value.substring(index + 1) : value;
	}

	private void addSwiftCodeCandidates(JsonArray codeCandidates, Set<String> seenCodeCandidateKeys,
			String typeName, String stableAlias, String role, Address sourceAddress, String rawName) {
		if (typeName == null || typeName.isEmpty() || sourceAddress == null) {
			return;
		}
		ReferenceIterator iterator = currentProgram.getReferenceManager().getReferencesTo(sourceAddress);
		while (iterator.hasNext()) {
			Reference reference = iterator.next();
			Address fromAddress = reference.getFromAddress();
			Function function = getFunctionContaining(fromAddress);
			Function canonical = function == null ? null : resolveCanonicalFunction(function);
			Instruction instruction = currentProgram.getListing().getInstructionContaining(fromAddress);
			MemoryBlock candidateBlock = currentProgram.getMemory().getBlock(fromAddress);
			boolean executable = candidateBlock != null && candidateBlock.isExecute();
			if (function == null && instruction == null && !executable) {
				continue;
			}
			Address candidate = canonical != null ? canonical.getEntryPoint() :
				instruction != null ? instruction.getAddress() : fromAddress;
			String candidateAddress = String.valueOf(candidate);
			String key = typeName + "|" + role + "|" + stableAlias + "|" + candidateAddress;
			if (!seenCodeCandidateKeys.add(key)) {
				continue;
			}
			JsonObject entry = new JsonObject();
			entry.addProperty("type_name", typeName);
			entry.addProperty("stable_alias", stableAlias);
			entry.addProperty("role", role);
			entry.addProperty("source_address", String.valueOf(sourceAddress));
			entry.addProperty("source_name", rawName);
			entry.addProperty("xref_from", String.valueOf(fromAddress));
			entry.addProperty("ref_type", String.valueOf(reference.getReferenceType()));
			entry.addProperty("candidate_address", candidateAddress);
			entry.addProperty("candidate_block",
				candidateBlock == null ? "" : empty(candidateBlock.getName()));
			entry.addProperty("candidate_executable", executable);
			if (function != null) {
				entry.addProperty("function_address", String.valueOf(function.getEntryPoint()));
				entry.addProperty("function_name", function.getName());
			}
			if (instruction != null) {
				entry.addProperty("instruction_address", String.valueOf(instruction.getAddress()));
				entry.addProperty("instruction", instruction.toString());
			}
			if (canonical != null) {
				entry.addProperty("canonical_address", String.valueOf(canonical.getEntryPoint()));
				entry.addProperty("canonical_name", canonical.getName());
				entry.add("implementation_chain", buildImplementationChain(function));
			}
			codeCandidates.add(entry);
		}
	}

	private Function findFunctionForAddress(String addressValue) {
		if (addressValue == null || addressValue.isEmpty()) {
			return null;
		}
		try {
			Address address = toAddr(addressValue);
			if (address == null) {
				return null;
			}
			Function at = currentProgram.getFunctionManager().getFunctionAt(address);
			if (at != null) {
				return at;
			}
			return getFunctionContaining(address);
		}
		catch (Exception ignored) {
			return null;
		}
	}

	private Function resolveCanonicalFunction(Function function) {
		if (function == null) {
			return null;
		}
		Set<String> seen = new LinkedHashSet<>();
		Function current = function;
		for (int depth = 0; depth < 8 && current != null; depth++) {
			String entry = String.valueOf(current.getEntryPoint());
			if (!seen.add(entry)) {
				break;
			}
			Function next = null;
			if (current.isThunk()) {
				next = current.getThunkedFunction(true);
			}
			if (next == null && current.getBody().getNumAddresses() <= 16) {
				Set<Function> called = current.getCalledFunctions(monitor);
				if (called.size() == 1) {
					next = called.iterator().next();
				}
			}
			if (next == null) {
				break;
			}
			current = next;
		}
		return current == null ? function : current;
	}

	private JsonArray buildImplementationChain(Function function) {
		JsonArray chain = new JsonArray();
		if (function == null) {
			return chain;
		}
		Set<String> seen = new LinkedHashSet<>();
		Function current = function;
		for (int depth = 0; depth < 8 && current != null; depth++) {
			String entry = String.valueOf(current.getEntryPoint());
			if (!seen.add(entry)) {
				break;
			}
			JsonObject step = new JsonObject();
			step.addProperty("address", entry);
			step.addProperty("name", current.getName());
			step.addProperty("is_thunk", current.isThunk());
			step.addProperty("body_size", current.getBody().getNumAddresses());
			chain.add(step);
			Function next = null;
			if (current.isThunk()) {
				next = current.getThunkedFunction(true);
			}
			if (next == null && current.getBody().getNumAddresses() <= 16) {
				Set<Function> called = current.getCalledFunctions(monitor);
				if (called.size() == 1) {
					next = called.iterator().next();
				}
			}
			if (next == null) {
				break;
			}
			current = next;
		}
		return chain;
	}

	private void ingestSwiftSectionStrings(JsonObject sections, Set<String> types,
			Set<String> protocolConformances) {
		ingestSwiftSectionStringsForName(sections, "__swift5_types", types);
		ingestSwiftSectionStringsForName(sections, "__swift5_typeref", types);
		ingestSwiftSectionStringsForName(sections, "__swift5_proto", protocolConformances);
		ingestSwiftSectionStringsForName(sections, "__swift5_assocty", protocolConformances);
	}

	private void ingestSwiftSectionStringsForName(JsonObject sections, String sectionName,
			Set<String> output) {
		JsonObject section = sections.getAsJsonObject(sectionName);
		if (section == null) {
			return;
		}
		JsonArray values = section.has("demangled_strings") &&
			section.getAsJsonArray("demangled_strings").size() > 0 ?
				section.getAsJsonArray("demangled_strings") : section.getAsJsonArray("strings");
		for (JsonElement element : values) {
			String value = element.getAsString().trim();
			if (value.isEmpty()) {
				continue;
			}
			if (looksLikeSwiftTypeName(value) || looksLikeSwiftProtocolName(value)) {
				output.add(value);
			}
		}
	}

	private MemoryBlock findBlockByName(String name) {
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (name.equals(empty(block.getName()))) {
				return block;
			}
		}
		return null;
	}

	private Set<String> extractPrintableStringsFromBlock(MemoryBlock block, int minLength) {
		Set<String> values = new LinkedHashSet<>();
		if (block == null || block.getSize() <= 0) {
			return values;
		}
		long size = Math.min(block.getSize(), 1024L * 1024L * 8L);
		if (size <= 0) {
			return values;
		}
		byte[] bytes = new byte[(int) size];
		try {
			int read = currentProgram.getMemory().getBytes(block.getStart(), bytes);
			if (read <= 0) {
				return values;
			}
			StringBuilder builder = new StringBuilder();
			for (int i = 0; i < read; i++) {
				int value = bytes[i] & 0xff;
				if (value >= 0x20 && value <= 0x7e) {
					builder.append((char) value);
				}
				else {
					if (builder.length() >= minLength) {
						values.add(builder.toString());
					}
					builder.setLength(0);
				}
			}
			if (builder.length() >= minLength) {
				values.add(builder.toString());
			}
		}
		catch (Exception ignored) {
			return values;
		}
		return values;
	}

	private String resolveSwiftDemangleTool() {
		if (swiftDemangleToolResolved) {
			return swiftDemangleTool;
		}
		swiftDemangleToolResolved = true;
		List<String> candidates = Arrays.asList(
			System.getenv("SWIFT_DEMANGLE"),
			"/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift-demangle",
			"/usr/bin/swift-demangle");
		for (String candidate : candidates) {
			if (candidate == null || candidate.isEmpty()) {
				continue;
			}
			File file = new File(candidate);
			if (file.isFile() && file.canExecute()) {
				swiftDemangleTool = file.getAbsolutePath();
				return swiftDemangleTool;
			}
		}
		return "";
	}

	private String demangleSwiftName(String name) {
		if (name == null || name.isEmpty()) {
			return "";
		}
		if (!name.startsWith("$s") && !name.startsWith("_$s") && !name.startsWith("So")) {
			return name;
		}
		if (swiftDemangleCache.containsKey(name)) {
			return swiftDemangleCache.get(name);
		}
		String tool = resolveSwiftDemangleTool();
		if (tool.isEmpty()) {
			swiftDemangleCache.put(name, name);
			return name;
		}
		try {
			Process process = new ProcessBuilder(tool, "-compact", name)
				.redirectErrorStream(true)
				.start();
			String output;
			try (InputStream input = process.getInputStream()) {
				output = new String(input.readAllBytes(), StandardCharsets.UTF_8).trim();
			}
			int exitCode = process.waitFor();
			String value = exitCode == 0 && !output.isEmpty() ? output : name;
			swiftDemangleCache.put(name, value);
			return value;
		}
		catch (Exception ignored) {
			swiftDemangleCache.put(name, name);
			return name;
		}
	}

	private String demangleSwiftMetadataString(String value) {
		if (value == null || value.isEmpty()) {
			return "";
		}
		if (value.startsWith("$s") || value.startsWith("_$s") || value.startsWith("So")) {
			return demangleSwiftName(value);
		}
		return value;
	}

	private boolean isSwiftDispatchThunk(String name) {
		String lower = name.toLowerCase(Locale.ROOT);
		return lower.contains("dispatch thunk of ") || lower.contains("@objc thunk");
	}

	private boolean isSwiftProtocolWitness(String name) {
		return name.toLowerCase(Locale.ROOT).contains("protocol witness");
	}

	private boolean isSwiftOutlinedHelper(String name) {
		String lower = name.toLowerCase(Locale.ROOT);
		return lower.contains("outlined") || lower.contains("partial apply");
	}

	private boolean isSwiftResumePartial(String name) {
		String lower = name.toLowerCase(Locale.ROOT);
		return lower.contains("resume partial function") || lower.contains("suspend resume");
	}

	private String buildStableSwiftAlias(String typeName, String memberName, String displayName,
			String rawName) {
		if (!typeName.isEmpty() && !memberName.isEmpty()) {
			return typeName + "." + memberName;
		}
		if (!typeName.isEmpty()) {
			return typeName;
		}
		if (displayName != null && !displayName.isEmpty()) {
			return displayName;
		}
		return empty(rawName);
	}

	private String extractSwiftTypeName(String displayName) {
		String normalized = stripSwiftPrefixes(displayName);
		Matcher typeMatcher = SWIFT_TYPE_PATTERN.matcher(normalized);
		if (typeMatcher.find()) {
			return typeMatcher.group(1).trim();
		}
		int witnessIndex = normalized.indexOf(" in conformance ");
		String primary = witnessIndex >= 0 ? normalized.substring(0, witnessIndex) : normalized;
		int parenIndex = primary.indexOf('(');
		int dotIndex = parenIndex >= 0 ? primary.lastIndexOf('.', parenIndex) :
			primary.lastIndexOf('.');
		if (dotIndex > 0) {
			return primary.substring(0, dotIndex).trim();
		}
		if (looksLikeSwiftTypeName(primary)) {
			return primary.trim();
		}
		return "";
	}

	private String extractSwiftMemberName(String displayName, String typeName) {
		String normalized = stripSwiftPrefixes(displayName);
		if (!typeName.isEmpty() && normalized.startsWith(typeName + ".")) {
			return normalized.substring(typeName.length() + 1).trim();
		}
		int witnessIndex = normalized.indexOf(" in conformance ");
		if (witnessIndex > 0) {
			normalized = normalized.substring(0, witnessIndex).trim();
			if (!typeName.isEmpty() && normalized.startsWith(typeName + ".")) {
				return normalized.substring(typeName.length() + 1).trim();
			}
		}
		return normalized;
	}

	private String stripSwiftPrefixes(String displayName) {
		if (displayName == null) {
			return "";
		}
		String value = displayName.trim();
		String[] prefixes = {
			"dispatch thunk of ",
			"@objc thunk for ",
			"protocol witness for ",
			"method descriptor for ",
			"type metadata accessor for ",
			"type metadata for ",
			"nominal type descriptor for "
		};
		for (String prefix : prefixes) {
			if (value.startsWith(prefix)) {
				return value.substring(prefix.length()).trim();
			}
		}
		return value;
	}

	private boolean looksLikeSwiftTypeName(String value) {
		if (value == null || value.isEmpty()) {
			return false;
		}
		if (value.contains("(") || value.contains(" ") || value.contains("-[") ||
			value.contains("+[") || value.startsWith("___")) {
			return false;
		}
		if (!value.matches("^[A-Za-z_][A-Za-z0-9_$.<>:]*$")) {
			return false;
		}
		return Character.isUpperCase(value.charAt(0)) || value.startsWith("__C.") ||
			value.contains(".");
	}

	private boolean looksLikeSwiftProtocolName(String value) {
		if (value == null || value.isEmpty()) {
			return false;
		}
		if (!looksLikeSwiftTypeName(value)) {
			return false;
		}
		String lower = value.toLowerCase(Locale.ROOT);
		return lower.contains("protocol") || value.startsWith("__C.") ||
			Character.isUpperCase(value.charAt(0));
	}

	private String classifySwiftSymbolKind(String displayName, String memberName) {
		String lowerMember = memberName.toLowerCase(Locale.ROOT);
		if (isSwiftDispatchThunk(displayName)) {
			return "dispatch_thunk";
		}
		if (isSwiftProtocolWitness(displayName)) {
			return "protocol_witness";
		}
		if (isSwiftMetadataAccessor(displayName)) {
			return "metadata_accessor";
		}
		if (isSwiftAsyncLike(displayName)) {
			return "async_method";
		}
		if (lowerMember.startsWith("getter :") || lowerMember.startsWith("setter :") ||
			lowerMember.startsWith("modify") || lowerMember.startsWith("read") ||
			lowerMember.contains("willset") || lowerMember.contains("didset")) {
			return "property_accessor";
		}
		if (lowerMember.startsWith("init(") || lowerMember.startsWith("__allocating_init(")) {
			return "initializer";
		}
		if (lowerMember.startsWith("deinit")) {
			return "deinitializer";
		}
		if (isSwiftOutlinedHelper(displayName)) {
			return "outlined_helper";
		}
		return "method";
	}

	private boolean looksLikeHighConfidenceSwiftMethod(String displayName, String memberName,
			String kind) {
		if (displayName == null || displayName.isEmpty() || memberName == null ||
			memberName.isEmpty()) {
			return false;
		}
		if ("metadata_accessor".equals(kind) || "outlined_helper".equals(kind)) {
			return false;
		}
		String lowerMember = memberName.toLowerCase(Locale.ROOT);
		if (memberName.contains("(") || lowerMember.startsWith("getter :") ||
			lowerMember.startsWith("setter :") || lowerMember.startsWith("modify") ||
			lowerMember.startsWith("read") || lowerMember.startsWith("init(") ||
			lowerMember.startsWith("__allocating_init(") || lowerMember.startsWith("deinit") ||
			lowerMember.startsWith("start(")) {
			return true;
		}
		return "dispatch_thunk".equals(kind) || "protocol_witness".equals(kind) ||
			"async_method".equals(kind);
	}

	private boolean isSwiftSymbol(String name) {
		String lower = name.toLowerCase(Locale.ROOT);
		if (name.startsWith("$s") || name.startsWith("_$s") || lower.contains("swift") ||
			lower.contains("type metadata") || lower.contains("protocol conformance")) {
			return true;
		}
		if (lower.contains("block_invoke") || name.contains("-[") || name.contains("+[") ||
			name.startsWith("___")) {
			return false;
		}
		String stripped = stripSwiftPrefixes(name);
		return stripped.contains(".") &&
			(stripped.contains("(") || stripped.contains("getter :") ||
				stripped.contains("setter :") || stripped.contains("modify") ||
				stripped.contains("read") || stripped.contains("init(") ||
				stripped.contains("deinit"));
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
