/* ###
 * IP: GHIDRA
 */
//@category BugHunt

import java.io.File;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class ExportFunctionDossier extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Map<String, String> args = parseArgs();
		String manifestPath = requireArg(args, "manifest");
		String outputDir = requireArg(args, "output_dir");
		int sampleLimit = parseIntArg(args, "sample_limit", 25);
		int timeout = parseIntArg(args, "timeout", 60);

		BugHuntSupport.Manifest manifest = BugHuntSupport.loadManifest(manifestPath);
		BugHuntSupport.ProgramIndex index =
			BugHuntSupport.buildProgramIndex(currentProgram, monitor);
		Function function =
			BugHuntSupport.resolveFunction(index, args.get("address"), args.get("function"));
		if (function == null) {
			throw new IllegalArgumentException("unable to resolve a target function");
		}
		BugHuntSupport.FunctionFacts facts = index.byAddress.get(function.getEntryPoint());
		if (facts == null) {
			throw new IllegalStateException("resolved function was not indexed");
		}

		File outdir = new File(outputDir);
		if (!outdir.exists() && !outdir.mkdirs()) {
			throw new IllegalStateException("failed to create " + outdir);
		}

		String decompiledText = decompile(function, timeout);
		JsonObject context = buildContext(index, manifest, facts, sampleLimit);
		BugHuntSupport.writeJson(new File(outdir, "context.json"), context);
		BugHuntSupport.writeText(new File(outdir, "decompile.c"), decompiledText);
		BugHuntSupport.writeText(new File(outdir, "summary.md"),
			buildSummary(index, manifest, facts, sampleLimit));
		println("Wrote dossier to " + outdir.getAbsolutePath());
	}

	private JsonObject buildContext(BugHuntSupport.ProgramIndex index,
			BugHuntSupport.Manifest manifest, BugHuntSupport.FunctionFacts facts,
			int sampleLimit) {
		JsonObject object = new JsonObject();
		object.addProperty("program_name", currentProgram.getName());
		object.add("function", BugHuntSupport.functionToJson(index, facts, sampleLimit));

		JsonArray callers = new JsonArray();
		for (String callerKey : facts.callerKeys) {
			BugHuntSupport.FunctionFacts caller = index.byKey.get(callerKey);
			if (caller != null) {
				callers.add(BugHuntSupport.functionToJson(index, caller, sampleLimit));
			}
		}
		JsonArray callees = new JsonArray();
		for (String calleeKey : facts.calleeKeys) {
			BugHuntSupport.FunctionFacts callee = index.byKey.get(calleeKey);
			if (callee != null) {
				callees.add(BugHuntSupport.functionToJson(index, callee, sampleLimit));
			}
		}
		object.add("callers", callers);
		object.add("callees", callees);

		object.add("nearby_strings", BugHuntSupport.toJsonArray(facts.referencedStrings, sampleLimit));
		object.add("nearby_selectors",
			BugHuntSupport.toJsonArray(facts.referencedSelectors, sampleLimit));
		object.add("imported_apis", BugHuntSupport.toJsonArray(facts.importedApis, sampleLimit));
		object.add("bug_hunt_tags", buildTagObject(facts, manifest));
		return object;
	}

	private JsonObject buildTagObject(BugHuntSupport.FunctionFacts facts,
			BugHuntSupport.Manifest manifest) {
		JsonObject tags = new JsonObject();
		JsonArray entryTags = new JsonArray();
		for (BugHuntSupport.CategoryMatch match :
				BugHuntSupport.findEntrypoints(facts, manifest)) {
			entryTags.add(match.categoryId);
		}
		JsonArray sinkTags = new JsonArray();
		for (BugHuntSupport.CategoryMatch match : BugHuntSupport.findSinks(facts, manifest)) {
			sinkTags.add(match.categoryId);
		}
		tags.add("entrypoint_categories", entryTags);
		tags.add("sink_categories", sinkTags);
		tags.addProperty("parser_like", BugHuntSupport.hasParserLikeEvidence(facts, manifest));
		return tags;
	}

	private String decompile(Function function, int timeout) throws Exception {
		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		DecompileResults results = decompiler.decompileFunction(function, timeout, monitor);
		if (!results.decompileCompleted()) {
			throw new RuntimeException(
				"decompilation failed for " + function.getName() + ": " + results.getErrorMessage());
		}
		StringBuilder builder = new StringBuilder();
		builder.append("// Program: ").append(currentProgram.getName()).append("\n");
		builder.append("// Function: ").append(function.getName()).append("\n");
		builder.append("// Entry: ").append(function.getEntryPoint()).append("\n\n");
		builder.append(results.getDecompiledFunction().getC()).append("\n");
		return builder.toString();
	}

	private String buildSummary(BugHuntSupport.ProgramIndex index,
			BugHuntSupport.Manifest manifest, BugHuntSupport.FunctionFacts facts,
			int sampleLimit) {
		StringBuilder builder = new StringBuilder();
		builder.append("# Function Dossier\n\n");
		builder.append("- Program: `").append(currentProgram.getName()).append("`\n");
		builder.append("- Function: `").append(facts.name).append("`\n");
		builder.append("- Address: `").append(facts.address).append("`\n");
		if (!facts.namespace.isEmpty()) {
			builder.append("- Namespace: `").append(facts.namespace).append("`\n");
		}
		builder.append("- Callers: ").append(facts.callerKeys.size()).append("\n");
		builder.append("- Callees: ").append(facts.calleeKeys.size()).append("\n");
		builder.append("- Imported APIs: ").append(facts.importedApis.size()).append("\n\n");

		List<BugHuntSupport.CategoryMatch> entryMatches =
			BugHuntSupport.findEntrypoints(facts, manifest);
		List<BugHuntSupport.CategoryMatch> sinkMatches =
			BugHuntSupport.findSinks(facts, manifest);
		builder.append("## Bug-Hunt Tags\n\n");
		builder.append("- Entrypoint tags: ");
		appendCategoryList(builder, entryMatches);
		builder.append("\n");
		builder.append("- Sink tags: ");
		appendCategoryList(builder, sinkMatches);
		builder.append("\n");
		builder.append("- Parser-like: ")
			.append(BugHuntSupport.hasParserLikeEvidence(facts, manifest) ? "yes" : "no")
			.append("\n\n");

		builder.append("## Imported APIs\n\n");
		appendSampleList(builder, facts.importedApis, sampleLimit);
		builder.append("\n## Nearby Strings\n\n");
		appendSampleList(builder, facts.referencedStrings, sampleLimit);
		builder.append("\n## Nearby Selectors\n\n");
		appendSampleList(builder, facts.referencedSelectors, sampleLimit);
		builder.append("\n## Direct Callers\n\n");
		appendFunctionSample(builder, index, facts.callerKeys, sampleLimit);
		builder.append("\n## Direct Callees\n\n");
		appendFunctionSample(builder, index, facts.calleeKeys, sampleLimit);
		return builder.toString();
	}

	private void appendCategoryList(StringBuilder builder,
			List<BugHuntSupport.CategoryMatch> matches) {
		if (matches.isEmpty()) {
			builder.append("none");
			return;
		}
		for (int index = 0; index < matches.size(); index++) {
			if (index > 0) {
				builder.append(", ");
			}
			builder.append("`").append(matches.get(index).categoryId).append("`");
		}
	}

	private void appendSampleList(StringBuilder builder, Iterable<String> values, int limit) {
		int count = 0;
		for (String value : values) {
			if (count >= limit) {
				break;
			}
			builder.append("- `").append(value).append("`\n");
			count++;
		}
		if (count == 0) {
			builder.append("- none\n");
		}
	}

	private void appendFunctionSample(StringBuilder builder, BugHuntSupport.ProgramIndex index,
			Iterable<String> keys, int limit) {
		int count = 0;
		for (String key : keys) {
			if (count >= limit) {
				break;
			}
			BugHuntSupport.FunctionFacts facts = index.byKey.get(key);
			if (facts == null) {
				continue;
			}
			builder.append("- `").append(facts.name).append(" @ ").append(facts.address)
				.append("`\n");
			count++;
		}
		if (count == 0) {
			builder.append("- none\n");
		}
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

	private int parseIntArg(Map<String, String> args, String key, int defaultValue) {
		String value = args.get(key);
		if (value == null || value.isEmpty()) {
			return defaultValue;
		}
		return Integer.decode(value);
	}
}
