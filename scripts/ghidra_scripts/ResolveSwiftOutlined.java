/* ###
 * IP: GHIDRA
 */
//@category Swift

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

/**
 * ResolveSwiftOutlined.java
 *
 * Renames and (optionally) inlines the _OUTLINED_FUNCTION_* stubs that the
 * Swift compiler emits for shared ARC/copy/move helpers and that appear in
 * ARM64 Apple dyld-extracted binaries.
 *
 * Two distinct populations exist in a typical WorkflowKit-size binary:
 *
 *   A. True Swift outlined helpers  — short (8-128 b) functions scattered
 *      through __text that implement retain/release/copy/destroy via register
 *      shuffles, global loads, and PAC-guarded tail calls.
 *
 *   B. Unresolved import auth stubs — dense 16-byte blocks that are really
 *      dyld __stubs (adrp/add/ldr/braa) whose GOT binding metadata was lost
 *      during dyld cache extraction.  Ghidra labels these _OUTLINED_FUNCTION_0
 *      because it could not resolve their names.
 *
 * This script:
 *   1. Iterates every function whose name starts with _OUTLINED_FUNCTION_.
 *   2. Reads its instruction sequence via the Listing API.
 *   3. Classifies by instruction pattern.
 *   4. Renames to a descriptive name that makes decompiler output readable.
 *   5. For pure ARC helpers (≤ 4 instructions, no branches except ret),
 *      marks the function as inline so the decompiler folds it away.
 *   6. Writes a JSON report to the output_dir.
 *
 * Arguments (key=value style):
 *   output_dir=<path>    Directory for the report JSON. Required.
 *   dry_run=true         Classify and report but do not rename or inline.
 *   inline=true          Mark pure helpers as inline (default: true).
 *   skip_stubs=true      Skip category-B auth stubs entirely (default: true).
 *   verbose=true         Print each rename to the script console.
 */
public class ResolveSwiftOutlined extends GhidraScript {

	// -------------------------------------------------------------------------
	// Pattern classifiers — each returns a short descriptive tag, or null if
	// the pattern does not match.  They are tried in order; first match wins.
	// -------------------------------------------------------------------------

	/** Category B: 4-instruction PAC auth stub (adrp / add / ldr / braa). */
	private static String classifyAuthStub(List<String> mnems) {
		if (mnems.size() == 4
				&& mnems.get(0).equals("adrp")
				&& mnems.get(1).equals("add")
				&& mnems.get(2).equals("ldr")
				&& (mnems.get(3).startsWith("bra"))) {
			return "authstub";
		}
		return null;
	}

	/** PAC-guarded tail call: ends with eor / tbz / brk / b. */
	private static String classifyPacTail(List<String> mnems) {
		int n = mnems.size();
		if (n >= 4
				&& mnems.get(n - 4).equals("eor")
				&& mnems.get(n - 3).equals("tbz")
				&& mnems.get(n - 2).equals("brk")
				&& mnems.get(n - 1).equals("b")) {
			// What does the preamble do?
			List<String> pre = mnems.subList(0, n - 4);
			if (pre.isEmpty()) return "pactail";
			if (allMov(pre)) return "pactail$argshuffle";
			if (pre.stream().allMatch(m -> m.equals("adrp") || m.equals("add"))) {
				return "pactail$typemeta";
			}
			if (pre.stream().anyMatch(m -> m.equals("ldr") || m.equals("ldur") || m.equals("ldp"))) {
				return "pactail$load";
			}
			return "pactail";
		}
		return null;
	}

	/** Pure register-to-register shuffles ending in ret — arg marshalling helpers. */
	private static String classifyArgShuffle(List<String> mnems) {
		if (mnems.isEmpty()) return null;
		String last = mnems.get(mnems.size() - 1);
		if (!last.startsWith("ret")) return null;
		List<String> body = mnems.subList(0, mnems.size() - 1);
		if (body.isEmpty()) return null;
		if (allMov(body)) return "argshuffle";
		// mov + sub (stack adjust) patterns
		if (body.stream().allMatch(m -> m.equals("mov") || m.equals("sub") || m.equals("add"))) {
			return "argshuffle$stackadj";
		}
		return null;
	}

	/** adrp+ldr or adrp+add pairs ending with ret — load a global/type-metadata pointer. */
	private static String classifyGlobalLoad(List<String> mnems) {
		if (mnems.isEmpty()) return null;
		String last = mnems.get(mnems.size() - 1);
		if (!last.startsWith("ret")) return null;
		List<String> body = mnems.subList(0, mnems.size() - 1);
		if (body.isEmpty()) return null;
		boolean allAddrLoad = body.stream().allMatch(
			m -> m.equals("adrp") || m.equals("add") || m.equals("ldr") || m.equals("ldur"));
		if (allAddrLoad) {
			// distinguish single load from multi-load
			long adrpCount = body.stream().filter(m -> m.equals("adrp")).count();
			if (adrpCount == 1) return "loadglobal";
			if (adrpCount == 2) return "loadglobal$pair";
			return "loadglobal$multi";
		}
		return null;
	}

	/**
	 * ldr/ldur/ldp + mov* + ret — load then move.  Covers retain/release
	 * patterns where an object pointer is loaded from a callee-saved slot.
	 */
	private static String classifyLoadMov(List<String> mnems) {
		if (mnems.isEmpty()) return null;
		String last = mnems.get(mnems.size() - 1);
		if (!last.startsWith("ret")) return null;
		List<String> body = mnems.subList(0, mnems.size() - 1);
		if (body.isEmpty()) return null;
		boolean startsWithLoad = body.get(0).equals("ldr") || body.get(0).equals("ldur")
				|| body.get(0).equals("ldp");
		if (!startsWithLoad) return null;
		boolean restMov = body.subList(1, body.size()).stream()
				.allMatch(m -> m.equals("mov") || m.equals("ldr") || m.equals("ldur"));
		if (restMov) return "loadmov";
		return null;
	}

	/**
	 * Small (≤ 5 insns) helper that ends in ret and mixes loads/stores/arithmetic.
	 * Too specific to match a known ARC template but clearly a shared computation
	 * helper extracted by the compiler. Rename as "helper$Nb" for readability.
	 */
	private static String classifySmallHelper(List<String> mnems, int bodySize) {
		if (mnems.isEmpty()) return null;
		if (mnems.size() > 5) return null;
		String last = mnems.get(mnems.size() - 1);
		// Accept ret or unconditional b (tail call without PAC guard)
		if (!last.startsWith("ret") && !last.equals("b")) return null;
		// Must not be a PAC stub (those have braa)
		if (mnems.stream().anyMatch(m -> m.startsWith("bra"))) return null;
		return "helper$" + bodySize + "b";
	}

	/** pacia/pacib sign-pointer helpers. */
	private static String classifyPacSign(List<String> mnems) {
		if (mnems.isEmpty()) return null;
		String last = mnems.get(mnems.size() - 1);
		if (!last.startsWith("ret")) return null;
		boolean hasPac = mnems.stream().anyMatch(m -> m.startsWith("pac") && !m.equals("pacibsp"));
		if (hasPac) return "pacsign";
		return null;
	}

	/** Comparison helpers — and/cmp/cset patterns. */
	private static String classifyCompare(List<String> mnems) {
		if (mnems.isEmpty()) return null;
		String last = mnems.get(mnems.size() - 1);
		if (!last.startsWith("ret")) return null;
		boolean hasCmp = mnems.stream().anyMatch(m -> m.equals("cmp") || m.equals("subs"));
		boolean hasCset = mnems.stream().anyMatch(m -> m.startsWith("cset") || m.startsWith("csel"));
		if (hasCmp && hasCset) return "compare";
		return null;
	}

	/** Fallback. */
	private static String classifyFallback(List<String> mnems, int bodySize) {
		return "misc$" + bodySize + "b";
	}

	// -------------------------------------------------------------------------

	private static boolean allMov(List<String> mnems) {
		return !mnems.isEmpty() && mnems.stream().allMatch(m -> m.equals("mov") || m.equals("movz")
				|| m.equals("movk") || m.equals("movn") || m.equals("fmov"));
	}

	// -------------------------------------------------------------------------
	// Main script body
	// -------------------------------------------------------------------------

	@Override
	protected void run() throws Exception {
		Map<String, String> args = parseArgs();
		String outputDir = requireArg(args, "output_dir");
		boolean dryRun = "true".equalsIgnoreCase(args.getOrDefault("dry_run", "false"));
		boolean doInline = !"false".equalsIgnoreCase(args.getOrDefault("inline", "true"));
		boolean skipStubs = !"false".equalsIgnoreCase(args.getOrDefault("skip_stubs", "true"));
		boolean verbose = "true".equalsIgnoreCase(args.getOrDefault("verbose", "false"));

		Listing listing = currentProgram.getListing();
		FunctionIterator iter = listing.getFunctions(true);

		// Counters per category
		Map<String, Integer> categoryCounts = new LinkedHashMap<>();
		JsonArray renames = new JsonArray();

		int total = 0;
		int renamed = 0;
		int inlined = 0;
		int skipped = 0;

		// Track per-category sequential index for unique naming
		Map<String, Integer> categoryIndex = new LinkedHashMap<>();

		while (iter.hasNext() && !monitor.isCancelled()) {
			Function fn = iter.next();
			String name = fn.getName();
			if (!name.startsWith("_OUTLINED_FUNCTION_")) continue;
			total++;

			// Read instructions
			AddressSetView body = fn.getBody();
			long bodySize = body.getNumAddresses();
			List<String> mnems = new ArrayList<>();
			InstructionIterator insns = listing.getInstructions(body, true);
			while (insns.hasNext()) {
				Instruction insn = insns.next();
				mnems.add(insn.getMnemonicString().toLowerCase());
			}

			// Classify
			String category = null;
			if (category == null) category = classifyAuthStub(mnems);
			boolean isStub = "authstub".equals(category);
			if (isStub && skipStubs) {
				skipped++;
				continue;
			}
			if (category == null) category = classifyPacSign(mnems);
			if (category == null) category = classifyCompare(mnems);
			if (category == null) category = classifyArgShuffle(mnems);
			if (category == null) category = classifyGlobalLoad(mnems);
			if (category == null) category = classifyLoadMov(mnems);
			if (category == null) category = classifyPacTail(mnems);
			if (category == null) category = classifySmallHelper(mnems, (int) bodySize);
			if (category == null) category = classifyFallback(mnems, (int) bodySize);

			categoryCounts.merge(category, 1, Integer::sum);
			int idx = categoryIndex.merge(category, 0, (a, b2) -> a + 1);
			String newName = "outlined$" + category + "$" + String.format("%04d", idx);

			// For PAC tail calls: resolve the branch target and embed callee name.
			// Only use the callee name when it is a real symbol (not FUN_xxxx or
			// another _OUTLINED_FUNCTION_ which hasn't been renamed yet).
			if (category != null && category.startsWith("pactail")) {
				String calleeName = resolveBranchTarget(fn, listing);
				if (calleeName != null
						&& !calleeName.isEmpty()
						&& !calleeName.startsWith("FUN_")
						&& !calleeName.startsWith("_OUTLINED_FUNCTION_")) {
					// Sanitise: collapse special chars, trim length
					String safe = calleeName.replaceAll("[^A-Za-z0-9_$]", "_");
					if (safe.startsWith("_")) safe = safe.substring(1);
					if (safe.length() > 60) safe = safe.substring(0, 60);
					newName = "outlined$" + category + "$" + safe;
				}
			}

			// Determine whether to mark as inline:
			// Only for pure helpers that have no branches (except terminal ret/b),
			// are small, and do not already have callers that would cause infinite recursion.
			boolean markInline = doInline && !isStub
					&& bodySize <= 64
					&& !category.startsWith("pactail") // pactail has a branch — keep as function
					&& !category.startsWith("misc");

			// Apply
			if (!dryRun) {
				fn.setName(newName, SourceType.ANALYSIS);
				if (markInline) {
					fn.setInline(true);
					inlined++;
				}
				renamed++;
			}

			if (verbose) {
				println((dryRun ? "[dry] " : "") + name + " → " + newName
						+ (markInline ? " [inline]" : "")
						+ "  (" + mnems.size() + " insns, " + bodySize + "b)");
			}

			JsonObject rec = new JsonObject();
			rec.addProperty("old_name", name);
			rec.addProperty("new_name", newName);
			rec.addProperty("category", category);
			rec.addProperty("entry", fn.getEntryPoint().toString());
			rec.addProperty("body_size", bodySize);
			rec.addProperty("instruction_count", mnems.size());
			rec.addProperty("marked_inline", markInline && !dryRun);
			renames.add(rec);
		}

		// Write report
		JsonObject report = new JsonObject();
		report.addProperty("program_name", currentProgram.getName());
		report.addProperty("dry_run", dryRun);
		report.addProperty("total_outlined_functions", total);
		report.addProperty("renamed", renamed);
		report.addProperty("inlined", inlined);
		report.addProperty("skipped_stubs", skipped);
		JsonObject cats = new JsonObject();
		for (Map.Entry<String, Integer> e : categoryCounts.entrySet()) {
			cats.addProperty(e.getKey(), e.getValue());
		}
		report.add("categories", cats);
		report.add("renames", renames);

		File dir = new File(outputDir);
		if (!dir.exists()) dir.mkdirs();
		File outFile = new File(dir, "swift_outlined_resolved.json");
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		try (Writer w = new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8)) {
			gson.toJson(report, w);
		}
		println("ResolveSwiftOutlined: " + total + " found, " + renamed + " renamed"
				+ (dryRun ? " (dry run)" : "") + ", " + inlined + " marked inline. "
				+ "Report: " + outFile.getAbsolutePath());
	}

	/**
	 * For a PAC-guarded tail call, resolve the ultimate branch target function name.
	 * The last instruction of the function is a direct B (unconditional branch).
	 */
	private String resolveBranchTarget(Function fn, Listing listing) {
		try {
			Address body_end = fn.getBody().getMaxAddress();
			// Walk back from end to find the B instruction
			Instruction insn = listing.getInstructionAt(body_end);
			if (insn == null) insn = listing.getInstructionContaining(body_end);
			// Scan backwards up to 8 instructions
			for (int i = 0; i < 8 && insn != null; i++) {
				String m = insn.getMnemonicString().toLowerCase();
				if (m.equals("b") || m.equals("bl") || m.startsWith("bra")) {
					// Get the branch target via flow references
					Reference[] refs = insn.getReferencesFrom();
					for (Reference ref : refs) {
						if (ref.getReferenceType().isFlow()) {
							Address target = ref.getToAddress();
							Function targetFn = currentProgram.getFunctionManager()
									.getFunctionAt(target);
							if (targetFn != null) {
								return targetFn.getName();
							}
							// Fallback: look up primary symbol
							Symbol sym = currentProgram.getSymbolTable()
									.getPrimarySymbol(target);
							if (sym != null) return sym.getName();
						}
					}
					break;
				}
				insn = insn.getPrevious();
			}
		}
		catch (Exception e) {
			// best-effort — ignore
		}
		return null;
	}

	// -------------------------------------------------------------------------

	private Map<String, String> parseArgs() {
		Map<String, String> args = new LinkedHashMap<>();
		for (String arg : getScriptArgs()) {
			int idx = arg.indexOf('=');
			if (idx > 0) {
				args.put(arg.substring(0, idx).trim().toLowerCase().replace('-', '_'),
					arg.substring(idx + 1));
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
}
