# Bug-Hunt Outputs

The bug-hunt bundle writes to:

`~/ghidra-projects/exports/<project_name>/<program_name>/bug-hunt/`

Expected files:

- `entrypoints.json`
  - ranked candidate entrypoint functions with matched categories and evidence
- `sinks.json`
  - ranked candidate sink functions with matched categories and evidence
- `candidate_paths.json`
  - bounded entrypoint-to-sink paths with score, evidence, and ordered function nodes
- `summary.md`
  - human-readable summary of the top candidate paths

Function dossiers write to:

`~/ghidra-projects/exports/<project_name>/<program_name>/dossiers/<slug>/`

Expected files:

- `context.json`
  - function metadata, callers, callees, imports, nearby strings/selectors, and bug-hunt tags
- `decompile.c`
  - decompiled C for the selected function
- `summary.md`
  - quick review notes for the selected function

Applied findings write to:

`~/ghidra-projects/exports/<project_name>/<program_name>/findings/<slug>/finding_result.json`
