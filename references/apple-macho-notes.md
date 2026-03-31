# Apple Mach-O Notes

Use this skill for:

- Mach-O binaries from live system paths
- dyld-extracted framework binaries
- XPC service executables
- simulator or iOSSupport binaries that already exist as standalone Mach-O files

V1 does not parse raw dyld shared cache files directly. Prefer already-extracted binaries.

## What the export bundle looks for

- Objective-C symbols such as `_OBJC_CLASS_$_*`, `_OBJC_METACLASS_$_*`, `_OBJC_PROTOCOL_$_*`
- Objective-C method names like `-[Class selector:]` and `+[Class selector:]`
- section or block names containing:
  - `objc`
  - `methname`
  - `classname`
  - `cfstring`
- imported and exported symbols
- demangled function names after `DemangleAllScript.java`

## Good Apple-first targets

- Small XPC or helper executables when you want quick iteration
- dyld-extracted private frameworks when the live on-disk framework has only resources
- Shortcuts and Siri support binaries where the public app bundle is a launcher and the implementation lives in a private framework

## Common follow-ups

- Export the default bundle first
- Decompile one function by exact name or address
- Export xrefs for `_objc_msgSend`, `_swift_allocObject`, `dispatch_*`, or a target selector string
