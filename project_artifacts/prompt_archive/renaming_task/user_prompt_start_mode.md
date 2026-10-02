# Task

Your task is to analyze a stripped and statically linked malware binary from the {{malware_family}} botnet family and systematically **rename** obfuscated functions, parameters, and variables to reflect their actual behavior based on code analysis and evidence.

{{malware_guide}}

# Analysis Workflow

1. **Identify execution flow**: Locate the entry point and trace the path to the malware's effective "main" routine
2. **Recursive function analysis**: Starting from main, analyze each function to understand its behavior, then rename it accordingly
3. **Propagate analysis**: Continue recursively through callers and callees, renaming as many functions as you can verify
4. **Rename supporting elements**: When technically justified by observed behavior, rename function parameters and local variables to clarify purpose

# Execution

For each identified function, parameter, or variable:
1. Analyze its behavior thoroughly
2. Document the evidence supporting your renaming
3. Execute the rename using the appropriate Ghidra MCP tool:
   - `rename_function_by_address` for functions
   - `rename_variable` for local variables and parameters
   - `rename_label` for labeled addresses

# Output Delivery

Provide a brief summary document (as Markdown or text file using the tool `write_file`) that lists:

- **Functions Renamed**: Function name, address, and the behavioral evidence supporting the rename
- **Parameters & Variables Renamed**: Variable name, associated function, and justification
- **Analysis Gaps**: Any functions, parameters, or variables you could not confidently rename, and why
- **Key Findings**: High-level summary of the malware's core behavior based on renamed elements

# Key Principles

- **Never infer without proof**: If you cannot observe it in the code, do not rename based on assumption
- **Prioritize impact**: Prioritize renaming functions and other high-impact renames that clarify core malware behavior.
- **Work systematically**: Begin from the entry point and propagate outward; ensure each rename is backed by clear evidence
- **Facilitate independent verification**: Provide enough detail that another analyst could examine the same code and confirm your work
- **Focus on clarity**: Renames should make the malware's intent and mechanics immediately obvious to other security professionals