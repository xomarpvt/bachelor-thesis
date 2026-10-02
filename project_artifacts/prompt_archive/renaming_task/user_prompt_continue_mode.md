# Task

Your task is to review, validate, and enhance the function, parameter, and variable renaming performed on a stripped and statically linked {{malware_family}} botnet malware binary.

Identify inaccurate, incomplete, or insufficiently justified renames; correct them; and identify additional renaming opportunities to improve code clarity and malware understanding.

Vague or speculative renames should be corrected to reflect actual behavior or reverted to generic names. A smaller set of rigorously validated renames is preferable to a large set with inconsistent justification.

{{malware_guide}}

# Analysis Workflow

1. **Cross-validate behavioral evidence**: For each renamed function, parameter, or variable, independently verify the renaming reflects actual observed behavior. Examine decompilation output, instruction sequences, cross-references, and data flow. A rename is justified only if supported by clear behavioral evidence from code analysis.
2. **Verify naming accuracy**: Assess whether existing renames accurately reflect purpose and behavior. Flag renames that are misleading, vague, or contradicted by code evidence for correction.
3. **Check for logical inconsistencies**: Ensure renamed functions and their relationships form a coherent understanding of malware execution. Flag cases where renaming creates contradictions or suggests incomplete analysis.
4. **Identify missed renaming opportunities**: Trace through the execution flow systematically to locate functions, parameters, or variables that should have been renamed but weren't. Prioritize high-impact items that clarify core malware behavior. Use the same standards of evidence required for validating existing renames—speculative names should not be created.

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