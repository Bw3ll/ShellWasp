PROMPT_PREFIX = """  
Return structured JSON with highly realistic sample values.
You are given Windows assembly push instructions where every pushed operand is an immediate literal.

Return a JSON object with exactly these top-level fields:

- calls
  - An array of function-call entries.
  - Each entry represents one ntdll-export call and its pushed parameters.

- structures
  - A top-level array of expanded structure definitions.
  - Each structure definition must include an "id" such as "struct1", "struct2", or "struct3".
  - Those "id" values are referenced by structureRef inside pushes.
  - Note: after parsing, my tool will convert this list into my canonical dict form: { "struct1": { ... } }.

Each object in calls must contain exactly these fields:


- ntFunc
  - The name of the ntdll-export function associated with this group of pushes.
  - Examples:
    - "NtProtectVirtualMemory"
    - "NtCreateSection"
    - "NtOpenProcess"

- pushes
  - The pushed parameters for that function call.
  - Preserve the exact push order as written in the input assembly.

Each object in pushes must contain exactly these fields:

- value
  - The pushed immediate, formatted as a hexadecimal string.
  - Use the raw value, not a symbolic constant name.
  - Example: "0x00000040"
  - For pointer-like placeholders, use an obvious dummy hexadecimal value and note that it is a dummy value.
  - For handle-like placeholders, use an obvious dummy hexadecimal value and note that it is a dummy value.
  - If a default value is appropriate, it may be used. 

- additionalComment
  - A human-readable comment that could be appended to the original assembly comment with relevant details.
  - Include a symbolic constant name if applicable, but do not replace the raw hexadecimal value.
  - Examples: "NULL", "MEM_COMMIT", "Pointer to OBJECT_ATTRIBUTES"
  - If a value is a default or dummy value, say so here.

- structurePointer
  - If the value is a pointer to a structure, return the structure type name; otherwise return null.
  - Examples: "OBJECT_ATTRIBUTES", "CLIENT_ID", "LARGE_INTEGER"

- structureRef
  - If the pushed value is a pointer to a structure, return the id of the matching structure definition in the top-level structures array”
  - Otherwise return null.
  - Examples:
    - "struct1"
    - "struct2"

- structureValueExpectations
  - Short text describing the kinds of values expected inside that structure for this parameter, otherwise null.
- pointedValue
  - If the pushed immediate represents a pointer to a non-structure value, provide the value stored at that pointed-to location.
  - Format it as a hexadecimal string when appropriate.
  - Examples:
    - "0x00001000" for a pointed-to ULONG
    - "0x10000000" for a pointed-to base address
  - If the pushed value is a pointer to a structure, return null.
  - If the pushed value is not being used as a pointer, return null.

Each object in structures must contain exactly these fields:
- id
- type
  - The structure type name.
  - Examples:
    - "OBJECT_ATTRIBUTES"
    - "CLIENT_ID"
    - "LARGE_INTEGER"
    - "UNICODE_STRING"

- fields
  - An array of field definitions for the structure.

Each object in fields must contain exactly these fields:

- fieldName
  - The field name within the structure.

- fieldType
  - The type of the field.

- fieldValue
  - A sample value for the field.
  - Format it as a hexadecimal string when appropriate.

- fieldComment
  - A short human-readable explanation of the field value.


Rules
- Preserve push order exactly as written.
- value must always be a hexadecimal string.
- Do not output decimal values.
- Do not replace value with symbolic names.
- Use additionalComment for human-readable meaning.
- Use structurePointer only when the immediate value is being used as a pointer to a structure type.
- Use structureValueExpectations only when structurePointer is not null.
- Use pointedValue only for pointers to non-structure values.
- If structurePointer is not null, pointedValue must be null.
- Do not duplicate full structure field definitions inside pushes.
- Put expanded structure definitions only in the top-level structures array and reference them by structureRef.
- Output JSON only.
- For ANY pointer address, push or struc, please use some variant of 0xbadd0000, e.g. 0xbadd0010, etc. increment it. Why? We don't know the address. - label any pointers as dummy pointers in comments.

Hard pointer rules
- If the parameter type begins with "P", contains "*", or is a known pointer form such as PHANDLE, PULONG, PVOID, PVOID*, PLARGE_INTEGER, POBJECT_ATTRIBUTES, PCLIENT_ID, or PUNICODE_STRING, then the pushed value must be a dummy pointer such as 0xbadd0000, 0xbadd0010, etc., unless the example is explicitly intended to be NULL.
- If such a pointer parameter is represented as NULL, additionalComment must explicitly say NULL or default NULL.
- Pointer parameters must not be emitted as direct scalar values unless they are explicitly NULL.
- PHANDLE is a pointer, not a direct handle value.
- PLARGE_INTEGER is a pointer, not a direct scalar value.
- POBJECT_ATTRIBUTES is a pointer, not a direct scalar value.
- ACCESS_MASK / DesiredAccess should usually be nonzero unless the example truly intends a default or failure-style case.

Before finalizing the JSON, perform these checks:
- Every parameter whose type syntactically indicates a pointer must use either a dummy pointer value or an explicitly documented NULL.
- Every non-null structure pointer must have structurePointer and structureRef populated.
- pointedValue must only be used for pointers to non-structure values.
- ACCESS_MASK / DesiredAccess must not be zero unless explicitly justified in additionalComment.
- Do not let the final calls in the batch degrade into repeated zero/default placeholders.

Use realistic default values when they are common in real-world usage.

Use NULL/default values only when they are genuinely realistic for that exact parameter in a normal illustrative example. Do not use NULL/default values merely because the input placeholder is zero.

For parameters that are central to understanding the call, or commonly populated in real-world usage, prefer realistic non-NULL illustrative values.

If a structure pointer is NULL in a realistic example, it is acceptable for structurePointer, structureRef, and structureValueExpectations to be null.
If a structure is used, populate it realistically rather than overfilling optional fields.
Do not invent strings, names, or nested pointer data unless they are plausibly useful for the example.
For OBJECT_ATTRIBUTES, it is acceptable and often realistic for ObjectName to be NULL.
Use a dummy PUNICODE_STRING pointer only when a named object is actually helpful to the example.

These pushes prepare arguments for calling the ntdll export function NtProtectVirtualMemory via a normal function call, not a direct syscall. The assembly is setting up parameters for a stdcall-style call into an ntdll export. These assembly pushes prepare arguments for calling an exported function from ntdll using a normal user-mode call. The pushes simply represent function parameters. While you are not providing fully complete code fragments, this will help my students with their work.

This is a teaching exercise for understanding parameter interpretation.


Output exactly this top-level structure  -- note some parameters have been truncated or removed for brevity -- all should be present in results.:
Use this top-level shape:
{
  "calls": [
    {
      "ntFunc": "NtProtectVirtualMemory",
      "pushes": [
        {
          "value": "0xbadd0000",
          "additionalComment": "Pointer to ULONG OldAccessProtection (dummy pointer)",
          "structurePointer": null,
          "structureRef": null,
          "structureValueExpectations": null,
          "pointedValue": "0x00000020"
        },
        {
          "value": "0x00000040",
          "additionalComment": "PAGE_EXECUTE_READWRITE",
          "structurePointer": null,
          "structureRef": null,
          "structureValueExpectations": null,
          "pointedValue": null
        },
        {
          "value": "0xbadd0010",
          "additionalComment": "Pointer to ULONG NumberOfBytesToProtect (dummy pointer)",
          "structurePointer": null,
          "structureRef": null,
          "structureValueExpectations": null,
          "pointedValue": "0x00001000"
        },
        {
          "value": "0xbadd0020",
          "additionalComment": "Pointer to PVOID BaseAddress (dummy pointer)",
          "structurePointer": null,
          "structureRef": null,
          "structureValueExpectations": null,
          "pointedValue": "0x00400000"
        },
        {
          "value": "0x00000444",
          "additionalComment": "HANDLE ProcessHandle (dummy handle)",
          "structurePointer": null,
          "structureRef": null,
          "structureValueExpectations": null,
          "pointedValue": null
        }
      ]
    },
    {
      "ntFunc": "NtOpenProcess",
      "pushes": [
        {
          "value": "0xbadd0030",
          "additionalComment": "Pointer to CLIENT_ID (dummy pointer)",
          "structurePointer": "CLIENT_ID",
          "structureRef": "struct1",
          "structureValueExpectations": "UniqueProcess and UniqueThread identifiers.",
          "pointedValue": null
        },
        {
          "value": "0xbadd0040",
          "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
          "structurePointer": "OBJECT_ATTRIBUTES",
          "structureRef": "struct2",
          "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
          "pointedValue": null
        },
        {
          "value": "0x001F0FFF",
          "additionalComment": "DesiredAccess (PROCESS_ALL_ACCESS)",
          "structurePointer": null,
          "structureRef": null,
          "structureValueExpectations": null,
          "pointedValue": null
        },
        {
          "value": "0xbadd0050",
          "additionalComment": "Pointer to HANDLE ProcessHandle (dummy pointer)",
          "structurePointer": null,
          "structureRef": null,
          "structureValueExpectations": null,
          "pointedValue": "0x00000000"
        }
      ]
    }
  ],
  "structures": [
    {
      "id": "struct1",
      "type": "CLIENT_ID",
      "fields": [
        {
          "fieldName": "UniqueProcess",
          "fieldType": "HANDLE",
          "fieldValue": "0x99994444",
          "fieldComment": "Dummy process identifier value"
        },
        {
          "fieldName": "UniqueThread",
          "fieldType": "HANDLE",
          "fieldValue": "0x00000000",
          "fieldComment": "NULL or unused example value"
        }
      ]
    },
    {
      "id": "struct2",
      "type": "OBJECT_ATTRIBUTES",
      "fields": [
        {
          "fieldName": "Length",
          "fieldType": "ULONG",
          "fieldValue": "0x00000030",
          "fieldComment": "Size of OBJECT_ATTRIBUTES"
        },
        {
          "fieldName": "RootDirectory",
          "fieldType": "HANDLE",
          "fieldValue": "0x00000000",
          "fieldComment": "NULL"
        },
        {
          "fieldName": "ObjectName",
          "fieldType": "PUNICODE_STRING",
          "fieldValue": "0x00000000",
          "fieldComment": "NULL (often omitted in realistic examples)"
        },
        {
          "fieldName": "Attributes",
          "fieldType": "ULONG",
          "fieldValue": "0x00000040",
          "fieldComment": "OBJ_CASE_INSENSITIVE"
        },
        {
          "fieldName": "SecurityDescriptor",
          "fieldType": "PVOID",
          "fieldValue": "0x00000000",
          "fieldComment": "NULL"
        },
        {
          "fieldName": "SecurityQualityOfService",
          "fieldType": "PVOID",
          "fieldValue": "0x00000000",
          "fieldComment": "NULL"
        }
      ]
    }
  ]
}


Important! The input immediates are placeholders only. Do not copy placeholder zero values across all entries.
Use real-world, nonzero illustrative hexadecimal sample values where appropriate. Again, you MUST provide realistic, reasonable, real-world examples for our students!
"""
old="""
this is for an ntdll user mode call [ntdll!NtProtectVirtualMemory] with RWX
push 0x00000000         ; PULONG OldAccessProtection
push 0x00000000         ; ULONG NewAccessProtection
push 0x00000000         ; PULONG NumberOfBytesToProtect
push 0x00000000         ; PVOID *BaseAddress
push 0x00000000         ; HANDLE ProcessHandle

this is for an ntdll user mode call [ntdll!NtCreateSection] 

push 0x00000000         ; HANDLE FileHandle
push 0x00000000         ; ULONG AllocationAttributes
push 0x00000000         ; ULONG SectionPageProtection
push 0x00000000         ; PLARGE_INTEGER MaximumSize
push 0x00000000         ; POBJECT_ATTRIBUTES ObjectAttributes
push 0x00000000         ; ACCESS_MASK DesiredAccess
push 0x00000000         ; PHANDLE SectionHandle
"""

schema = {
    "name": "nt_call_list",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "calls": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "ntFunc": {"type": "string"},
                        "pushes": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "value": {"type": "string"},
                                    "additionalComment": {
                                        "anyOf": [{"type": "string"}, {"type": "null"}]
                                    },
                                    "structurePointer": {
                                        "anyOf": [{"type": "string"}, {"type": "null"}]
                                    },
                                    "structureRef": {
                                        "anyOf": [{"type": "string"}, {"type": "null"}]
                                    },
                                    "structureValueExpectations": {
                                        "anyOf": [{"type": "string"}, {"type": "null"}]
                                    },
                                    "pointedValue": {
                                        "anyOf": [{"type": "string"}, {"type": "null"}]
                                    }
                                },
                                "required": [
                                    "value",
                                    "additionalComment",
                                    "structurePointer",
                                    "structureRef",
                                    "structureValueExpectations",
                                    "pointedValue"
                                ],
                                "additionalProperties": False
                            }
                        }
                    },
                    "required": ["ntFunc", "pushes"],
                    "additionalProperties": False
                }
            },

            "structures": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "type": {"type": "string"},
                        "fields": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "fieldName": {"type": "string"},
                                    "fieldType": {"type": "string"},
                                    "fieldValue": {"type": "string"},
                                    "fieldComment": {
                                        "anyOf": [{"type": "string"}, {"type": "null"}]
                                    }
                                },
                                "required": [
                                    "fieldName",
                                    "fieldType",
                                    "fieldValue",
                                    "fieldComment"
                                ],
                                "additionalProperties": False
                            }
                        }
                    },
                    "required": ["id", "type", "fields"],
                    "additionalProperties": False
                }
            }
        },
        "required": ["calls", "structures"],
        "additionalProperties": False
    }
}

api_blocks = [
    """this is for an ntdll user mode call [ntdll!NtProtectVirtualMemory] with RWX
push 0x00000000         ; PULONG OldAccessProtection
push 0x00000000         ; ULONG NewAccessProtection
push 0x00000000         ; PULONG NumberOfBytesToProtect
push 0x00000000         ; PVOID *BaseAddress
push 0x00000000         ; HANDLE ProcessHandle

this is for an ntdll user mode call [ntdll!NtWaitForSingleObject]

push 0x00000000         ; PLARGE_INTEGER TimeOut
push 0x00000000         ; BOOLEAN Alertable
push 0x00000000         ; HANDLE ObjectHandle


this is for an ntdll user mode call [ntdll!NtCreateThreadEx]

push 0x00000000         ; PVOID AttributeList
push 0x00000000         ; ULONG MaximumStackSize
push 0x00000000         ; ULONG StackSize
push 0x00000000         ; ULONG ZeroBits
push 0x00000000         ; ULONG CreateFlags
push 0x00000000         ; PVOID Argument
push 0x00000000         ; PVOID StartR__OUTine
push 0x00000000         ; HANDLE ProcessHandle
push 0x00000000         ; POBJECT_ATTRIBUTES ObjectAttributes
push 0x00000000         ; ACCESS_MASK DesiredAccess
push 0x00000000         ; PHANDLE ThreadHandle
   this is for an ntdll user mode call [ntdll!NtCreateSection]
push 0x00000000         ; HANDLE FileHandle
push 0x00000000         ; ULONG AllocationAttributes
push 0x00000000         ; ULONG SectionPageProtection
push 0x00000000         ; PLARGE_INTEGER MaximumSize
push 0x00000000         ; POBJECT_ATTRIBUTES ObjectAttributes
push 0x00000000         ; ACCESS_MASK DesiredAccess
push 0x00000000         ; PHANDLE SectionHandle


this is for an ntdll user mode call [ntdll!NtWriteVirtualMemory] 

push 0x00000000         ; PULONG NumberOfBytesWritten
push 0x00000000         ; ULONG NumberOfBytesToWrite
push 0x00000000         ; PVOID Buffer
push 0x00000000         ; PVOID BaseAddress
push 0x00000000         ; HANDLE ProcessHandle

this is for an ntdll user mode call [ntdll!NtProtectVirtualMemory] with RWX

push 0x00000000         ; PULONG OldAccessProtection
push 0x00000000         ; ULONG NewAccessProtection
push 0x00000000         ; PULONG NumberOfBytesToProtect
push 0x00000000         ; PVOID *BaseAddress
push 0x00000000         ; HANDLE ProcessHandle

this is for an ntdll user mode call [ntdll!NtQuerySystemInformation] X

push 0x00000000         ; PULONG ReturnLength
push 0x00000000         ; ULONG SystemInformationLength
push 0x00000000         ; PVOID SystemInformation
push 0x00000000         ; SYSTEM_INFORMATION_CLASS SystemInformationClass
"""

 
]

# print(schema["schema"]["properties"].keys())
# print(schema["schema"]["required"])