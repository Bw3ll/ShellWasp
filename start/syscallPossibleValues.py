
syscallPossibleValues = {
  "NtWorkerFactoryWorkerReady": {
    "ntFunc": "NtWorkerFactoryWorkerReady",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE WorkerFactoryHandle (None, typical for test or error path)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtMapUserPhysicalPagesScatter": {
    "ntFunc": "NtMapUserPhysicalPagesScatter",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PULONG_PTR UserPfnArray (None, no physical pages mapped)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG_PTR NumberOfPages (0, no pages to map)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID VirtualAddresses (None, no virtual addresses provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtWaitForMultipleObjects32": {
    "ntFunc": "NtWaitForMultipleObjects32",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PLARGE_INTEGER Time_Out (None, wait indefinitely)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN Alertable (FALSE, not alertable)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "WAIT_TYPE WaitType (WaitAll, default value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PLONG Handles (None, no handles provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG ObjectCount (0, no objects to wait for)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtReplyWaitReceivePortEx": {
    "ntFunc": "NtReplyWaitReceivePortEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PLARGE_INTEGER Time_Out (None, wait indefinitely)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PPORT_MESSAGE ReceiveMessage (None, no receive message buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PPORT_MESSAGE ReplyMessage (None, no reply message buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID PortContext (None, no port context)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE PortHandle (None, no port handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryDefaultUILanguage": {
    "ntFunc": "NtQueryDefaultUILanguage",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "LANGID DefaultUILanguageId (None, output parameter, will be filled by function)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtApphelpCacheControl": {
    "ntFunc": "NtApphelpCacheControl",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None ServiceContext (no context provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "AHC_SERVICE_CLASS ServiceClass (e.g., ApphelpCheckExe)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateProcessEx": {
    "ntFunc": "NtCreateProcessEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN InJob (FALSE, not in job)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE ExceptionPort (None, no exception port)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE DebugPort (None, no debug port)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "HANDLE SectionHandle (dummy handle, e.g., section for image)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN InheritObjectTable (TRUE, inherit handles)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ParentProcess (dummy handle, e.g., current process)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct1",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F0FFF",
        "additionalComment": "ACCESS_MASK DesiredAccess (PROCESS_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to HANDLE ProcessHandle (dummy pointer, receives new process handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct1": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (no name)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtIsProcessInJob": {
    "ntFunc": "NtIsProcessInJob",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE JobHandle (None, current job)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle, e.g., current process)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAccessCheckByTypeAndAuditAlarm": {
    "ntFunc": "NtAccessCheckByTypeAndAuditAlarm",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to BOOLEAN GenerateOnClose (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to NTSTATUS (dummy pointer, receives status)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to ACCESS_MASK GrantedAccess (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN ObjectCreation (FALSE, not object creation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to GENERIC_MAPPING (dummy pointer)",
        "structurePointer": "GENERIC_MAPPING",
        "structureRef": "struct2",
        "structureValueExpectations": "GENERIC_READ/WRITE/EXECUTE/ALL mappings.",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG ObjectTypeListLength (1 object type)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to OBJECT_TYPE_LIST (dummy pointer)",
        "structurePointer": "OBJECT_TYPE_LIST",
        "structureRef": "struct3",
        "structureValueExpectations": "Array of object type entries.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Flags (no flags)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "AUDIT_EVENT_TYPE AuditType (ObjectAccess)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00120089",
        "additionalComment": "ACCESS_MASK DesiredAccess (e.g., READ_CONTROL | WRITE_DAC)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to SID PrincipalSelfSid (dummy pointer)",
        "structurePointer": "SID",
        "structureRef": "struct4",
        "structureValueExpectations": "SID structure for principal.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to SECURITY_DESCRIPTOR (dummy pointer)",
        "structurePointer": "SECURITY_DESCRIPTOR",
        "structureRef": "struct5",
        "structureValueExpectations": "Security descriptor for object.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PUNICODE_STRING ObjectName (None, no name)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PUNICODE_STRING ObjectTypeName (None, no type name)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID HandleId (None, not used)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00a0",
        "additionalComment": "Pointer to UNICODE_STRING SubsystemName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct6",
        "structureValueExpectations": "Name of the subsystem.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct2": {
        "type": "GENERIC_MAPPING",
        "fields": [
          {
            "fieldName": "GenericRead",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x80000000",
            "fieldComment": "GENERIC_READ"
          },
          {
            "fieldName": "GenericWrite",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x40000000",
            "fieldComment": "GENERIC_WRITE"
          },
          {
            "fieldName": "GenericExecute",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x20000000",
            "fieldComment": "GENERIC_EXECUTE"
          },
          {
            "fieldName": "GenericAll",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x10000000",
            "fieldComment": "GENERIC_ALL"
          }
        ]
      },
      "struct3": {
        "type": "OBJECT_TYPE_LIST",
        "fields": [
          {
            "fieldName": "Level",
            "fieldType": "WORD",
            "fieldValue": "0x0000",
            "fieldComment": "Top-level object"
          },
          {
            "fieldName": "Sbz",
            "fieldType": "WORD",
            "fieldValue": "0x0000",
            "fieldComment": "Reserved"
          },
          {
            "fieldName": "ObjectType",
            "fieldType": "GUID*",
            "fieldValue": "0xbadd00c0",
            "fieldComment": "Pointer to object type GUID (dummy pointer)"
          }
        ]
      },
      "struct4": {
        "type": "SID",
        "fields": [
          {
            "fieldName": "Revision",
            "fieldType": "BYTE",
            "fieldValue": "0x01",
            "fieldComment": "SID revision"
          },
          {
            "fieldName": "SubAuthorityCount",
            "fieldType": "BYTE",
            "fieldValue": "0x01",
            "fieldComment": "One subauthority"
          },
          {
            "fieldName": "IdentifierAuthority",
            "fieldType": "BYTE[6]",
            "fieldValue": "0x000000000005",
            "fieldComment": "NT Authority"
          },
          {
            "fieldName": "SubAuthority[0]",
            "fieldType": "ULONG",
            "fieldValue": "0x00000020",
            "fieldComment": "Local system"
          }
        ]
      },
      "struct5": {
        "type": "SECURITY_DESCRIPTOR",
        "fields": [
          {
            "fieldName": "Revision",
            "fieldType": "BYTE",
            "fieldValue": "0x01",
            "fieldComment": "Revision"
          },
          {
            "fieldName": "Sbz1",
            "fieldType": "BYTE",
            "fieldValue": "0x00",
            "fieldComment": "Reserved"
          },
          {
            "fieldName": "Control",
            "fieldType": "SECURITY_DESCRIPTOR_CONTROL",
            "fieldValue": "0x8004",
            "fieldComment": "SE_DACL_PRESENT | SE_SELF_RELATIVE"
          },
          {
            "fieldName": "Owner",
            "fieldType": "PSID",
            "fieldValue": "0xbadd00d0",
            "fieldComment": "Pointer to owner SID (dummy pointer)"
          },
          {
            "fieldName": "Group",
            "fieldType": "PSID",
            "fieldValue": "0xbadd00e0",
            "fieldComment": "Pointer to group SID (dummy pointer)"
          },
          {
            "fieldName": "Sacl",
            "fieldType": "PACL",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          },
          {
            "fieldName": "Dacl",
            "fieldType": "PACL",
            "fieldValue": "0xbadd00f0",
            "fieldComment": "Pointer to DACL (dummy pointer)"
          }
        ]
      },
      "struct6": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0014",
            "fieldComment": "20 bytes (10 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "32 bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0100",
            "fieldComment": "Pointer to subsystem name string (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtTraceEvent": {
    "ntFunc": "NtTraceEvent",
    "pushes": [
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to event fields buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000020",
        "additionalComment": "ULONG FieldSize (32 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG Flags (e.g., TRACE_EVENT_FLAG_CRITICAL)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE TraceHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtPowerInformation": {
    "ntFunc": "NtPowerInformation",
    "pushes": [
      {
        "value": "0x00000010",
        "additionalComment": "ULONG OutputBufferLength (typical small buffer size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to OutputBuffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000008",
        "additionalComment": "ULONG InputBufferLength (typical small input buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to InputBuffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x0000000c",
        "additionalComment": "POWER_INFORMATION_LEVEL InformationLevel (SystemPowerInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAccessCheckByType": {
    "ntFunc": "NtAccessCheckByType",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to NTSTATUS ReturnStatus (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to ACCESS_MASK GrantedAccess (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to ULONG PrivilegeSetLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to PRIVILEGE_SET (dummy pointer)",
        "structurePointer": "PRIVILEGE_SET",
        "structureRef": "struct7",
        "structureValueExpectations": "PrivilegeCount, Control, array of LUID_AND_ATTRIBUTES.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to GENERIC_MAPPING (dummy pointer)",
        "structurePointer": "GENERIC_MAPPING",
        "structureRef": "struct8",
        "structureValueExpectations": "GenericRead, GenericWrite, GenericExecute, GenericAll masks.",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG ObjectTypeListLength (single object type)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to OBJECT_TYPE_LIST (dummy pointer)",
        "structurePointer": "OBJECT_TYPE_LIST",
        "structureRef": "struct9",
        "structureValueExpectations": "Level, Sbz, Type pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00020019",
        "additionalComment": "ACCESS_MASK DesiredAccess (GENERIC_READ | GENERIC_EXECUTE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ClientToken (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to SID PrincipalSelfSid (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x01020300"
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to SECURITY_DESCRIPTOR (dummy pointer)",
        "structurePointer": "SECURITY_DESCRIPTOR",
        "structureRef": "struct10",
        "structureValueExpectations": "Revision, Control, Owner, Group, SACL, DACL.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct7": {
        "type": "PRIVILEGE_SET",
        "fields": [
          {
            "fieldName": "PrivilegeCount",
            "fieldType": "DWORD",
            "fieldValue": "0x00000001",
            "fieldComment": "One privilege in set"
          },
          {
            "fieldName": "Control",
            "fieldType": "DWORD",
            "fieldValue": "0x00000001",
            "fieldComment": "SE_PRIVILEGE_ENABLED"
          },
          {
            "fieldName": "Privilege[0].Luid.LowPart",
            "fieldType": "DWORD",
            "fieldValue": "0x00000017",
            "fieldComment": "LUID for SeDebugPrivilege"
          },
          {
            "fieldName": "Privilege[0].Luid.HighPart",
            "fieldType": "LONG",
            "fieldValue": "0x00000000",
            "fieldComment": "High part of LUID"
          },
          {
            "fieldName": "Privilege[0].Attributes",
            "fieldType": "DWORD",
            "fieldValue": "0x00000002",
            "fieldComment": "SE_PRIVILEGE_ENABLED"
          }
        ]
      },
      "struct8": {
        "type": "GENERIC_MAPPING",
        "fields": [
          {
            "fieldName": "GenericRead",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x80000000",
            "fieldComment": "GENERIC_READ"
          },
          {
            "fieldName": "GenericWrite",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x40000000",
            "fieldComment": "GENERIC_WRITE"
          },
          {
            "fieldName": "GenericExecute",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x20000000",
            "fieldComment": "GENERIC_EXECUTE"
          },
          {
            "fieldName": "GenericAll",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x10000000",
            "fieldComment": "GENERIC_ALL"
          }
        ]
      },
      "struct9": {
        "type": "OBJECT_TYPE_LIST",
        "fields": [
          {
            "fieldName": "Level",
            "fieldType": "WORD",
            "fieldValue": "0x0001",
            "fieldComment": "Object type level"
          },
          {
            "fieldName": "Sbz",
            "fieldType": "WORD",
            "fieldValue": "0x0000",
            "fieldComment": "Reserved"
          },
          {
            "fieldName": "Type",
            "fieldType": "POINTER",
            "fieldValue": "0xbadd0300",
            "fieldComment": "Pointer to object type GUID (dummy pointer)"
          }
        ]
      },
      "struct10": {
        "type": "SECURITY_DESCRIPTOR",
        "fields": [
          {
            "fieldName": "Revision",
            "fieldType": "BYTE",
            "fieldValue": "0x01",
            "fieldComment": "SECURITY_DESCRIPTOR_REVISION"
          },
          {
            "fieldName": "Sbz1",
            "fieldType": "BYTE",
            "fieldValue": "0x00",
            "fieldComment": "Reserved"
          },
          {
            "fieldName": "Control",
            "fieldType": "WORD",
            "fieldValue": "0x8004",
            "fieldComment": "SE_DACL_PRESENT | SE_SELF_RELATIVE"
          },
          {
            "fieldName": "Owner",
            "fieldType": "PSID",
            "fieldValue": "0xbadd0310",
            "fieldComment": "Pointer to owner SID (dummy pointer)"
          },
          {
            "fieldName": "Group",
            "fieldType": "PSID",
            "fieldValue": "0xbadd0320",
            "fieldComment": "Pointer to group SID (dummy pointer)"
          },
          {
            "fieldName": "Sacl",
            "fieldType": "PACL",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          },
          {
            "fieldName": "Dacl",
            "fieldType": "PACL",
            "fieldValue": "0xbadd0330",
            "fieldComment": "Pointer to DACL (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtAccessCheckByTypeResultList": {
    "ntFunc": "NtAccessCheckByTypeResultList",
    "pushes": [
      {
        "value": "0xbadd00a0",
        "additionalComment": "Pointer to NTSTATUS ReturnStatus (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to ACCESS_MASK GrantedAccess (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0xbadd00c0",
        "additionalComment": "Pointer to ULONG PrivilegeSetLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0xbadd00d0",
        "additionalComment": "Pointer to PRIVILEGE_SET (dummy pointer)",
        "structurePointer": "PRIVILEGE_SET",
        "structureRef": "struct7",
        "structureValueExpectations": "PrivilegeCount, Control, array of LUID_AND_ATTRIBUTES.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00e0",
        "additionalComment": "Pointer to GENERIC_MAPPING (dummy pointer)",
        "structurePointer": "GENERIC_MAPPING",
        "structureRef": "struct8",
        "structureValueExpectations": "GenericRead, GenericWrite, GenericExecute, GenericAll masks.",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG ObjectTypeListLength (single object type)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00f0",
        "additionalComment": "Pointer to OBJECT_TYPE_LIST (dummy pointer)",
        "structurePointer": "OBJECT_TYPE_LIST",
        "structureRef": "struct9",
        "structureValueExpectations": "Level, Sbz, Type pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00020019",
        "additionalComment": "ACCESS_MASK DesiredAccess (GENERIC_READ | GENERIC_EXECUTE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ClientToken (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0100",
        "additionalComment": "Pointer to SID PrincipalSelfSid (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x01020300"
      },
      {
        "value": "0xbadd0110",
        "additionalComment": "Pointer to SECURITY_DESCRIPTOR (dummy pointer)",
        "structurePointer": "SECURITY_DESCRIPTOR",
        "structureRef": "struct10",
        "structureValueExpectations": "Revision, Control, Owner, Group, SACL, DACL.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct7": {
        "type": "PRIVILEGE_SET",
        "fields": [
          {
            "fieldName": "PrivilegeCount",
            "fieldType": "DWORD",
            "fieldValue": "0x00000001",
            "fieldComment": "One privilege in set"
          },
          {
            "fieldName": "Control",
            "fieldType": "DWORD",
            "fieldValue": "0x00000001",
            "fieldComment": "SE_PRIVILEGE_ENABLED"
          },
          {
            "fieldName": "Privilege[0].Luid.LowPart",
            "fieldType": "DWORD",
            "fieldValue": "0x00000017",
            "fieldComment": "LUID for SeDebugPrivilege"
          },
          {
            "fieldName": "Privilege[0].Luid.HighPart",
            "fieldType": "LONG",
            "fieldValue": "0x00000000",
            "fieldComment": "High part of LUID"
          },
          {
            "fieldName": "Privilege[0].Attributes",
            "fieldType": "DWORD",
            "fieldValue": "0x00000002",
            "fieldComment": "SE_PRIVILEGE_ENABLED"
          }
        ]
      },
      "struct8": {
        "type": "GENERIC_MAPPING",
        "fields": [
          {
            "fieldName": "GenericRead",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x80000000",
            "fieldComment": "GENERIC_READ"
          },
          {
            "fieldName": "GenericWrite",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x40000000",
            "fieldComment": "GENERIC_WRITE"
          },
          {
            "fieldName": "GenericExecute",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x20000000",
            "fieldComment": "GENERIC_EXECUTE"
          },
          {
            "fieldName": "GenericAll",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x10000000",
            "fieldComment": "GENERIC_ALL"
          }
        ]
      },
      "struct9": {
        "type": "OBJECT_TYPE_LIST",
        "fields": [
          {
            "fieldName": "Level",
            "fieldType": "WORD",
            "fieldValue": "0x0001",
            "fieldComment": "Object type level"
          },
          {
            "fieldName": "Sbz",
            "fieldType": "WORD",
            "fieldValue": "0x0000",
            "fieldComment": "Reserved"
          },
          {
            "fieldName": "Type",
            "fieldType": "POINTER",
            "fieldValue": "0xbadd0300",
            "fieldComment": "Pointer to object type GUID (dummy pointer)"
          }
        ]
      },
      "struct10": {
        "type": "SECURITY_DESCRIPTOR",
        "fields": [
          {
            "fieldName": "Revision",
            "fieldType": "BYTE",
            "fieldValue": "0x01",
            "fieldComment": "SECURITY_DESCRIPTOR_REVISION"
          },
          {
            "fieldName": "Sbz1",
            "fieldType": "BYTE",
            "fieldValue": "0x00",
            "fieldComment": "Reserved"
          },
          {
            "fieldName": "Control",
            "fieldType": "WORD",
            "fieldValue": "0x8004",
            "fieldComment": "SE_DACL_PRESENT | SE_SELF_RELATIVE"
          },
          {
            "fieldName": "Owner",
            "fieldType": "PSID",
            "fieldValue": "0xbadd0310",
            "fieldComment": "Pointer to owner SID (dummy pointer)"
          },
          {
            "fieldName": "Group",
            "fieldType": "PSID",
            "fieldValue": "0xbadd0320",
            "fieldComment": "Pointer to group SID (dummy pointer)"
          },
          {
            "fieldName": "Sacl",
            "fieldType": "PACL",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          },
          {
            "fieldName": "Dacl",
            "fieldType": "PACL",
            "fieldValue": "0xbadd0330",
            "fieldComment": "Pointer to DACL (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtAccessCheckByTypeResultListAndAuditAlarm": {
    "ntFunc": "NtAccessCheckByTypeResultListAndAuditAlarm",
    "pushes": [
      {
        "value": "0xbadd0120",
        "additionalComment": "Pointer to BOOLEAN GenerateOnClose (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00"
      },
      {
        "value": "0xbadd0130",
        "additionalComment": "Pointer to NTSTATUS ReturnStatus (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0140",
        "additionalComment": "Pointer to ACCESS_MASK GrantedAccess (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00",
        "additionalComment": "BOOLEAN ObjectCreation (FALSE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0150",
        "additionalComment": "Pointer to GENERIC_MAPPING (dummy pointer)",
        "structurePointer": "GENERIC_MAPPING",
        "structureRef": "struct8",
        "structureValueExpectations": "GenericRead, GenericWrite, GenericExecute, GenericAll masks.",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG ObjectTypeListLength (single object type)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0160",
        "additionalComment": "Pointer to OBJECT_TYPE_LIST (dummy pointer)",
        "structurePointer": "OBJECT_TYPE_LIST",
        "structureRef": "struct9",
        "structureValueExpectations": "Level, Sbz, Type pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Flags (no flags set)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "AUDIT_EVENT_TYPE AuditType (ObjectAccess)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00020019",
        "additionalComment": "ACCESS_MASK DesiredAccess (GENERIC_READ | GENERIC_EXECUTE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0170",
        "additionalComment": "Pointer to SID PrincipalSelfSid (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x01020300"
      },
      {
        "value": "0xbadd0180",
        "additionalComment": "Pointer to SECURITY_DESCRIPTOR (dummy pointer)",
        "structurePointer": "SECURITY_DESCRIPTOR",
        "structureRef": "struct10",
        "structureValueExpectations": "Revision, Control, Owner, Group, SACL, DACL.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0190",
        "additionalComment": "Pointer to UNICODE_STRING ObjectName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct11",
        "structureValueExpectations": "Length, MaximumLength, Buffer pointer.",
        "pointedValue": None
      },
      {
        "value": "0xbadd01a0",
        "additionalComment": "Pointer to UNICODE_STRING ObjectTypeName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct12",
        "structureValueExpectations": "Length, MaximumLength, Buffer pointer.",
        "pointedValue": None
      },
      {
        "value": "0xbadd01b0",
        "additionalComment": "Pointer to HandleId (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0xbadd01c0",
        "additionalComment": "Pointer to UNICODE_STRING SubsystemName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct13",
        "structureValueExpectations": "Length, MaximumLength, Buffer pointer.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct8": {
        "type": "GENERIC_MAPPING",
        "fields": [
          {
            "fieldName": "GenericRead",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x80000000",
            "fieldComment": "GENERIC_READ"
          },
          {
            "fieldName": "GenericWrite",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x40000000",
            "fieldComment": "GENERIC_WRITE"
          },
          {
            "fieldName": "GenericExecute",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x20000000",
            "fieldComment": "GENERIC_EXECUTE"
          },
          {
            "fieldName": "GenericAll",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x10000000",
            "fieldComment": "GENERIC_ALL"
          }
        ]
      },
      "struct9": {
        "type": "OBJECT_TYPE_LIST",
        "fields": [
          {
            "fieldName": "Level",
            "fieldType": "WORD",
            "fieldValue": "0x0001",
            "fieldComment": "Object type level"
          },
          {
            "fieldName": "Sbz",
            "fieldType": "WORD",
            "fieldValue": "0x0000",
            "fieldComment": "Reserved"
          },
          {
            "fieldName": "Type",
            "fieldType": "POINTER",
            "fieldValue": "0xbadd0300",
            "fieldComment": "Pointer to object type GUID (dummy pointer)"
          }
        ]
      },
      "struct10": {
        "type": "SECURITY_DESCRIPTOR",
        "fields": [
          {
            "fieldName": "Revision",
            "fieldType": "BYTE",
            "fieldValue": "0x01",
            "fieldComment": "SECURITY_DESCRIPTOR_REVISION"
          },
          {
            "fieldName": "Sbz1",
            "fieldType": "BYTE",
            "fieldValue": "0x00",
            "fieldComment": "Reserved"
          },
          {
            "fieldName": "Control",
            "fieldType": "WORD",
            "fieldValue": "0x8004",
            "fieldComment": "SE_DACL_PRESENT | SE_SELF_RELATIVE"
          },
          {
            "fieldName": "Owner",
            "fieldType": "PSID",
            "fieldValue": "0xbadd0310",
            "fieldComment": "Pointer to owner SID (dummy pointer)"
          },
          {
            "fieldName": "Group",
            "fieldType": "PSID",
            "fieldValue": "0xbadd0320",
            "fieldComment": "Pointer to group SID (dummy pointer)"
          },
          {
            "fieldName": "Sacl",
            "fieldType": "PACL",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          },
          {
            "fieldName": "Dacl",
            "fieldType": "PACL",
            "fieldValue": "0xbadd0330",
            "fieldComment": "Pointer to DACL (dummy pointer)"
          }
        ]
      },
      "struct11": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "String length in bytes"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Maximum buffer size in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0340",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      },
      "struct12": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0012",
            "fieldComment": "String length in bytes"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0022",
            "fieldComment": "Maximum buffer size in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0350",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      },
      "struct13": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0014",
            "fieldComment": "String length in bytes"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0024",
            "fieldComment": "Maximum buffer size in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0360",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtAccessCheckByTypeResultListAndAuditAlarmByHandle": {
    "ntFunc": "NtAccessCheckByTypeResultListAndAuditAlarmByHandle",
    "pushes": [
      {
        "value": "0xbadd01d0",
        "additionalComment": "Pointer to BOOLEAN GenerateOnClose (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00"
      },
      {
        "value": "0xbadd01e0",
        "additionalComment": "Pointer to NTSTATUS ReturnStatus (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd01f0",
        "additionalComment": "Pointer to ACCESS_MASK GrantedAccess (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00",
        "additionalComment": "BOOLEAN ObjectCreation (FALSE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0200",
        "additionalComment": "Pointer to GENERIC_MAPPING (dummy pointer)",
        "structurePointer": "GENERIC_MAPPING",
        "structureRef": "struct8",
        "structureValueExpectations": "GenericRead, GenericWrite, GenericExecute, GenericAll masks.",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG ObjectTypeListLength (single object type)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0210",
        "additionalComment": "Pointer to OBJECT_TYPE_LIST (dummy pointer)",
        "structurePointer": "OBJECT_TYPE_LIST",
        "structureRef": "struct9",
        "structureValueExpectations": "Level, Sbz, Type pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Flags (no flags set)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "AUDIT_EVENT_TYPE AuditType (ObjectAccess)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00020019",
        "additionalComment": "ACCESS_MASK DesiredAccess (GENERIC_READ | GENERIC_EXECUTE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0220",
        "additionalComment": "Pointer to SID PrincipalSelfSid (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x01020300"
      },
      {
        "value": "0xbadd0230",
        "additionalComment": "Pointer to SECURITY_DESCRIPTOR (dummy pointer)",
        "structurePointer": "SECURITY_DESCRIPTOR",
        "structureRef": "struct10",
        "structureValueExpectations": "Revision, Control, Owner, Group, SACL, DACL.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0240",
        "additionalComment": "Pointer to UNICODE_STRING ObjectName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct11",
        "structureValueExpectations": "Length, MaximumLength, Buffer pointer.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0250",
        "additionalComment": "Pointer to UNICODE_STRING ObjectTypeName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct12",
        "structureValueExpectations": "Length, MaximumLength, Buffer pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ClientToken (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0260",
        "additionalComment": "Pointer to HandleId (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0xbadd0270",
        "additionalComment": "Pointer to UNICODE_STRING SubsystemName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct13",
        "structureValueExpectations": "Length, MaximumLength, Buffer pointer.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct8": {
        "type": "GENERIC_MAPPING",
        "fields": [
          {
            "fieldName": "GenericRead",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x80000000",
            "fieldComment": "GENERIC_READ"
          },
          {
            "fieldName": "GenericWrite",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x40000000",
            "fieldComment": "GENERIC_WRITE"
          },
          {
            "fieldName": "GenericExecute",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x20000000",
            "fieldComment": "GENERIC_EXECUTE"
          },
          {
            "fieldName": "GenericAll",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x10000000",
            "fieldComment": "GENERIC_ALL"
          }
        ]
      },
      "struct9": {
        "type": "OBJECT_TYPE_LIST",
        "fields": [
          {
            "fieldName": "Level",
            "fieldType": "WORD",
            "fieldValue": "0x0001",
            "fieldComment": "Object type level"
          },
          {
            "fieldName": "Sbz",
            "fieldType": "WORD",
            "fieldValue": "0x0000",
            "fieldComment": "Reserved"
          },
          {
            "fieldName": "Type",
            "fieldType": "POINTER",
            "fieldValue": "0xbadd0300",
            "fieldComment": "Pointer to object type GUID (dummy pointer)"
          }
        ]
      },
      "struct10": {
        "type": "SECURITY_DESCRIPTOR",
        "fields": [
          {
            "fieldName": "Revision",
            "fieldType": "BYTE",
            "fieldValue": "0x01",
            "fieldComment": "SECURITY_DESCRIPTOR_REVISION"
          },
          {
            "fieldName": "Sbz1",
            "fieldType": "BYTE",
            "fieldValue": "0x00",
            "fieldComment": "Reserved"
          },
          {
            "fieldName": "Control",
            "fieldType": "WORD",
            "fieldValue": "0x8004",
            "fieldComment": "SE_DACL_PRESENT | SE_SELF_RELATIVE"
          },
          {
            "fieldName": "Owner",
            "fieldType": "PSID",
            "fieldValue": "0xbadd0310",
            "fieldComment": "Pointer to owner SID (dummy pointer)"
          },
          {
            "fieldName": "Group",
            "fieldType": "PSID",
            "fieldValue": "0xbadd0320",
            "fieldComment": "Pointer to group SID (dummy pointer)"
          },
          {
            "fieldName": "Sacl",
            "fieldType": "PACL",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          },
          {
            "fieldName": "Dacl",
            "fieldType": "PACL",
            "fieldValue": "0xbadd0330",
            "fieldComment": "Pointer to DACL (dummy pointer)"
          }
        ]
      },
      "struct11": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "String length in bytes"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Maximum buffer size in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0340",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      },
      "struct12": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0012",
            "fieldComment": "String length in bytes"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0022",
            "fieldComment": "Maximum buffer size in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0350",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      },
      "struct13": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0014",
            "fieldComment": "String length in bytes"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0024",
            "fieldComment": "Maximum buffer size in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0360",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtAddAtomEx": {
    "ntFunc": "NtAddAtomEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Flags (default: 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to RTL_ATOM (optional, None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000000C",
        "additionalComment": "Length of AtomName in bytes (example: 12 bytes for 'TestAtom')",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to AtomName (PWSTR, dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd1000"
      }
    ],
    "structures": {}
  },
  "NtAddBootEntry": {
    "ntFunc": "NtAddBootEntry",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to ULONG (optional, None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to BOOT_ENTRY (dummy pointer)",
        "structurePointer": "BOOT_ENTRY",
        "structureRef": "struct14",
        "structureValueExpectations": "Boot entry structure with identifier, attributes, and file path.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct14": {
        "type": "BOOT_ENTRY",
        "fields": [
          {
            "fieldName": "Version",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Version 1"
          },
          {
            "fieldName": "Length",
            "fieldType": "ULONG",
            "fieldValue": "0x00000100",
            "fieldComment": "Size of BOOT_ENTRY"
          },
          {
            "fieldName": "Id",
            "fieldType": "ULONG",
            "fieldValue": "0x00000010",
            "fieldComment": "Boot entry identifier"
          },
          {
            "fieldName": "Attributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Active attribute"
          },
          {
            "fieldName": "FriendlyNameOffset",
            "fieldType": "ULONG",
            "fieldValue": "0x00000040",
            "fieldComment": "Offset to friendly name"
          },
          {
            "fieldName": "BootFilePathOffset",
            "fieldType": "ULONG",
            "fieldValue": "0x00000080",
            "fieldComment": "Offset to boot file path"
          }
        ]
      }
    }
  },
  "NtAddDriverEntry": {
    "ntFunc": "NtAddDriverEntry",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to ULONG (optional, None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to EFI_DRIVER_ENTRY (dummy pointer)",
        "structurePointer": "EFI_DRIVER_ENTRY",
        "structureRef": "struct15",
        "structureValueExpectations": "EFI driver entry structure with version, attributes, and file path.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct15": {
        "type": "EFI_DRIVER_ENTRY",
        "fields": [
          {
            "fieldName": "Version",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Version 1"
          },
          {
            "fieldName": "Length",
            "fieldType": "ULONG",
            "fieldValue": "0x00000080",
            "fieldComment": "Size of EFI_DRIVER_ENTRY"
          },
          {
            "fieldName": "Id",
            "fieldType": "ULONG",
            "fieldValue": "0x00000020",
            "fieldComment": "Driver entry identifier"
          },
          {
            "fieldName": "Attributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Active attribute"
          },
          {
            "fieldName": "FriendlyNameOffset",
            "fieldType": "ULONG",
            "fieldValue": "0x00000030",
            "fieldComment": "Offset to friendly name"
          },
          {
            "fieldName": "DriverFilePathOffset",
            "fieldType": "ULONG",
            "fieldValue": "0x00000050",
            "fieldComment": "Offset to driver file path"
          }
        ]
      }
    }
  },
  "NtAdjustTokenClaimsAndDeviceGroups": {
    "ntFunc": "NtAdjustTokenClaimsAndDeviceGroups",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to ULONG (optional, None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to ULONG (optional, None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to ULONG (optional, None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to TOKEN_GROUPS PreviousDeviceGroups (optional, None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "DeviceGroupsBufferLength (default: 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to TOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousDeviceState (optional, None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "DeviceBufferLength (default: 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to TOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousUserState (optional, None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "UserBufferLength (default: 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to TOKEN_GROUPS NewDeviceGroupsState (optional, None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to TOKEN_SECURITY_ATTRIBUTES_INFORMATION NewDeviceState (optional, None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to TOKEN_SECURITY_ATTRIBUTES_INFORMATION NewUserState (optional, None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00",
        "additionalComment": "DeviceGroupsResetToDefault (BOOLEAN, FALSE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00",
        "additionalComment": "DeviceResetToDefault (BOOLEAN, FALSE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00",
        "additionalComment": "UserResetToDefault (BOOLEAN, FALSE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "TokenHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAlertThreadByThreadId": {
    "ntFunc": "NtAlertThreadByThreadId",
    "pushes": [
      {
        "value": "0x00001234",
        "additionalComment": "Thread ID (example: 0x1234)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAllocateReserveObject": {
    "ntFunc": "NtAllocateReserveObject",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "MEMORY_RESERVE_TYPE Type (MemoryReserveObject)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES ObjectAttributes (None, typical for unnamed reserve objects)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to HANDLE MemoryReserveHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000444"
      }
    ],
    "structures": {}
  },
  "NtGetNextProcess": {
    "ntFunc": "NtGetNextProcess",
    "pushes": [
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to HANDLE NewProcessHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Flags (0, typical for default enumeration)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000040",
        "additionalComment": "ULONG HandleAttributes (OBJ_CASE_INSENSITIVE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00100000",
        "additionalComment": "ACCESS_MASK DesiredAccess (PROCESS_QUERY_LIMITED_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle, start from None for first call)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtGetNextThread": {
    "ntFunc": "NtGetNextThread",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to HANDLE NewThreadHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Flags (0, typical for default enumeration)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000040",
        "additionalComment": "ULONG HandleAttributes (OBJ_CASE_INSENSITIVE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00100000",
        "additionalComment": "ACCESS_MASK DesiredAccess (THREAD_QUERY_LIMITED_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE ThreadHandle (None for first thread enumeration)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle, process whose threads are being enumerated)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueueApcThreadEx": {
    "ntFunc": "NtQueueApcThreadEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PVOID ApcArgument3 (None, typical for unused argument)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID ApcArgument2 (None, typical for unused argument)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID ApcArgument1 (None, typical for unused argument)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "PPS_APC_ROUTINE ApcRoutine (dummy function pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE UserApcReserveHandle (None, typical usage)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ThreadHandle (dummy handle, target thread)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtUmsThreadYield": {
    "ntFunc": "NtUmsThreadYield",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PVOID SchedulerParam (None, typical usage)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAllocateUserPhysicalPages": {
    "ntFunc": "NtAllocateUserPhysicalPages",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG_PTR UserPfnArray (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to ULONG_PTR NumberOfPages (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAllocateVirtualMemoryEx": {
    "ntFunc": "NtAllocateVirtualMemoryEx",
    "pushes": [
      {
        "value": "0x00000002",
        "additionalComment": "ULONG ExtendedParameterCount (example: 2 parameters)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to MEM_EXTENDED_PARAMETER array (dummy pointer)",
        "structurePointer": "MEM_EXTENDED_PARAMETER",
        "structureRef": "struct16",
        "structureValueExpectations": "Array of MEM_EXTENDED_PARAMETER structures describing extended allocation options.",
        "pointedValue": None
      },
      {
        "value": "0x00000040",
        "additionalComment": "ULONG PageProtection (PAGE_EXECUTE_READWRITE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG AllocationType (MEM_COMMIT)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to SIZE_T RegionSize (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00020000"
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to PVOID BaseAddress (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00400000"
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct16": {
        "type": "MEM_EXTENDED_PARAMETER",
        "fields": [
          {
            "fieldName": "Type",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "MEM_EXTENDED_PARAMETER_TYPE"
          },
          {
            "fieldName": "Reserved",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Reserved, must be zero"
          },
          {
            "fieldName": "ULong64",
            "fieldType": "ULONG64",
            "fieldValue": "0x0000000000000001",
            "fieldComment": "Sample value for extended parameter"
          }
        ]
      }
    }
  },
  "NtAlpcAcceptConnectPort": {
    "ntFunc": "NtAlpcAcceptConnectPort",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN AcceptConnection (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to ALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes (dummy pointer)",
        "structurePointer": "ALPC_MESSAGE_ATTRIBUTES",
        "structureRef": "struct17",
        "structureValueExpectations": "Attributes for the connection message.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to PORT_MESSAGE ConnectionRequest (dummy pointer)",
        "structurePointer": "PORT_MESSAGE",
        "structureRef": "struct18",
        "structureValueExpectations": "PORT_MESSAGE structure describing the connection request.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to PortContext (dummy pointer, context value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to ALPC_PORT_ATTRIBUTES PortAttributes (dummy pointer)",
        "structurePointer": "ALPC_PORT_ATTRIBUTES",
        "structureRef": "struct19",
        "structureValueExpectations": "Attributes for the new port.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES ObjectAttributes (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct20",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Flags (default: 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ConnectionPortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00a0",
        "additionalComment": "Pointer to HANDLE PortHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct17": {
        "type": "ALPC_MESSAGE_ATTRIBUTES",
        "fields": [
          {
            "fieldName": "AllocatedAttributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Sample attribute flag"
          },
          {
            "fieldName": "ValidAttributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Sample valid attribute"
          }
        ]
      },
      "struct18": {
        "type": "PORT_MESSAGE",
        "fields": [
          {
            "fieldName": "u1.Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Message length"
          },
          {
            "fieldName": "u1.ZeroInit",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "Zero-initialized"
          },
          {
            "fieldName": "u2.Type",
            "fieldType": "USHORT",
            "fieldValue": "0x0001",
            "fieldComment": "Message type"
          },
          {
            "fieldName": "u2.DataInfoOffset",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "No data info"
          },
          {
            "fieldName": "ClientId.UniqueProcess",
            "fieldType": "HANDLE",
            "fieldValue": "0x99994444",
            "fieldComment": "Dummy process ID"
          },
          {
            "fieldName": "ClientId.UniqueThread",
            "fieldType": "HANDLE",
            "fieldValue": "0x00000000",
            "fieldComment": "Dummy thread ID"
          },
          {
            "fieldName": "MessageId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Sample message ID"
          },
          {
            "fieldName": "ClientViewSize",
            "fieldType": "SIZE_T",
            "fieldValue": "0x00000000",
            "fieldComment": "No client view"
          }
        ]
      },
      "struct19": {
        "type": "ALPC_PORT_ATTRIBUTES",
        "fields": [
          {
            "fieldName": "Flags",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Sample flag"
          },
          {
            "fieldName": "SecurityQos.Length",
            "fieldType": "ULONG",
            "fieldValue": "0x0000000C",
            "fieldComment": "SECURITY_QUALITY_OF_SERVICE length"
          },
          {
            "fieldName": "MaxMessageLength",
            "fieldType": "ULONG",
            "fieldValue": "0x00001000",
            "fieldComment": "4KB max message"
          },
          {
            "fieldName": "MemoryBandwidth",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          },
          {
            "fieldName": "MaxPoolUsage",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          },
          {
            "fieldName": "MaxSectionSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          },
          {
            "fieldName": "MaxViewSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          },
          {
            "fieldName": "MaxTotalSectionSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          }
        ]
      },
      "struct20": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtAlpcCancelMessage": {
    "ntFunc": "NtAlpcCancelMessage",
    "pushes": [
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to ALPC_CONTEXT_ATTRIBUTES MessageContext (dummy pointer)",
        "structurePointer": "ALPC_CONTEXT_ATTRIBUTES",
        "structureRef": "struct21",
        "structureValueExpectations": "Context attributes for the message.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Flags (default: 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct21": {
        "type": "ALPC_CONTEXT_ATTRIBUTES",
        "fields": [
          {
            "fieldName": "AttributeFlags",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Sample context attribute"
          }
        ]
      }
    }
  },
  "NtAlpcCreatePort": {
    "ntFunc": "NtAlpcCreatePort",
    "pushes": [
      {
        "value": "0xbadd00c0",
        "additionalComment": "Pointer to ALPC_PORT_ATTRIBUTES PortAttributes (dummy pointer)",
        "structurePointer": "ALPC_PORT_ATTRIBUTES",
        "structureRef": "struct22",
        "structureValueExpectations": "Attributes for the new port.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00d0",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES ObjectAttributes (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct23",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00e0",
        "additionalComment": "Pointer to HANDLE PortHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct22": {
        "type": "ALPC_PORT_ATTRIBUTES",
        "fields": [
          {
            "fieldName": "Flags",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Sample flag"
          },
          {
            "fieldName": "SecurityQos.Length",
            "fieldType": "ULONG",
            "fieldValue": "0x0000000C",
            "fieldComment": "SECURITY_QUALITY_OF_SERVICE length"
          },
          {
            "fieldName": "MaxMessageLength",
            "fieldType": "ULONG",
            "fieldValue": "0x00001000",
            "fieldComment": "4KB max message"
          },
          {
            "fieldName": "MemoryBandwidth",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          },
          {
            "fieldName": "MaxPoolUsage",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          },
          {
            "fieldName": "MaxSectionSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          },
          {
            "fieldName": "MaxViewSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          },
          {
            "fieldName": "MaxTotalSectionSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          }
        ]
      },
      "struct23": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtAlpcCreatePortSection": {
    "ntFunc": "NtAlpcCreatePortSection",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG ActualSectionSize (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00001000"
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to HANDLE AlpcSectionHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00020000",
        "additionalComment": "ULONG SectionSize (128 KB typical section size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE SectionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Flags (default, no flags)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000555",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAlpcCreateResourceReserve": {
    "ntFunc": "NtAlpcCreateResourceReserve",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to HANDLE ResourceID (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00004000",
        "additionalComment": "SIZE_T MessageSize (16 KB typical message size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Reserved (must be zero)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000555",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAlpcCreateSectionView": {
    "ntFunc": "NtAlpcCreateSectionView",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to ALPC_DATA_VIEW ViewAttributes (dummy pointer)",
        "structurePointer": "ALPC_DATA_VIEW",
        "structureRef": "struct24",
        "structureValueExpectations": "Base address, size, and flags for the section view.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Reserved (must be zero)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000555",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct24": {
        "type": "ALPC_DATA_VIEW",
        "fields": [
          {
            "fieldName": "Base",
            "fieldType": "PVOID",
            "fieldValue": "0x00400000",
            "fieldComment": "Base address of the section view"
          },
          {
            "fieldName": "Size",
            "fieldType": "SIZE_T",
            "fieldValue": "0x00001000",
            "fieldComment": "Size of the view (4 KB)"
          },
          {
            "fieldName": "Flags",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "View is committed"
          }
        ]
      }
    }
  },
  "NtAlpcCreateSecurityContext": {
    "ntFunc": "NtAlpcCreateSecurityContext",
    "pushes": [
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to ALPC_SECURITY_ATTRIBUTES SecurityAttribute (dummy pointer)",
        "structurePointer": "ALPC_SECURITY_ATTRIBUTES",
        "structureRef": "struct25",
        "structureValueExpectations": "Security descriptor, context flags, QoS, etc.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Reserved (must be zero)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000555",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct25": {
        "type": "ALPC_SECURITY_ATTRIBUTES",
        "fields": [
          {
            "fieldName": "Flags",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Default security context"
          },
          {
            "fieldName": "QoS",
            "fieldType": "SECURITY_QUALITY_OF_SERVICE",
            "fieldValue": "0xbadd0050",
            "fieldComment": "Pointer to SECURITY_QUALITY_OF_SERVICE (dummy pointer)"
          },
          {
            "fieldName": "SecurityDescriptor",
            "fieldType": "PSECURITY_DESCRIPTOR",
            "fieldValue": "0x00000000",
            "fieldComment": "None (no custom security descriptor)"
          }
        ]
      }
    }
  },
  "NtAlpcDeletePortSection": {
    "ntFunc": "NtAlpcDeletePortSection",
    "pushes": [
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE SectionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Reserved (must be zero)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000555",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAlpcDeleteResourceReserve": {
    "ntFunc": "NtAlpcDeleteResourceReserve",
    "pushes": [
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE ResourceID (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "__reserved ULONG (must be zero)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000cafe",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAlpcDeleteSectionView": {
    "ntFunc": "NtAlpcDeleteSectionView",
    "pushes": [
      {
        "value": "0x00400000",
        "additionalComment": "PVOID ViewBase (example mapped base address)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "__reserved ULONG (must be zero)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000cafe",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAlpcDeleteSecurityContext": {
    "ntFunc": "NtAlpcDeleteSecurityContext",
    "pushes": [
      {
        "value": "0x0000beef",
        "additionalComment": "HANDLE ContextHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "__reserved ULONG (must be zero)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000cafe",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAlpcDisconnectPort": {
    "ntFunc": "NtAlpcDisconnectPort",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "ULONG Flags (ALPC_DISCONNECT_SEND_NOTIFICATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000cafe",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAlpcImpersonateClientOfPort": {
    "ntFunc": "NtAlpcImpersonateClientOfPort",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "__reserved PVOID (must be None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to PORT_MESSAGE (dummy pointer)",
        "structurePointer": "PORT_MESSAGE",
        "structureRef": "struct26",
        "structureValueExpectations": "Message header and client information.",
        "pointedValue": None
      },
      {
        "value": "0x0000cafe",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct26": {
        "type": "PORT_MESSAGE",
        "fields": [
          {
            "fieldName": "u1.s1.DataLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Length of message data"
          },
          {
            "fieldName": "u1.s1.TotalLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0030",
            "fieldComment": "Total length including header"
          },
          {
            "fieldName": "u2.s2.Type",
            "fieldType": "USHORT",
            "fieldValue": "0x0001",
            "fieldComment": "Message type (e.g., LPC_REQUEST)"
          },
          {
            "fieldName": "u2.s2.DataInfoOffset",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "Offset to data info (if any)"
          },
          {
            "fieldName": "ClientId.UniqueProcess",
            "fieldType": "HANDLE",
            "fieldValue": "0x99994444",
            "fieldComment": "Dummy process ID"
          },
          {
            "fieldName": "ClientId.UniqueThread",
            "fieldType": "HANDLE",
            "fieldValue": "0x88883333",
            "fieldComment": "Dummy thread ID"
          },
          {
            "fieldName": "MessageId",
            "fieldType": "ULONG",
            "fieldValue": "0x00001234",
            "fieldComment": "Message identifier"
          },
          {
            "fieldName": "ClientViewSize",
            "fieldType": "SIZE_T",
            "fieldValue": "0x00000000",
            "fieldComment": "Typically zero unless using views"
          }
        ]
      }
    }
  },
  "NtAlpcOpenSenderProcess": {
    "ntFunc": "NtAlpcOpenSenderProcess",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None for POBJECT_ATTRIBUTES (optional, commonly None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Optional; typically None unless filtering by object attributes.",
        "pointedValue": None
      },
      {
        "value": "0x001F0FFF",
        "additionalComment": "ACCESS_MASK Access (PROCESS_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Reserved ULONG (must be zero)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to PORT_MESSAGE (dummy pointer, required)",
        "structurePointer": "PORT_MESSAGE",
        "structureRef": "struct27",
        "structureValueExpectations": "PORT_MESSAGE structure describing the ALPC message.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to HANDLE ProcessHandle (dummy pointer, receives process handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct27": {
        "type": "PORT_MESSAGE",
        "fields": [
          {
            "fieldName": "u1.s1.TotalLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Total length of the message"
          },
          {
            "fieldName": "u1.s1.DataLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0018",
            "fieldComment": "Length of the data"
          },
          {
            "fieldName": "u2.s2.Type",
            "fieldType": "USHORT",
            "fieldValue": "0x0001",
            "fieldComment": "Message type"
          },
          {
            "fieldName": "u2.s2.DataInfoOffset",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "Offset to data info"
          },
          {
            "fieldName": "ClientId.UniqueProcess",
            "fieldType": "HANDLE",
            "fieldValue": "0x99990001",
            "fieldComment": "Dummy process ID"
          },
          {
            "fieldName": "ClientId.UniqueThread",
            "fieldType": "HANDLE",
            "fieldValue": "0x99990002",
            "fieldComment": "Dummy thread ID"
          },
          {
            "fieldName": "MessageId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Message identifier"
          },
          {
            "fieldName": "ClientViewSize",
            "fieldType": "SIZE_T",
            "fieldValue": "0x00000000",
            "fieldComment": "No client view"
          }
        ]
      }
    }
  },
  "NtAlpcOpenSenderThread": {
    "ntFunc": "NtAlpcOpenSenderThread",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None for POBJECT_ATTRIBUTES (optional, commonly None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Optional; typically None unless filtering by object attributes.",
        "pointedValue": None
      },
      {
        "value": "0x00100020",
        "additionalComment": "ACCESS_MASK Access (THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Reserved ULONG (must be zero)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to PORT_MESSAGE (dummy pointer, required)",
        "structurePointer": "PORT_MESSAGE",
        "structureRef": "struct28",
        "structureValueExpectations": "PORT_MESSAGE structure describing the ALPC message.",
        "pointedValue": None
      },
      {
        "value": "0x00000555",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to HANDLE ThreadHandle (dummy pointer, receives thread handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct28": {
        "type": "PORT_MESSAGE",
        "fields": [
          {
            "fieldName": "u1.s1.TotalLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Total length of the message"
          },
          {
            "fieldName": "u1.s1.DataLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0018",
            "fieldComment": "Length of the data"
          },
          {
            "fieldName": "u2.s2.Type",
            "fieldType": "USHORT",
            "fieldValue": "0x0002",
            "fieldComment": "Message type"
          },
          {
            "fieldName": "u2.s2.DataInfoOffset",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "Offset to data info"
          },
          {
            "fieldName": "ClientId.UniqueProcess",
            "fieldType": "HANDLE",
            "fieldValue": "0x99990003",
            "fieldComment": "Dummy process ID"
          },
          {
            "fieldName": "ClientId.UniqueThread",
            "fieldType": "HANDLE",
            "fieldValue": "0x99990004",
            "fieldComment": "Dummy thread ID"
          },
          {
            "fieldName": "MessageId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000002",
            "fieldComment": "Message identifier"
          },
          {
            "fieldName": "ClientViewSize",
            "fieldType": "SIZE_T",
            "fieldValue": "0x00000000",
            "fieldComment": "No client view"
          }
        ]
      }
    }
  },
  "NtAlpcQueryInformation": {
    "ntFunc": "NtAlpcQueryInformation",
    "pushes": [
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer, optional)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000020"
      },
      {
        "value": "0x00000020",
        "additionalComment": "ULONG Length (buffer size, 32 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to output buffer (dummy pointer, receives information)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "ALPC_PORT_INFORMATION_CLASS PortInformationClass (AlpcBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000666",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAlpcQueryInformationMessage": {
    "ntFunc": "NtAlpcQueryInformationMessage",
    "pushes": [
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer, optional)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00000010",
        "additionalComment": "ULONG Length (buffer size, 16 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to output buffer (dummy pointer, receives information)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000002",
        "additionalComment": "ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass (AlpcMessageBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to PORT_MESSAGE (dummy pointer, required)",
        "structurePointer": "PORT_MESSAGE",
        "structureRef": "struct29",
        "structureValueExpectations": "PORT_MESSAGE structure describing the ALPC message.",
        "pointedValue": None
      },
      {
        "value": "0x00000777",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct29": {
        "type": "PORT_MESSAGE",
        "fields": [
          {
            "fieldName": "u1.s1.TotalLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Total length of the message"
          },
          {
            "fieldName": "u1.s1.DataLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0008",
            "fieldComment": "Length of the data"
          },
          {
            "fieldName": "u2.s2.Type",
            "fieldType": "USHORT",
            "fieldValue": "0x0003",
            "fieldComment": "Message type"
          },
          {
            "fieldName": "u2.s2.DataInfoOffset",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "Offset to data info"
          },
          {
            "fieldName": "ClientId.UniqueProcess",
            "fieldType": "HANDLE",
            "fieldValue": "0x99990005",
            "fieldComment": "Dummy process ID"
          },
          {
            "fieldName": "ClientId.UniqueThread",
            "fieldType": "HANDLE",
            "fieldValue": "0x99990006",
            "fieldComment": "Dummy thread ID"
          },
          {
            "fieldName": "MessageId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000003",
            "fieldComment": "Message identifier"
          },
          {
            "fieldName": "ClientViewSize",
            "fieldType": "SIZE_T",
            "fieldValue": "0x00000000",
            "fieldComment": "No client view"
          }
        ]
      }
    }
  },
  "NtAlpcRevokeSecurityContext": {
    "ntFunc": "NtAlpcRevokeSecurityContext",
    "pushes": [
      {
        "value": "0x00000888",
        "additionalComment": "HANDLE ContextHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Reserved ULONG (must be zero)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000999",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAlpcSendWaitReceivePort": {
    "ntFunc": "NtAlpcSendWaitReceivePort",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for PLARGE_INTEGER Time_Out (no timeout specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes (no receive attributes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for PULONG BufferLength (no receive buffer length)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for PPORT_MESSAGE ReceiveMessage (no receive message buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes (no send attributes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for PPORT_MESSAGE SendMessage (no send message buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Flags = 0 (no special flags)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None PortHandle (no port specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAlpcSetInformation": {
    "ntFunc": "NtAlpcSetInformation",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Length = 0 (no information provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for PortInformation (no information buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PortInformationClass = 0 (unspecified information class)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None PortHandle (no port specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtEnumerateBootEntries": {
    "ntFunc": "NtEnumerateBootEntries",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for PULONG BufferLength (no buffer length provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for Buffer (no buffer provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtEnumerateDriverEntries": {
    "ntFunc": "NtEnumerateDriverEntries",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for PULONG BufferLength (no buffer length provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for Buffer (no buffer provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtEnumerateSystemEnvironmentValuesEx": {
    "ntFunc": "NtEnumerateSystemEnvironmentValuesEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for PULONG BufferLength (no buffer length provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for Buffer (no buffer provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "InformationClass = 0 (Environment Value Information Class, unspecified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryBootEntryOrder": {
    "ntFunc": "NtQueryBootEntryOrder",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG Count (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000003"
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to ULONG array Ids (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      }
    ],
    "structures": {}
  },
  "NtQueryBootOptions": {
    "ntFunc": "NtQueryBootOptions",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to ULONG BootOptionsLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000040"
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to BOOT_OPTIONS structure (dummy pointer)",
        "structurePointer": "BOOT_OPTIONS",
        "structureRef": "struct30",
        "structureValueExpectations": "Version, Length, Timeout, CurrentBootEntryId, NextBootEntryId, HeadlessTerminal.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct30": {
        "type": "BOOT_OPTIONS",
        "fields": [
          {
            "fieldName": "Version",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Version 1"
          },
          {
            "fieldName": "Length",
            "fieldType": "ULONG",
            "fieldValue": "0x00000040",
            "fieldComment": "Structure size"
          },
          {
            "fieldName": "Timeout",
            "fieldType": "ULONG",
            "fieldValue": "0x0000001e",
            "fieldComment": "30 seconds"
          },
          {
            "fieldName": "CurrentBootEntryId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Current boot entry ID"
          },
          {
            "fieldName": "NextBootEntryId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000002",
            "fieldComment": "Next boot entry ID"
          },
          {
            "fieldName": "HeadlessTerminal",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Not headless"
          }
        ]
      }
    }
  },
  "NtQueryDriverEntryOrder": {
    "ntFunc": "NtQueryDriverEntryOrder",
    "pushes": [
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to ULONG Count (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000002"
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to ULONG array Ids (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      }
    ],
    "structures": {}
  },
  "NtQuerySystemEnvironmentValueEx": {
    "ntFunc": "NtQuerySystemEnvironmentValueEx",
    "pushes": [
      {
        "value": "0xbadd0060",
        "additionalComment": "Optional pointer to ULONG (dummy pointer, optional parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to ULONG ValueLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000020"
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to buffer for Value (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x41414141"
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to GUID VendorGuid (dummy pointer)",
        "structurePointer": "GUID",
        "structureRef": "struct31",
        "structureValueExpectations": "Vendor GUID for the environment variable.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00a0",
        "additionalComment": "Pointer to UNICODE_STRING VariableName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct32",
        "structureValueExpectations": "UNICODE_STRING describing the variable name.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct31": {
        "type": "GUID",
        "fields": [
          {
            "fieldName": "Data1",
            "fieldType": "ULONG",
            "fieldValue": "0x12345678",
            "fieldComment": "Sample GUID Data1"
          },
          {
            "fieldName": "Data2",
            "fieldType": "USHORT",
            "fieldValue": "0x9abc",
            "fieldComment": "Sample GUID Data2"
          },
          {
            "fieldName": "Data3",
            "fieldType": "USHORT",
            "fieldValue": "0xdef0",
            "fieldComment": "Sample GUID Data3"
          },
          {
            "fieldName": "Data4",
            "fieldType": "UCHAR[8]",
            "fieldValue": "0x1122334455667788",
            "fieldComment": "Sample GUID Data4"
          }
        ]
      },
      "struct32": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "String length in bytes"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Maximum buffer size in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd00c0",
            "fieldComment": "Pointer to string buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtSetBootEntryOrder": {
    "ntFunc": "NtSetBootEntryOrder",
    "pushes": [
      {
        "value": "0x00000002",
        "additionalComment": "ULONG Count (number of entries)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to ULONG array Ids (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      }
    ],
    "structures": {}
  },
  "NtSetDriverEntryOrder": {
    "ntFunc": "NtSetDriverEntryOrder",
    "pushes": [
      {
        "value": "0x00000002",
        "additionalComment": "ULONG Count (number of driver IDs to set)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG Ids (dummy pointer, array of driver IDs)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000123"
      }
    ],
    "structures": {}
  },
  "NtQuerySystemInformationEx": {
    "ntFunc": "NtQuerySystemInformationEx",
    "pushes": [
      {
        "value": "0xbadd0010",
        "additionalComment": "Optional pointer to ULONG (dummy pointer, receives return length)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000080"
      },
      {
        "value": "0x00000100",
        "additionalComment": "ULONG SystemInformationLength (256 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to buffer for SystemInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000040",
        "additionalComment": "ULONG QueryInformationLength (64 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to buffer for QueryInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000007",
        "additionalComment": "SYSTEM_INFORMATION_CLASS SystemInformationClass (e.g., SystemProcessInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtInitializeNlsFiles": {
    "ntFunc": "NtInitializeNlsFiles",
    "pushes": [
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to LARGE_INTEGER DefaultCasingTableSize (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct33",
        "structureValueExpectations": "64-bit integer representing table size.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to LCID DefaultLocaleId (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000409"
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to base address for NLS files (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x7ffd0000"
      }
    ],
    "structures": {
      "struct33": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000000100000",
            "fieldComment": "Default casing table size (1MB)"
          }
        ]
      }
    }
  },
  "NtAcquireCMFViewOwnership": {
    "ntFunc": "NtAcquireCMFViewOwnership",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN replaceExisting (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to BOOLEAN tokenTaken (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to ULONGLONG TimeStamp (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x01d8c0de"
      }
    ],
    "structures": {}
  },
  "NtCreateProfileEx": {
    "ntFunc": "NtCreateProfileEx",
    "pushes": [
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to GROUP_AFFINITY (dummy pointer)",
        "structurePointer": "GROUP_AFFINITY",
        "structureRef": "struct34",
        "structureValueExpectations": "Processor affinity mask and group number.",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG GroupAffinityCount (1 group)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "KPROFILE_SOURCE ProfileSource (e.g., ProfileTime)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG BufferSize (4096 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00a0",
        "additionalComment": "Pointer to ULONG Buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000010",
        "additionalComment": "ULONG BucketSize (16 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00010000",
        "additionalComment": "SIZE_T ProfileSize (65536 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to ProfileBase (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00400000"
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE Process (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00c0",
        "additionalComment": "Pointer to HANDLE ProfileHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct34": {
        "type": "GROUP_AFFINITY",
        "fields": [
          {
            "fieldName": "Mask",
            "fieldType": "KAFFINITY",
            "fieldValue": "0x00000001",
            "fieldComment": "Processor 0"
          },
          {
            "fieldName": "Group",
            "fieldType": "WORD",
            "fieldValue": "0x0000",
            "fieldComment": "Group 0"
          },
          {
            "fieldName": "Reserved",
            "fieldType": "WORD[3]",
            "fieldValue": "0x00000000",
            "fieldComment": "Reserved, set to zero"
          }
        ]
      }
    }
  },
  "NtCreateWorkerFactory": {
    "ntFunc": "NtCreateWorkerFactory",
    "pushes": [
      {
        "value": "0x00001000",
        "additionalComment": "StackCommit (4KB, typical default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00100000",
        "additionalComment": "StackReserve (1MB, typical default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000010",
        "additionalComment": "MaxThreadCount (16 threads, realistic example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "StartParameter (None, no parameter passed)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to StartRoutine (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00401000"
      },
      {
        "value": "0x00000444",
        "additionalComment": "WorkerProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000555",
        "additionalComment": "CompletionPortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct35",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F0001",
        "additionalComment": "DesiredAccess (WORKER_FACTORY_ALL_ACCESS, typical value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to HANDLE WorkerFactoryHandleReturn (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct35": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (no name)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtFlushInstallUILanguage": {
    "ntFunc": "NtFlushInstallUILanguage",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "SetComittedFlag (TRUE, commit the language)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000409",
        "additionalComment": "InstallUILanguage (LANGID for en-US)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtGetMUIRegistryInfo": {
    "ntFunc": "NtGetMUIRegistryInfo",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to Data buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0040"
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to ULONG DataSize (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000100"
      },
      {
        "value": "0x00000000",
        "additionalComment": "Flags (0, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtGetNlsSectionPtr": {
    "ntFunc": "NtGetNlsSectionPtr",
    "pushes": [
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to ULONG SectionSize (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00008000"
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to SectionPointer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00500000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "ContextData (None, not used)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "SectionData (example: 1, could be code page identifier)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "SectionType (example: 2, could be NLS section type)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtIsUILanguageComitted": {
    "ntFunc": "NtIsUILanguageComitted",
    "pushes": [],
    "structures": {}
  },
  "NtReleaseCMFViewOwnership": {
    "ntFunc": "NtReleaseCMFViewOwnership",
    "pushes": [],
    "structures": {}
  },
  "NtReleaseWorkerFactoryWorker": {
    "ntFunc": "NtReleaseWorkerFactoryWorker",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE WorkerFactoryHandle (None, typical for test or error path)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryInformationWorkerFactory": {
    "ntFunc": "NtQueryInformationWorkerFactory",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to ULONG ReturnLength (None, optional out parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000020",
        "additionalComment": "ULONG WorkerFactoryInformationLength (32 bytes, typical for info query)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to WorkerFactoryInformation buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "WORKERFACTORYINFOCLASS WorkerFactoryInformationClass (e.g., WorkerFactoryBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE WorkerFactoryHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetInformationWorkerFactory": {
    "ntFunc": "NtSetInformationWorkerFactory",
    "pushes": [
      {
        "value": "0x00000010",
        "additionalComment": "ULONG WorkerFactoryInformationLength (16 bytes, typical for set info)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to WorkerFactoryInformation buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000002",
        "additionalComment": "WORKERFACTORYINFOCLASS WorkerFactoryInformationClass (e.g., WorkerFactoryReconfigureInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE WorkerFactoryHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtWaitForWorkViaWorkerFactory": {
    "ntFunc": "NtWaitForWorkViaWorkerFactory",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to FILE_IO_COMPLETION_INFORMATION MiniPacket (dummy pointer)",
        "structurePointer": "FILE_IO_COMPLETION_INFORMATION",
        "structureRef": "struct36",
        "structureValueExpectations": "Contains information about the I/O completion packet.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE WorkerFactoryHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct36": {
        "type": "FILE_IO_COMPLETION_INFORMATION",
        "fields": [
          {
            "fieldName": "KeyContext",
            "fieldType": "PVOID",
            "fieldValue": "0xdeadbeef",
            "fieldComment": "Dummy key context value"
          },
          {
            "fieldName": "ApcContext",
            "fieldType": "PVOID",
            "fieldValue": "0xabadcafe",
            "fieldComment": "Dummy APC context value"
          },
          {
            "fieldName": "IoStatusBlock",
            "fieldType": "PIO_STATUS_BLOCK",
            "fieldValue": "0xbadd0030",
            "fieldComment": "Pointer to IO_STATUS_BLOCK (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtShutdownWorkerFactory": {
    "ntFunc": "NtShutdownWorkerFactory",
    "pushes": [
      {
        "value": "0x00000005",
        "additionalComment": "LONG PendingWorkerCount (example: 5 workers pending)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000DEAD",
        "additionalComment": "HANDLE WorkerFactoryHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetTimerEx": {
    "ntFunc": "NtSetTimerEx",
    "pushes": [
      {
        "value": "0x00000010",
        "additionalComment": "ULONG TimerSetInformationLength (example: 16 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "PVOID TimerSetInformation (dummy pointer, typically points to a structure or buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "TIMER_SET_INFORMATION_CLASS TimerSetInformationClass (example: TimerSetCoalescableTimer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000BEEF",
        "additionalComment": "HANDLE TimerHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCancelTimer2": {
    "ntFunc": "NtCancelTimer2",
    "pushes": [
      {
        "value": "0xbadd0010",
        "additionalComment": "Optional PBOOLEAN (dummy pointer, can be None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x0000BEEF",
        "additionalComment": "HANDLE TimerHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetTimer2": {
    "ntFunc": "NtSetTimer2",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "PT2_SET_PARAMETERS Parameters (dummy pointer, typically points to a structure)",
        "structurePointer": "T2_SET_PARAMETERS",
        "structureRef": "struct37",
        "structureValueExpectations": "Timer configuration parameters such as tolerable delay, flags, etc.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "PLARGE_INTEGER Period (dummy pointer, typically points to a 64-bit interval)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct38",
        "structureValueExpectations": "Interval in 100-nanosecond units for periodic timer.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "PLARGE_INTEGER DueTime (dummy pointer, typically points to a 64-bit time value)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct39",
        "structureValueExpectations": "Absolute or relative time when the timer is set.",
        "pointedValue": None
      },
      {
        "value": "0x0000BEEF",
        "additionalComment": "HANDLE TimerHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct37": {
        "type": "T2_SET_PARAMETERS",
        "fields": [
          {
            "fieldName": "TolerableDelay",
            "fieldType": "ULONG",
            "fieldValue": "0x00000064",
            "fieldComment": "100 ms tolerable delay"
          },
          {
            "fieldName": "Flags",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Example: T2_SET_PARAMETERS_FLAG_NO_WAKE"
          }
        ]
      },
      "struct38": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000000002710",
            "fieldComment": "Period: 10,000 (1 ms in 100-ns units)"
          }
        ]
      },
      "struct39": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0xFFFFFFFFFFDCD650",
            "fieldComment": "DueTime: -2,000,000 (relative, 200 ms in 100-ns units)"
          }
        ]
      }
    }
  },
  "NtQueryWnfStateData": {
    "ntFunc": "NtQueryWnfStateData",
    "pushes": [
      {
        "value": "0xbadd0050",
        "additionalComment": "PULONG BufferSize (dummy pointer, receives size of data)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000100"
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "PVOID Buffer (dummy pointer, receives state data)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "PWNF_CHANGE_STAMP ChangeStamp (dummy pointer, receives change stamp)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID ExplicitScope (None, typical usage)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PCWNF_TYPE_ID TypeId (None, typical usage)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x41C64E6D",
        "additionalComment": "PCWNF_STATE_NAME StateName (example: random state name value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtUpdateWnfStateData": {
    "ntFunc": "NtUpdateWnfStateData",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "LOGICAL CheckStamp (FALSE, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "WNF_CHANGE_STAMP MatchingChangeStamp (default, not used)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID ExplicitScope (None, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PCWNF_TYPE_ID TypeId (None, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Length (0, default, no buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID Buffer (None, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PCWNF_STATE_NAME StateName (None, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtDisableLastKnownGood": {
    "ntFunc": "NtDisableLastKnownGood",
    "pushes": [],
    "structures": {}
  },
  "NtEnableLastKnownGood": {
    "ntFunc": "NtEnableLastKnownGood",
    "pushes": [],
    "structures": {}
  },
  "NtCancelSynchronousIoFile": {
    "ntFunc": "NtCancelSynchronousIoFile",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to IO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct40",
        "structureValueExpectations": "Status and information fields for I/O completion.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to IO_STATUS_BLOCK IoRequestToCancel (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct41",
        "structureValueExpectations": "Pointer to the I/O request to cancel.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ThreadHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct40": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "STATUS_SUCCESS"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "No additional information"
          }
        ]
      },
      "struct41": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0xC0000120",
            "fieldComment": "STATUS_CANCELLED"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "No additional information"
          }
        ]
      }
    }
  },
  "NtSetIoCompletion": {
    "ntFunc": "NtSetIoCompletion",
    "pushes": [
      {
        "value": "0x00001000",
        "additionalComment": "ULONG NumberOfBytesTransfered (4096 bytes, typical I/O size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "NTSTATUS CompletionStatus (STATUS_SUCCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to IO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct42",
        "structureValueExpectations": "Status and information fields for I/O completion.",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG CompletionKey (arbitrary key, 1)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000445",
        "additionalComment": "HANDLE IoCompletionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct42": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "STATUS_SUCCESS"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00001000",
            "fieldComment": "4096 bytes transferred"
          }
        ]
      }
    }
  },
  "NtSetIoCompletionEx": {
    "ntFunc": "NtSetIoCompletionEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "IoStatusInformation (no information, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "IoStatus (STATUS_SUCCESS, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "CompletionValue (None, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "CompletionKey (example key value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "IoCompletionReserveHandle (dummy handle, usually None or reserved)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "IoCompletionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRemoveIoCompletionEx": {
    "ntFunc": "NtRemoveIoCompletionEx",
    "pushes": [
      {
        "value": "0x00",
        "additionalComment": "Alertable (FALSE, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to LARGE_INTEGER Timeout (dummy pointer, usually None for infinite)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct43",
        "structureValueExpectations": "Timeout interval in 100-nanosecond units, negative for relative.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to ULONG NumEntriesRemoved (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00000010",
        "additionalComment": "Count (16 entries to remove, example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to FILE_IO_COMPLETION_INFORMATION array (dummy pointer)",
        "structurePointer": "FILE_IO_COMPLETION_INFORMATION",
        "structureRef": "struct44",
        "structureValueExpectations": "Array of FILE_IO_COMPLETION_INFORMATION structures.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "IoCompletionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct43": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000000000000",
            "fieldComment": "Infinite timeout (None pointer means wait forever)"
          }
        ]
      },
      "struct44": {
        "type": "FILE_IO_COMPLETION_INFORMATION",
        "fields": [
          {
            "fieldName": "CompletionKey",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000001",
            "fieldComment": "Example completion key"
          },
          {
            "fieldName": "CompletionValue",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None, example value"
          },
          {
            "fieldName": "IoStatus",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "STATUS_SUCCESS"
          },
          {
            "fieldName": "IoStatusInformation",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "No additional information"
          }
        ]
      }
    }
  },
  "NtNotifyChangeSession": {
    "ntFunc": "NtNotifyChangeSession",
    "pushes": [
      {
        "value": "0x00001000",
        "additionalComment": "BufferSize (4096 bytes, example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to Buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000002",
        "additionalComment": "IoState2 (IO_SESSION_STATE, example value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "IoState (IO_SESSION_STATE, example value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000010",
        "additionalComment": "Action (example action value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Reserved (None, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000005",
        "additionalComment": "IoStateSequence (example sequence number)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "SessionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAssociateWaitCompletionPacket": {
    "ntFunc": "NtAssociateWaitCompletionPacket",
    "pushes": [
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to BOOLEAN (dummy pointer, optional parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00"
      },
      {
        "value": "0x00000000",
        "additionalComment": "IoStatusInformation (default, no information)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "IoStatus (STATUS_SUCCESS, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "ApcContext (dummy pointer, user context)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x12345678"
      },
      {
        "value": "0xbadd00a0",
        "additionalComment": "KeyContext (dummy pointer, user key context)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x87654321"
      },
      {
        "value": "0xbadd00b0",
        "additionalComment": "TargetObjectHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00c0",
        "additionalComment": "IoCompletionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00d0",
        "additionalComment": "WaitCompletionPacketHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtFlushProcessWriteBuffers": {
    "ntFunc": "NtFlushProcessWriteBuffers",
    "pushes": [],
    "structures": {}
  },
  "NtCommitComplete": {
    "ntFunc": "NtCommitComplete",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to LARGE_INTEGER TmVirtualClock (dummy pointer, commonly None)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct45",
        "structureValueExpectations": "Optional virtual clock value; often None.",
        "pointedValue": None
      },
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE EnlistmentHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct45": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000000000000",
            "fieldComment": "None/zero, commonly used for optional TmVirtualClock"
          }
        ]
      }
    }
  },
  "NtCommitEnlistment": {
    "ntFunc": "NtCommitEnlistment",
    "pushes": [
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to LARGE_INTEGER TmVirtualClock (dummy pointer, commonly None)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct46",
        "structureValueExpectations": "Optional virtual clock value; often None.",
        "pointedValue": None
      },
      {
        "value": "0x0000bcde",
        "additionalComment": "HANDLE EnlistmentHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct46": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000000000000",
            "fieldComment": "None/zero, commonly used for optional TmVirtualClock"
          }
        ]
      }
    }
  },
  "NtCommitTransaction": {
    "ntFunc": "NtCommitTransaction",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN Wait (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000cdef",
        "additionalComment": "HANDLE TransactionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateEnlistment": {
    "ntFunc": "NtCreateEnlistment",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PVOID EnlistmentKey (None, optional context pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000000F",
        "additionalComment": "NOTIFICATION_MASK NotificationMask (example mask)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG CreateOptions (ENLISTMENT_SUPERIOR, example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer, commonly None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct47",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x0000def0",
        "additionalComment": "HANDLE TransactionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000ef01",
        "additionalComment": "HANDLE ResourceManagerHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x001F0001",
        "additionalComment": "ACCESS_MASK DesiredAccess (GENERIC_READ | GENERIC_WRITE, example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to HANDLE EnlistmentHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct47": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtCreateResourceManager": {
    "ntFunc": "NtCreateResourceManager",
    "pushes": [
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to UNICODE_STRING Description (dummy pointer, commonly None)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct48",
        "structureValueExpectations": "Optional description string for the resource manager.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG CreateOptions (default 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer, commonly None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct49",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to GUID RmGuid (dummy pointer)",
        "structurePointer": "GUID",
        "structureRef": "struct50",
        "structureValueExpectations": "Globally unique identifier for the resource manager.",
        "pointedValue": None
      },
      {
        "value": "0x0000f012",
        "additionalComment": "HANDLE TmHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x001F0001",
        "additionalComment": "ACCESS_MASK DesiredAccess (GENERIC_READ | GENERIC_WRITE, example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to HANDLE ResourceManagerHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct48": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "Zero length (no description)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "Zero maximum length"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0x00000000",
            "fieldComment": "None buffer"
          }
        ]
      },
      "struct49": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      },
      "struct50": {
        "type": "GUID",
        "fields": [
          {
            "fieldName": "Data1",
            "fieldType": "ULONG",
            "fieldValue": "0x12345678",
            "fieldComment": "Example GUID part"
          },
          {
            "fieldName": "Data2",
            "fieldType": "USHORT",
            "fieldValue": "0x9abc",
            "fieldComment": "Example GUID part"
          },
          {
            "fieldName": "Data3",
            "fieldType": "USHORT",
            "fieldValue": "0xdef0",
            "fieldComment": "Example GUID part"
          },
          {
            "fieldName": "Data4",
            "fieldType": "UCHAR[8]",
            "fieldValue": "0x1122334455667788",
            "fieldComment": "Example GUID part"
          }
        ]
      }
    }
  },
  "NtCreateTransaction": {
    "ntFunc": "NtCreateTransaction",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None (no description)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None (no timeout specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "IsolationFlags = 0 (default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "IsolationLevel = 0 (default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "CreateOptions = 0 (default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None TmHandle (no transaction manager handle specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None Uow (no UOW GUID specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None ObjectAttributes (default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x001F0001",
        "additionalComment": "DesiredAccess (TRANSACTION_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to HANDLE TransactionHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtCreateTransactionManager": {
    "ntFunc": "NtCreateTransactionManager",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "CommitStrength = 0 (default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "CreateOptions = 0 (default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None LogFileName (no log file specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None ObjectAttributes (default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x001F0001",
        "additionalComment": "DesiredAccess (TRANSACTIONMANAGER_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to HANDLE TmHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtEnumerateTransactionObject": {
    "ntFunc": "NtEnumerateTransactionObject",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00000010",
        "additionalComment": "ObjectCursorLength = 0x10 (16 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None ObjectCursor (no cursor structure provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "KTMOBJECT_TYPE = KTMOBJECT_TRANSACTION",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE RootObjectHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtFreezeTransactions": {
    "ntFunc": "NtFreezeTransactions",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None ThawTime_Out (no timeout specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None FreezeTime_Out (no timeout specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtGetNotificationResourceManager": {
    "ntFunc": "NtGetNotificationResourceManager",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "AsynchronousContext = 0 (default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Asynchronous = 0 (synchronous operation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None optional PULONG (no return value requested)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None Time_Out (no timeout specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "NotificationLength = 0x1000 (4096 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None TransactionNotification (no notification buffer provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ResourceManagerHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtOpenEnlistment": {
    "ntFunc": "NtOpenEnlistment",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for OBJECT_ATTRIBUTES (optional, commonly None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for LPGUID EnlistmentGuid (optional, commonly None)",
        "structurePointer": "GUID",
        "structureRef": None,
        "structureValueExpectations": "GUID structure representing the enlistment identifier.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None ResourceManagerHandle (commonly invalid or defaulted in examples)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x000F0000",
        "additionalComment": "DesiredAccess (GENERIC_READ | GENERIC_WRITE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to HANDLE EnlistmentHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtOpenResourceManager": {
    "ntFunc": "NtOpenResourceManager",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for OBJECT_ATTRIBUTES (optional, commonly None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for LPGUID ResourceManagerGuid (optional, commonly None)",
        "structurePointer": "GUID",
        "structureRef": None,
        "structureValueExpectations": "GUID structure representing the resource manager identifier.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None TmHandle (commonly invalid or defaulted in examples)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x000F0000",
        "additionalComment": "DesiredAccess (GENERIC_READ | GENERIC_WRITE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to HANDLE ResourceManagerHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtOpenTransaction": {
    "ntFunc": "NtOpenTransaction",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None TmHandle (commonly invalid or defaulted in examples)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for LPGUID Uow (optional, commonly None)",
        "structurePointer": "GUID",
        "structureRef": None,
        "structureValueExpectations": "GUID structure representing the unit of work identifier.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for OBJECT_ATTRIBUTES (optional, commonly None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x000F0000",
        "additionalComment": "DesiredAccess (GENERIC_READ | GENERIC_WRITE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to HANDLE TransactionHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtOpenTransactionManager": {
    "ntFunc": "NtOpenTransactionManager",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "OpenOptions (commonly 0 for default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for LPGUID TmIdentity (optional, commonly None)",
        "structurePointer": "GUID",
        "structureRef": None,
        "structureValueExpectations": "GUID structure representing the transaction manager identity.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for PUNICODE_STRING LogFileName (optional, commonly None)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": None,
        "structureValueExpectations": "UNICODE_STRING structure for log file name.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for OBJECT_ATTRIBUTES (optional, commonly None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x000F0000",
        "additionalComment": "DesiredAccess (GENERIC_READ | GENERIC_WRITE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to HANDLE TmHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtPrepareComplete": {
    "ntFunc": "NtPrepareComplete",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for PLARGE_INTEGER TmVirtualClock (optional, commonly None)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": None,
        "structureValueExpectations": "64-bit integer value representing the virtual clock.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None EnlistmentHandle (commonly invalid or defaulted in examples)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtPrepareEnlistment": {
    "ntFunc": "NtPrepareEnlistment",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for PLARGE_INTEGER TmVirtualClock (optional, commonly None)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": None,
        "structureValueExpectations": "Optional timestamp; commonly None.",
        "pointedValue": None
      },
      {
        "value": "0xdead1000",
        "additionalComment": "HANDLE EnlistmentHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtPrePrepareComplete": {
    "ntFunc": "NtPrePrepareComplete",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for PLARGE_INTEGER TmVirtualClock (optional, commonly None)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": None,
        "structureValueExpectations": "Optional timestamp; commonly None.",
        "pointedValue": None
      },
      {
        "value": "0xdead2000",
        "additionalComment": "HANDLE EnlistmentHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtPrePrepareEnlistment": {
    "ntFunc": "NtPrePrepareEnlistment",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for PLARGE_INTEGER TmVirtualClock (optional, commonly None)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": None,
        "structureValueExpectations": "Optional timestamp; commonly None.",
        "pointedValue": None
      },
      {
        "value": "0xdead3000",
        "additionalComment": "HANDLE EnlistmentHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtPropagationComplete": {
    "ntFunc": "NtPropagationComplete",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for Buffer (optional, commonly None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": "Optional buffer for propagation data.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "BufferLength = 0 (no buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "RequestCookie (dummy value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xdead4000",
        "additionalComment": "HANDLE ResourceManagerHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtPropagationFailed": {
    "ntFunc": "NtPropagationFailed",
    "pushes": [
      {
        "value": "0xc0000022",
        "additionalComment": "NTSTATUS PropStatus (STATUS_ACCESS_DENIED, dummy error)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "RequestCookie (dummy value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xdead5000",
        "additionalComment": "HANDLE ResourceManagerHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryInformationEnlistment": {
    "ntFunc": "NtQueryInformationEnlistment",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer, optional output)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000020"
      },
      {
        "value": "0x00000100",
        "additionalComment": "EnlistmentInformationLength (256 bytes, typical buffer size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to buffer for EnlistmentInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0100"
      },
      {
        "value": "0x00000001",
        "additionalComment": "EnlistmentInformationClass (ENLISTMENT_BASIC_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE EnlistmentHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryInformationResourceManager": {
    "ntFunc": "NtQueryInformationResourceManager",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer, optional output)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000020"
      },
      {
        "value": "0x00000100",
        "additionalComment": "ResourceManagerInformationLength (256 bytes, typical buffer size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to buffer for ResourceManagerInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0110"
      },
      {
        "value": "0x00000001",
        "additionalComment": "ResourceManagerInformationClass (RESOURCEMANAGER_BASIC_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000bcde",
        "additionalComment": "HANDLE ResourceManagerHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryInformationTransaction": {
    "ntFunc": "NtQueryInformationTransaction",
    "pushes": [
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer, optional output)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000020"
      },
      {
        "value": "0x00000100",
        "additionalComment": "TransactionInformationLength (256 bytes, typical buffer size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to buffer for TransactionInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0120"
      },
      {
        "value": "0x00000001",
        "additionalComment": "TransactionInformationClass (TRANSACTION_BASIC_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000cdef",
        "additionalComment": "HANDLE TransactionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryInformationTransactionManager": {
    "ntFunc": "NtQueryInformationTransactionManager",
    "pushes": [
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer, optional output)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000020"
      },
      {
        "value": "0x00000100",
        "additionalComment": "TransactionManagerInformationLength (256 bytes, typical buffer size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to buffer for TransactionManagerInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0130"
      },
      {
        "value": "0x00000001",
        "additionalComment": "TransactionManagerInformationClass (TRANSACTIONMANAGER_BASIC_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000def0",
        "additionalComment": "HANDLE TransactionManagerHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtReadOnlyEnlistment": {
    "ntFunc": "NtReadOnlyEnlistment",
    "pushes": [
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to LARGE_INTEGER TmVirtualClock (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct51",
        "structureValueExpectations": "64-bit signed integer representing a virtual clock value.",
        "pointedValue": None
      },
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE EnlistmentHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct51": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x01d8e3b5a7c0000",
            "fieldComment": "Sample virtual clock value"
          }
        ]
      }
    }
  },
  "NtRecoverEnlistment": {
    "ntFunc": "NtRecoverEnlistment",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "EnlistmentKey (None, commonly unused)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE EnlistmentHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRecoverResourceManager": {
    "ntFunc": "NtRecoverResourceManager",
    "pushes": [
      {
        "value": "0x0000bcde",
        "additionalComment": "HANDLE ResourceManagerHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRecoverTransactionManager": {
    "ntFunc": "NtRecoverTransactionManager",
    "pushes": [
      {
        "value": "0x0000cdef",
        "additionalComment": "HANDLE TransactionManagerHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRegisterProtocolAddressInformation": {
    "ntFunc": "NtRegisterProtocolAddressInformation",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "CreateOptions (example: 1, e.g. RM_PROTOCOL_REGISTER_VOLATILE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ProtocolInformation (dummy pointer, typically a buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xdeadbeef"
      },
      {
        "value": "0x00000010",
        "additionalComment": "ProtocolInformationSize (16 bytes, typical small structure)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "ProtocolId (dummy protocol ID value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000bcde",
        "additionalComment": "HANDLE ResourceManager (dummy handle, matches ResourceManagerHandle above)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRenameTransactionManager": {
    "ntFunc": "NtRenameTransactionManager",
    "pushes": [
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to LPGUID ExistingTransactionManagerGuid (dummy pointer)",
        "structurePointer": "GUID",
        "structureRef": "struct52",
        "structureValueExpectations": "A valid GUID structure identifying the existing transaction manager.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to UNICODE_STRING LogFileName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct53",
        "structureValueExpectations": "UNICODE_STRING structure describing the new log file name.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct52": {
        "type": "GUID",
        "fields": [
          {
            "fieldName": "Data1",
            "fieldType": "ULONG",
            "fieldValue": "0x12345678",
            "fieldComment": "Example GUID Data1"
          },
          {
            "fieldName": "Data2",
            "fieldType": "USHORT",
            "fieldValue": "0x9abc",
            "fieldComment": "Example GUID Data2"
          },
          {
            "fieldName": "Data3",
            "fieldType": "USHORT",
            "fieldValue": "0xdef0",
            "fieldComment": "Example GUID Data3"
          },
          {
            "fieldName": "Data4",
            "fieldType": "UCHAR[8]",
            "fieldValue": "0x1122334455667788",
            "fieldComment": "Example GUID Data4"
          }
        ]
      },
      "struct53": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0014",
            "fieldComment": "20 bytes (10 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "32 bytes buffer"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0030",
            "fieldComment": "Pointer to buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtRollBackComplete": {
    "ntFunc": "NtRollBackComplete",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PLARGE_INTEGER TmVirtualClock (None, not used in typical call)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": None,
        "structureValueExpectations": "Pointer to LARGE_INTEGER specifying a virtual clock value, often None.",
        "pointedValue": None
      },
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE EnlistmentHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRollBackEnlistment": {
    "ntFunc": "NtRollBackEnlistment",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PLARGE_INTEGER TmVirtualClock (None, not used in typical call)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": None,
        "structureValueExpectations": "Pointer to LARGE_INTEGER specifying a virtual clock value, often None.",
        "pointedValue": None
      },
      {
        "value": "0x0000bcde",
        "additionalComment": "HANDLE EnlistmentHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRollBackTransaction": {
    "ntFunc": "NtRollBackTransaction",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN Wait (TRUE, wait for rollback to complete)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000cdef",
        "additionalComment": "HANDLE TransactionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRollforwardTransactionManager": {
    "ntFunc": "NtRollforwardTransactionManager",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PLARGE_INTEGER TmVirtualClock (None, not used in typical call)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": None,
        "structureValueExpectations": "Pointer to LARGE_INTEGER specifying a virtual clock value, often None.",
        "pointedValue": None
      },
      {
        "value": "0x0000def0",
        "additionalComment": "HANDLE TmHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetInformationEnlistment": {
    "ntFunc": "NtSetInformationEnlistment",
    "pushes": [
      {
        "value": "0x00000010",
        "additionalComment": "ULONG EnlistmentInformationLength (16 bytes, typical small info structure)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "PVOID EnlistmentInformation (dummy pointer, points to info buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass (EnlistmentBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000ef01",
        "additionalComment": "HANDLE EnlistmentHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetInformationResourceManager": {
    "ntFunc": "NtSetInformationResourceManager",
    "pushes": [
      {
        "value": "0x00000010",
        "additionalComment": "ResourceManagerInformationLength (16 bytes, typical for a small structure)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ResourceManagerInformation (dummy pointer, could be a structure or buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "ResourceManagerInformationClass (ResourceManagerBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE ResourceManagerHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetInformationTransaction": {
    "ntFunc": "NtSetInformationTransaction",
    "pushes": [
      {
        "value": "0x00000020",
        "additionalComment": "TransactionInformationLength (32 bytes, typical for a structure)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to TransactionInformation (dummy pointer, could be a structure or buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000002",
        "additionalComment": "TransactionInformationClass (TransactionPropertiesInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000dcba",
        "additionalComment": "HANDLE TransactionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetInformationTransactionManager": {
    "ntFunc": "NtSetInformationTransactionManager",
    "pushes": [
      {
        "value": "0x00000018",
        "additionalComment": "TransactionManagerInformationLength (24 bytes, typical for a structure)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to TransactionManagerInformation (dummy pointer, could be a structure or buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "TransactionManagerInformationClass (TmBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000beef",
        "additionalComment": "HANDLE TmHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSinglePhaseReject": {
    "ntFunc": "NtSinglePhaseReject",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to LARGE_INTEGER TmVirtualClock (dummy pointer, often None)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct54",
        "structureValueExpectations": "64-bit integer representing a virtual clock value.",
        "pointedValue": None
      },
      {
        "value": "0x0000cafe",
        "additionalComment": "HANDLE EnlistmentHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct54": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x01d7e6a5b4000000",
            "fieldComment": "Sample virtual clock value"
          }
        ]
      }
    }
  },
  "NtStartTm": {
    "ntFunc": "NtStartTm",
    "pushes": [],
    "structures": {}
  },
  "NtThawRegistry": {
    "ntFunc": "NtThawRegistry",
    "pushes": [],
    "structures": {}
  },
  "NtThawTransactions": {
    "ntFunc": "NtThawTransactions",
    "pushes": [],
    "structures": {}
  },
  "NtDrawText": {
    "ntFunc": "NtDrawText",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PUNICODE_STRING Text (None, no text to draw)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtTraceControl": {
    "ntFunc": "NtTraceControl",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PULONG ReturnLength (None, not requesting return length)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG __OUTBufferLen (zero, no output buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID __OUTBuffer (None, no output buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG InBufferLen (zero, no input buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID InBuffer (None, no input buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG FunctionCode (zero, no operation specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetWnfProcessNotificationEvent": {
    "ntFunc": "NtSetWnfProcessNotificationEvent",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE Unknown1 (None handle, default/unused)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetInformationVirtualMemory": {
    "ntFunc": "NtSetInformationVirtualMemory",
    "pushes": [
      {
        "value": "0x00000020",
        "additionalComment": "ULONG VmInformationLength (example: 32 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to VmInformation buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to MEMORY_RANGE_ENTRY array (dummy pointer)",
        "structurePointer": "MEMORY_RANGE_ENTRY",
        "structureRef": "struct55",
        "structureValueExpectations": "Array of MEMORY_RANGE_ENTRY structures describing memory ranges.",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG_PTR NumberOfEntries (example: 1 entry)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass (example: VmPrefetchInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct55": {
        "type": "MEMORY_RANGE_ENTRY",
        "fields": [
          {
            "fieldName": "VirtualAddress",
            "fieldType": "PVOID",
            "fieldValue": "0x00400000",
            "fieldComment": "Start address of memory range"
          },
          {
            "fieldName": "NumberOfBytes",
            "fieldType": "SIZE_T",
            "fieldValue": "0x00001000",
            "fieldComment": "Size of memory range (4 KB)"
          }
        ]
      }
    }
  },
  "NtOpenPrivateNamespace": {
    "ntFunc": "NtOpenPrivateNamespace",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to BoundaryDescriptor (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": "BoundaryDescriptor structure or buffer.",
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct56",
        "structureValueExpectations": "OBJECT_ATTRIBUTES for the namespace object.",
        "pointedValue": None
      },
      {
        "value": "0x000F0001",
        "additionalComment": "ACCESS_MASK DesiredAccess (example: GENERIC_READ | GENERIC_WRITE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to HANDLE NamespaceHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct56": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (no name)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtCreatePrivateNamespace": {
    "ntFunc": "NtCreatePrivateNamespace",
    "pushes": [
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to BoundaryDescriptor (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": "BoundaryDescriptor structure or buffer.",
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct57",
        "structureValueExpectations": "OBJECT_ATTRIBUTES for the namespace object.",
        "pointedValue": None
      },
      {
        "value": "0x000F0001",
        "additionalComment": "ACCESS_MASK DesiredAccess (example: GENERIC_READ | GENERIC_WRITE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to HANDLE NamespaceHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct57": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (no name)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtDeletePrivateNamespace": {
    "ntFunc": "NtDeletePrivateNamespace",
    "pushes": [
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE NamespaceHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtReplacePartitionUnit": {
    "ntFunc": "NtReplacePartitionUnit",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "ULONG Flags (example: 1, e.g. REPLACE_PARTITION_UNIT_FLAG_NONE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to UNICODE_STRING SpareInstancePath (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct58",
        "structureValueExpectations": "UNICODE_STRING describing the spare partition instance path.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to UNICODE_STRING TargetInstancePath (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct59",
        "structureValueExpectations": "UNICODE_STRING describing the target partition instance path.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct58": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Length in bytes (example: 16 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0022",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd00a0",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      },
      "struct59": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Length in bytes (example: 16 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0022",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd00b0",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtSerializeBoot": {
    "ntFunc": "NtSerializeBoot",
    "pushes": [],
    "structures": {}
  },
  "NtOpenKeyTransacted": {
    "ntFunc": "NtOpenKeyTransacted",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE TransactionHandle (None, default for no transaction)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (None, default for root key)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00020019",
        "additionalComment": "DesiredAccess (KEY_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to HANDLE KeyHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtOpenKeyTransactedEx": {
    "ntFunc": "NtOpenKeyTransactedEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE TransactionHandle (None, default for no transaction)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000020",
        "additionalComment": "OpenOptions (REG_OPTION_OPEN_LINK)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct60",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00020019",
        "additionalComment": "DesiredAccess (KEY_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to HANDLE KeyHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct60": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd0060",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtFreezeRegistry": {
    "ntFunc": "NtFreezeRegistry",
    "pushes": [
      {
        "value": "0x0000000A",
        "additionalComment": "Time_OutInSeconds (10 seconds)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateKeyTransacted": {
    "ntFunc": "NtCreateKeyTransacted",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to ULONG (dummy pointer, optional return for disposition)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE TransactionHandle (None, default for no transaction)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000010",
        "additionalComment": "CreateOptions (REG_OPTION_NON_VOLATILE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to UNICODE_STRING Class (None, default for no class string)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": None,
        "structureValueExpectations": "Optional class string for the key.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Reserved ULONG (must be zero)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct61",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x000F003F",
        "additionalComment": "DesiredAccess (KEY_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to HANDLE KeyHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct61": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd0070",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtQuerySecurityAttributesToken": {
    "ntFunc": "NtQuerySecurityAttributesToken",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer, optional, may be None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000020"
      },
      {
        "value": "0x00000100",
        "additionalComment": "ULONG Length (typical buffer size, e.g. 256 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to output buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd1000"
      },
      {
        "value": "0x00000002",
        "additionalComment": "ULONG NumberOfAttributes (example: 2 attributes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to UNICODE_STRING Attributes (dummy pointer, optional, may be None)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct62",
        "structureValueExpectations": "UNICODE_STRING describing attribute name(s)",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE TokenHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct62": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Length in bytes of string"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0130",
            "fieldComment": "Pointer to string buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtWow64CallFunction64": {
    "ntFunc": "NtWow64CallFunction64",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Optional pointer to ULONG (dummy pointer, may be None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to output buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd2000"
      },
      {
        "value": "0x00000100",
        "additionalComment": "ULONG OutputLength (256 bytes typical)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to input buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd3000"
      },
      {
        "value": "0x00000020",
        "additionalComment": "ULONG InputLength (32 bytes typical)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG Flags (example: 1)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000005",
        "additionalComment": "ULONG FunctionIndex (example: 5)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtWow64WriteVirtualMemory64": {
    "ntFunc": "NtWow64WriteVirtualMemory64",
    "pushes": [
      {
        "value": "0xbadd0060",
        "additionalComment": "Optional pointer to ULONGLONG (dummy pointer, may be None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONGLONG BufferSize (4096 bytes typical)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd4000"
      },
      {
        "value": "0x00007fff0000",
        "additionalComment": "PVOID64 BaseAddress (typical 64-bit address)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAlpcConnectPortEx": {
    "ntFunc": "NtAlpcConnectPortEx",
    "pushes": [
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to LARGE_INTEGER TimeOut (dummy pointer, optional, may be None)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct63",
        "structureValueExpectations": "Timeout value in 100-nanosecond intervals",
        "pointedValue": None
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to ALPC_MESSAGE_ATTRIBUTES InMessageAttributes (dummy pointer, optional, may be None)",
        "structurePointer": "ALPC_MESSAGE_ATTRIBUTES",
        "structureRef": "struct64",
        "structureValueExpectations": "Attributes for the input message",
        "pointedValue": None
      },
      {
        "value": "0xbadd00a0",
        "additionalComment": "Pointer to ALPC_MESSAGE_ATTRIBUTES OutMessageAttributes (dummy pointer, optional, may be None)",
        "structurePointer": "ALPC_MESSAGE_ATTRIBUTES",
        "structureRef": "struct65",
        "structureValueExpectations": "Attributes for the output message",
        "pointedValue": None
      },
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to SIZE_T BufferLength (dummy pointer, optional, may be None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000200"
      },
      {
        "value": "0xbadd00c0",
        "additionalComment": "Pointer to PORT_MESSAGE ConnectionMessage (dummy pointer, optional, may be None)",
        "structurePointer": "PORT_MESSAGE",
        "structureRef": "struct66",
        "structureValueExpectations": "Connection message structure",
        "pointedValue": None
      },
      {
        "value": "0xbadd00d0",
        "additionalComment": "Pointer to SECURITY_DESCRIPTOR ServerSecurityRequirements (dummy pointer, optional, may be None)",
        "structurePointer": "SECURITY_DESCRIPTOR",
        "structureRef": "struct67",
        "structureValueExpectations": "Security descriptor for server requirements",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG Flags (example: ALPC_CONNECTFLAG_SYNC_CONNECTION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00e0",
        "additionalComment": "Pointer to ALPC_PORT_ATTRIBUTES PortAttributes (dummy pointer, optional, may be None)",
        "structurePointer": "ALPC_PORT_ATTRIBUTES",
        "structureRef": "struct68",
        "structureValueExpectations": "Port attribute structure",
        "pointedValue": None
      },
      {
        "value": "0xbadd00f0",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES ClientPortObjectAttributes (dummy pointer, optional, may be None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct69",
        "structureValueExpectations": "Object attributes for client port",
        "pointedValue": None
      },
      {
        "value": "0xbadd0100",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES ConnectionPortObjectAttributes (dummy pointer, optional, may be None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct70",
        "structureValueExpectations": "Object attributes for connection port",
        "pointedValue": None
      },
      {
        "value": "0xbadd0110",
        "additionalComment": "Pointer to HANDLE PortHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct63": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x00000001dcd65000",
            "fieldComment": "Timeout value: 2 seconds in 100-nanosecond intervals"
          }
        ]
      },
      "struct64": {
        "type": "ALPC_MESSAGE_ATTRIBUTES",
        "fields": [
          {
            "fieldName": "AllocatedAttributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Example: ALPC_MESSAGE_SECURITY_ATTRIBUTE"
          },
          {
            "fieldName": "ValidAttributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Example: ALPC_MESSAGE_SECURITY_ATTRIBUTE"
          }
        ]
      },
      "struct65": {
        "type": "ALPC_MESSAGE_ATTRIBUTES",
        "fields": [
          {
            "fieldName": "AllocatedAttributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "No attributes allocated"
          },
          {
            "fieldName": "ValidAttributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "No attributes valid"
          }
        ]
      },
      "struct66": {
        "type": "PORT_MESSAGE",
        "fields": [
          {
            "fieldName": "u1.Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0040",
            "fieldComment": "Message length"
          },
          {
            "fieldName": "u1.ZeroInit",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "Zero-initialized"
          },
          {
            "fieldName": "u2.Type",
            "fieldType": "USHORT",
            "fieldValue": "0x0001",
            "fieldComment": "Message type"
          },
          {
            "fieldName": "u2.DataInfoOffset",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "No data info"
          },
          {
            "fieldName": "ClientId.UniqueProcess",
            "fieldType": "HANDLE",
            "fieldValue": "0x99995555",
            "fieldComment": "Dummy process ID"
          },
          {
            "fieldName": "ClientId.UniqueThread",
            "fieldType": "HANDLE",
            "fieldValue": "0x00000000",
            "fieldComment": "Dummy thread ID"
          },
          {
            "fieldName": "MessageId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Message ID"
          },
          {
            "fieldName": "ClientViewSize",
            "fieldType": "SIZE_T",
            "fieldValue": "0x00000000",
            "fieldComment": "No client view"
          }
        ]
      },
      "struct67": {
        "type": "SECURITY_DESCRIPTOR",
        "fields": [
          {
            "fieldName": "Revision",
            "fieldType": "UCHAR",
            "fieldValue": "0x01",
            "fieldComment": "Revision 1"
          },
          {
            "fieldName": "Sbz1",
            "fieldType": "UCHAR",
            "fieldValue": "0x00",
            "fieldComment": "Reserved"
          },
          {
            "fieldName": "Control",
            "fieldType": "USHORT",
            "fieldValue": "0x8004",
            "fieldComment": "SE_DACL_PRESENT | SE_SELF_RELATIVE"
          },
          {
            "fieldName": "Owner",
            "fieldType": "PVOID",
            "fieldValue": "0xbadd0140",
            "fieldComment": "Pointer to owner SID (dummy pointer)"
          },
          {
            "fieldName": "Group",
            "fieldType": "PVOID",
            "fieldValue": "0xbadd0150",
            "fieldComment": "Pointer to group SID (dummy pointer)"
          },
          {
            "fieldName": "Sacl",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          },
          {
            "fieldName": "Dacl",
            "fieldType": "PVOID",
            "fieldValue": "0xbadd0160",
            "fieldComment": "Pointer to DACL (dummy pointer)"
          }
        ]
      },
      "struct68": {
        "type": "ALPC_PORT_ATTRIBUTES",
        "fields": [
          {
            "fieldName": "Flags",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "ALPC_PORTFLG_ALLOW_LPC_REQUESTS"
          },
          {
            "fieldName": "SecurityQos.Length",
            "fieldType": "ULONG",
            "fieldValue": "0x0000000c",
            "fieldComment": "SECURITY_QUALITY_OF_SERVICE size"
          },
          {
            "fieldName": "MaxMessageLength",
            "fieldType": "ULONG",
            "fieldValue": "0x00001000",
            "fieldComment": "4096 bytes"
          },
          {
            "fieldName": "MemoryBandwidth",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          },
          {
            "fieldName": "MaxPoolUsage",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          },
          {
            "fieldName": "MaxSectionSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          },
          {
            "fieldName": "MaxViewSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          },
          {
            "fieldName": "MaxTotalSectionSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          },
          {
            "fieldName": "DupObjectTypes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          }
        ]
      },
      "struct69": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      },
      "struct70": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtAlpcImpersonateClientContainerOfPort": {
    "ntFunc": "NtAlpcImpersonateClientContainerOfPort",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Flags (default: 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0120",
        "additionalComment": "Pointer to PORT_MESSAGE Message (dummy pointer)",
        "structurePointer": "PORT_MESSAGE",
        "structureRef": "struct71",
        "structureValueExpectations": "Message to impersonate",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct71": {
        "type": "PORT_MESSAGE",
        "fields": [
          {
            "fieldName": "u1.Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0040",
            "fieldComment": "Message length"
          },
          {
            "fieldName": "u1.ZeroInit",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "Zero-initialized"
          },
          {
            "fieldName": "u2.Type",
            "fieldType": "USHORT",
            "fieldValue": "0x0001",
            "fieldComment": "Message type"
          },
          {
            "fieldName": "u2.DataInfoOffset",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "No data info"
          },
          {
            "fieldName": "ClientId.UniqueProcess",
            "fieldType": "HANDLE",
            "fieldValue": "0x99996666",
            "fieldComment": "Dummy process ID"
          },
          {
            "fieldName": "ClientId.UniqueThread",
            "fieldType": "HANDLE",
            "fieldValue": "0x00000000",
            "fieldComment": "Dummy thread ID"
          },
          {
            "fieldName": "MessageId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000002",
            "fieldComment": "Message ID"
          },
          {
            "fieldName": "ClientViewSize",
            "fieldType": "SIZE_T",
            "fieldValue": "0x00000000",
            "fieldComment": "No client view"
          }
        ]
      }
    }
  },
  "NtAreMappedFilesTheSame": {
    "ntFunc": "NtAreMappedFilesTheSame",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PVOID File2MappedAsFile (None, no file mapped)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID File1MappedAsAnImage (None, no image mapped)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAssignProcessToJobObject": {
    "ntFunc": "NtAssignProcessToJobObject",
    "pushes": [
      {
        "value": "0x00004444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00003333",
        "additionalComment": "HANDLE JobHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateJobSet": {
    "ntFunc": "NtCreateJobSet",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "ULONG JobSetCount (1 job in set)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to JOB_SET_ARRAY (dummy pointer)",
        "structurePointer": "JOB_SET_ARRAY",
        "structureRef": "struct72",
        "structureValueExpectations": "Array of JOB_SET_ARRAY structures describing jobs to create.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Flags (0, no special flags)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct72": {
        "type": "JOB_SET_ARRAY",
        "fields": [
          {
            "fieldName": "JobHandle",
            "fieldType": "HANDLE",
            "fieldValue": "0x00003333",
            "fieldComment": "Dummy job handle"
          },
          {
            "fieldName": "MemberLevel",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Member level 1"
          },
          {
            "fieldName": "Flags",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "No special flags"
          }
        ]
      }
    }
  },
  "NtCreateJobObject": {
    "ntFunc": "NtCreateJobObject",
    "pushes": [
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct73",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00020000",
        "additionalComment": "ACCESS_MASK DesiredAccess (JOB_OBJECT_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to HANDLE JobHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct73": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (no name)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtOpenJobObject": {
    "ntFunc": "NtOpenJobObject",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct74",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00020000",
        "additionalComment": "ACCESS_MASK DesiredAccess (JOB_OBJECT_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to HANDLE JobHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct74": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (no name)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtQueryInformationJobObject": {
    "ntFunc": "NtQueryInformationJobObject",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer, optional, may be None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000040"
      },
      {
        "value": "0x00000040",
        "additionalComment": "ULONG JobInformationLength (typical size for JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to JobInformation buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "JOBOBJECTINFOCLASS JobInformationClass (JobObjectBasicAccountingInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE JobHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetInformationJobObject": {
    "ntFunc": "NtSetInformationJobObject",
    "pushes": [
      {
        "value": "0x00000010",
        "additionalComment": "ULONG JobInformationLength (typical size for JOBOBJECT_BASIC_LIMIT_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to JobInformation buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000002",
        "additionalComment": "JOBOBJECTINFOCLASS JobInformationClass (JobObjectBasicLimitInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE JobHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtTerminateJobObject": {
    "ntFunc": "NtTerminateJobObject",
    "pushes": [
      {
        "value": "0xC0000001",
        "additionalComment": "NTSTATUS ExitStatus (STATUS_UNSUCCESSFUL)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE JobHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCallEnclave": {
    "ntFunc": "NtCallEnclave",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Optional PVOID (None, not used in this example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN WaitForThread (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "PVOID Parameter (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xDEADBEEF"
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "PENCLAVE_ROUTINE Routine (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00401000"
      }
    ],
    "structures": {}
  },
  "NtTerminateEnclave": {
    "ntFunc": "NtTerminateEnclave",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN WaitForThread (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00400000",
        "additionalComment": "PVOID BaseAddress (typical enclave base address)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtInitializeEnclave": {
    "ntFunc": "NtInitializeEnclave",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG Result (dummy pointer, optional out parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000020",
        "additionalComment": "EnclaveInformationLength (32 bytes, typical for SGX)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to EnclaveInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadcafe0"
      },
      {
        "value": "0x00400000",
        "additionalComment": "BaseAddress (typical enclave base address)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateEnclave": {
    "ntFunc": "NtCreateEnclave",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to ULONG Result (dummy pointer, optional out parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000020",
        "additionalComment": "EnclaveInformationLength (32 bytes, typical for SGX)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to EnclaveInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadcafe0"
      },
      {
        "value": "0x00000001",
        "additionalComment": "EnclaveType (ENCLAVE_TYPE_SGX)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "InitialCommitment (4 KB, typical page size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00100000",
        "additionalComment": "Size (1 MB enclave)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ZeroBits (no address restriction)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to PVOID BaseAddress (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00400000"
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtLoadEnclaveData": {
    "ntFunc": "NtLoadEnclaveData",
    "pushes": [
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to ULONG Result (dummy pointer, optional out parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to SIZE_T BytesWritten (dummy pointer, optional out parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00001000"
      },
      {
        "value": "0x00000010",
        "additionalComment": "PageInformationLength (16 bytes, typical for SGX)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to PageInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadcafe0"
      },
      {
        "value": "0x00000040",
        "additionalComment": "Protect (PAGE_EXECUTE_READWRITE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "BufferSize (4 KB, typical page size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to Buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadcafe0"
      },
      {
        "value": "0x00400000",
        "additionalComment": "BaseAddress (typical enclave base address)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateSectionEx": {
    "ntFunc": "NtCreateSectionEx",
    "pushes": [
      {
        "value": "0x00000002",
        "additionalComment": "ExtendedParameterCount (2 parameters)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to MEM_EXTENDED_PARAMETER array (dummy pointer)",
        "structurePointer": "MEM_EXTENDED_PARAMETER",
        "structureRef": "struct75",
        "structureValueExpectations": "Array of MEM_EXTENDED_PARAMETER structures.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "FileHandle (None, pagefile-backed section)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x08000000",
        "additionalComment": "AllocationAttributes (SEC_COMMIT)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000004",
        "additionalComment": "SectionPageProtection (PAGE_READWRITE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00a0",
        "additionalComment": "Pointer to LARGE_INTEGER MaximumSize (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct76",
        "structureValueExpectations": "Maximum size of the section in bytes.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct77",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F000F",
        "additionalComment": "DesiredAccess (SECTION_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00c0",
        "additionalComment": "Pointer to HANDLE SectionHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct75": {
        "type": "MEM_EXTENDED_PARAMETER",
        "fields": [
          {
            "fieldName": "Type",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000001",
            "fieldComment": "MEM_EXTENDED_PARAMETER_TYPE"
          },
          {
            "fieldName": "Reserved",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Reserved, must be zero"
          },
          {
            "fieldName": "Value",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000001",
            "fieldComment": "Sample value"
          }
        ]
      },
      "struct76": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x000200000",
            "fieldComment": "2 MB section size"
          }
        ]
      },
      "struct77": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (unnamed section)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtMapViewOfSectionEx": {
    "ntFunc": "NtMapViewOfSectionEx",
    "pushes": [
      {
        "value": "0x00000002",
        "additionalComment": "ExtendedParameterCount (2 parameters)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00d0",
        "additionalComment": "Pointer to MEM_EXTENDED_PARAMETER array (dummy pointer)",
        "structurePointer": "MEM_EXTENDED_PARAMETER",
        "structureRef": "struct78",
        "structureValueExpectations": "Array of MEM_EXTENDED_PARAMETER structures.",
        "pointedValue": None
      },
      {
        "value": "0x00000040",
        "additionalComment": "Win32Protect (PAGE_EXECUTE_READWRITE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "AllocationType (MEM_COMMIT)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00e0",
        "additionalComment": "Pointer to SIZE_T ViewSize (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00100000"
      },
      {
        "value": "0xbadd00f0",
        "additionalComment": "Pointer to LARGE_INTEGER SectionOffset (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct79",
        "structureValueExpectations": "Offset into the section.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0100",
        "additionalComment": "Pointer to PVOID BaseAddress (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00400000"
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000888",
        "additionalComment": "HANDLE SectionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct78": {
        "type": "MEM_EXTENDED_PARAMETER",
        "fields": [
          {
            "fieldName": "Type",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000002",
            "fieldComment": "MEM_EXTENDED_PARAMETER_TYPE"
          },
          {
            "fieldName": "Reserved",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Reserved, must be zero"
          },
          {
            "fieldName": "Value",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000002",
            "fieldComment": "Sample value"
          }
        ]
      },
      "struct79": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Offset 0"
          }
        ]
      }
    }
  },
  "NtUnmapViewOfSectionEx": {
    "ntFunc": "NtUnmapViewOfSectionEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Flags (default: 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00400000",
        "additionalComment": "BaseAddress (commonly the base of a mapped section)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreatePartition": {
    "ntFunc": "NtCreatePartition",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "PreferredNode (example: NUMA node 1)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer, typically None for unnamed partition)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct80",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F0001",
        "additionalComment": "DesiredAccess (example: PARTITION_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to HANDLE PartitionHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ParentPartitionHandle (dummy handle, often None for root)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct80": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (unnamed partition)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtOpenPartition": {
    "ntFunc": "NtOpenPartition",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer, typically points to named partition)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct81",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00120001",
        "additionalComment": "DesiredAccess (example: PARTITION_QUERY_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to HANDLE PartitionHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct81": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd0060",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer, named partition)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtManagePartition": {
    "ntFunc": "NtManagePartition",
    "pushes": [
      {
        "value": "0x00000020",
        "additionalComment": "PartitionInformationLength (example: 32 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to PartitionInformation buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "PARTITION_INFORMATION_CLASS (example: PartitionBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE SourceHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000555",
        "additionalComment": "HANDLE TargetHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtMapUserPhysicalPages": {
    "ntFunc": "NtMapUserPhysicalPages",
    "pushes": [
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to ULONG_PTR UserPfnArray (dummy pointer, typically array of page frame numbers)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000010",
        "additionalComment": "NumberOfPages (example: 16 pages)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00500000",
        "additionalComment": "VirtualAddress (example: base address to map physical pages)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAllocateUserPhysicalPagesEx": {
    "ntFunc": "NtAllocateUserPhysicalPagesEx",
    "pushes": [
      {
        "value": "0x00000002",
        "additionalComment": "ULONG ExtendedParameterCount (requesting 2 extended parameters)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to MEM_EXTENDED_PARAMETER array (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0100"
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to ULONG_PTR UserPfnArray (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to ULONG_PTR NumberOfPages (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtGetWriteWatch": {
    "ntFunc": "NtGetWriteWatch",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to ULONG Granularity (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00001000"
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to ULONG_PTR EntriesInUserAddressArray (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000008"
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to PVOID UserAddressArray (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00400000"
      },
      {
        "value": "0x00002000",
        "additionalComment": "SIZE_T RegionSize (8 KB region)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00400000",
        "additionalComment": "PVOID BaseAddress (typical image base)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG Flags (WRITE_WATCH_FLAG_RESET)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtResetWriteWatch": {
    "ntFunc": "NtResetWriteWatch",
    "pushes": [
      {
        "value": "0x00002000",
        "additionalComment": "SIZE_T RegionSize (8 KB region)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00400000",
        "additionalComment": "PVOID BaseAddress (typical image base)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreatePagingFile": {
    "ntFunc": "NtCreatePagingFile",
    "pushes": [
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to LARGE_INTEGER ActualSize (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct82",
        "structureValueExpectations": "Actual size of the paging file in bytes.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to LARGE_INTEGER MaximumSize (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct83",
        "structureValueExpectations": "Maximum size of the paging file in bytes.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to LARGE_INTEGER MinimumSize (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct84",
        "structureValueExpectations": "Minimum size of the paging file in bytes.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to UNICODE_STRING PageFileName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct85",
        "structureValueExpectations": "Path to the paging file.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct82": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000800000000",
            "fieldComment": "Actual size: 2 GB"
          }
        ]
      },
      "struct83": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000001000000000",
            "fieldComment": "Maximum size: 4 GB"
          }
        ]
      },
      "struct84": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000200000000",
            "fieldComment": "Minimum size: 512 MB"
          }
        ]
      },
      "struct85": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Length in bytes (16 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0040",
            "fieldComment": "Buffer capacity in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd00c0",
            "fieldComment": "Pointer to paging file path string (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtCancelIoFileEx": {
    "ntFunc": "NtCancelIoFileEx",
    "pushes": [
      {
        "value": "0xbadd00a0",
        "additionalComment": "Pointer to IO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct86",
        "structureValueExpectations": "Receives I/O completion status.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to IO_STATUS_BLOCK IoRequestToCancel (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct87",
        "structureValueExpectations": "Pointer to I/O request to cancel.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct86": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "Operation status (initialized to STATUS_SUCCESS)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Operation-specific information"
          }
        ]
      },
      "struct87": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0xc0000120",
            "fieldComment": "STATUS_CANCELLED"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Operation-specific information"
          }
        ]
      }
    }
  },
  "NtCancelWaitCompletionPacket": {
    "ntFunc": "NtCancelWaitCompletionPacket",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN RemoveSignaledPacket (FALSE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000cafe",
        "additionalComment": "HANDLE WaitCompletionPacketHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateWaitCompletionPacket": {
    "ntFunc": "NtCreateWaitCompletionPacket",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES ObjectAttributes (None, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00100001",
        "additionalComment": "ACCESS_MASK DesiredAccess (SYNCHRONIZE | GENERIC_READ)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to HANDLE WaitCompletionPacketHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtCompareObjects": {
    "ntFunc": "NtCompareObjects",
    "pushes": [
      {
        "value": "0x0000beef",
        "additionalComment": "HANDLE Handle2 (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000cafe",
        "additionalComment": "HANDLE Handle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCompareTokens": {
    "ntFunc": "NtCompareTokens",
    "pushes": [
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to BOOLEAN Equal (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x0000beef",
        "additionalComment": "HANDLE SecondTokenHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000cafe",
        "additionalComment": "HANDLE FirstTokenHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtContinueEx": {
    "ntFunc": "NtContinueEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PKCONTINUE_ARGUMENT ContinueArgument (None, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PCONTEXT ContextRecord (None, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateCrossVmEvent": {
    "ntFunc": "NtCreateCrossVmEvent",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to GUID (dummy pointer, typically None unless cross-VM event is named)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Unknown parameter, typically None",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Unknown ULONG parameter, typically 0",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer, often None for unnamed event)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct88",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F0003",
        "additionalComment": "DesiredAccess (EVENT_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to HANDLE EventHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct88": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (unnamed event)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtCreateCrossVmMutant": {
    "ntFunc": "NtCreateCrossVmMutant",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to GUID (dummy pointer, typically None unless cross-VM mutant is named)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Unknown parameter, typically None",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Unknown ULONG parameter, typically 0",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer, often None for unnamed mutant)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct89",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F0001",
        "additionalComment": "DesiredAccess (MUTANT_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to HANDLE MutantHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct89": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (unnamed mutant)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtCreateDirectoryObjectEx": {
    "ntFunc": "NtCreateDirectoryObjectEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Flags (typically 0 for default behavior)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ShadowDirectoryHandle (typically None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer, usually required for named directory)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct90",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x000F000F",
        "additionalComment": "DesiredAccess (DIRECTORY_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to HANDLE DirectoryHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct90": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd00e0",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer for directory name)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtCreateIRTimer": {
    "ntFunc": "NtCreateIRTimer",
    "pushes": [
      {
        "value": "0x00100000",
        "additionalComment": "DesiredAccess (TIMER_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to HANDLE TimerHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtCreateLowBoxToken": {
    "ntFunc": "NtCreateLowBoxToken",
    "pushes": [
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to LowBoxStruct (dummy pointer, typically a structure describing the lowbox)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "LowBoxCount (number of entries in LowBoxStruct, typically 1)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00a0",
        "additionalComment": "Pointer to SID_AND_ATTRIBUTES Capabilities (dummy pointer, typically None if no capabilities)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "CapabilityCount (typically 0 if Capabilities is None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to SID AppContainerSid (dummy pointer, typically None if not using AppContainer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00c0",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer, often None for default token)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct91",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00020000",
        "additionalComment": "DesiredAccess (TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE hOrgToken (dummy handle, typically a real token handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00d0",
        "additionalComment": "Pointer to HANDLE LowBoxToken (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct91": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (unnamed token)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtCreateRegistryTransaction": {
    "ntFunc": "NtCreateRegistryTransaction",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Flags (default: 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES ObjectAttributes (None, defaulted)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x000F003F",
        "additionalComment": "DesiredAccess (KEY_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to HANDLE RegistryHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtCreateThreadEx": {
    "ntFunc": "NtCreateThreadEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PVOID AttributeList (None, defaulted)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00200000",
        "additionalComment": "MaximumStackSize (2MB typical)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00100000",
        "additionalComment": "StackSize (1MB typical)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ZeroBits (default: 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000004",
        "additionalComment": "CreateFlags (THREAD_CREATE_FLAGS_CREATE_SUSPENDED)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID Argument (None, defaulted)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00401000",
        "additionalComment": "PVOID StartRoutine (entry point address)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES ObjectAttributes (None, defaulted)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F03FF",
        "additionalComment": "DesiredAccess (THREAD_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to HANDLE ThreadHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtCreateTimer2": {
    "ntFunc": "NtCreateTimer2",
    "pushes": [
      {
        "value": "0x0010001F",
        "additionalComment": "DesiredAccess (TIMER_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Attributes (default: 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES ObjectAttributes (None, defaulted)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID Unknown1 (None, defaulted)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to HANDLE TimerHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtCreateTokenEx": {
    "ntFunc": "NtCreateTokenEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PTOKEN_SOURCE TokenSource (None, defaulted)",
        "structurePointer": "TOKEN_SOURCE",
        "structureRef": None,
        "structureValueExpectations": "SourceName and SourceIdentifier fields.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PTOKEN_DEFAULT_DACL DefaultDacl (None, defaulted)",
        "structurePointer": "TOKEN_DEFAULT_DACL",
        "structureRef": None,
        "structureValueExpectations": "Default discretionary ACL for the token.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PTOKEN_PRIMARY_GROUP PrimaryGroup (None, defaulted)",
        "structurePointer": "TOKEN_PRIMARY_GROUP",
        "structureRef": None,
        "structureValueExpectations": "Primary group SID.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PTOKEN_OWNER Owner (None, defaulted)",
        "structurePointer": "TOKEN_OWNER",
        "structureRef": None,
        "structureValueExpectations": "Owner SID.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PTOKEN_MANDATORY_POLICY TokenMandatoryPolicy (None, defaulted)",
        "structurePointer": "TOKEN_MANDATORY_POLICY",
        "structureRef": None,
        "structureValueExpectations": "Mandatory policy settings.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PTOKEN_GROUPS DeviceGroups (None, defaulted)",
        "structurePointer": "TOKEN_GROUPS",
        "structureRef": None,
        "structureValueExpectations": "Device group SIDs.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes (None, defaulted)",
        "structurePointer": "TOKEN_SECURITY_ATTRIBUTES_INFORMATION",
        "structureRef": None,
        "structureValueExpectations": "Device security attributes.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes (None, defaulted)",
        "structurePointer": "TOKEN_SECURITY_ATTRIBUTES_INFORMATION",
        "structureRef": None,
        "structureValueExpectations": "User security attributes.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PTOKEN_PRIVILEGES Privileges (None, defaulted)",
        "structurePointer": "TOKEN_PRIVILEGES",
        "structureRef": None,
        "structureValueExpectations": "Token privileges.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PTOKEN_GROUPS Groups (None, defaulted)",
        "structurePointer": "TOKEN_GROUPS",
        "structureRef": None,
        "structureValueExpectations": "Group SIDs.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PTOKEN_USER User (None, defaulted)",
        "structurePointer": "TOKEN_USER",
        "structureRef": None,
        "structureValueExpectations": "User SID.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PLARGE_INTEGER ExpirationTime (None, defaulted)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": None,
        "structureValueExpectations": "Expiration time as a 64-bit integer.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PLUID AuthenticationId (None, defaulted)",
        "structurePointer": "LUID",
        "structureRef": None,
        "structureValueExpectations": "Locally unique identifier.",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "TokenType (TokenPrimary)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES ObjectAttributes (None, defaulted)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x000F01FF",
        "additionalComment": "DesiredAccess (TOKEN_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to HANDLE TokenHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtCreateUserProcess": {
    "ntFunc": "NtCreateUserProcess",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PVOID AttributeList (None, defaulted)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID CreateInfo (None, defaulted)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PRTL_USER_PROCESS_PARAMETERS ProcessParameters (None, defaulted)",
        "structurePointer": "RTL_USER_PROCESS_PARAMETERS",
        "structureRef": None,
        "structureValueExpectations": "Process parameters structure.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ThreadFlags (default: 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ProcessFlags (default: 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES ThreadObjectAttributes (None, defaulted)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES ProcessObjectAttributes (None, defaulted)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F0FFF",
        "additionalComment": "ThreadDesiredAccess (THREAD_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x001F0FFF",
        "additionalComment": "ProcessDesiredAccess (PROCESS_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to HANDLE ThreadHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to HANDLE ProcessHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtCreateWaitablePort": {
    "ntFunc": "NtCreateWaitablePort",
    "pushes": [
      {
        "value": "0x00010000",
        "additionalComment": "ULONG MaxPoolUsage (example: 64KB)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000400",
        "additionalComment": "ULONG MaxMsgLength (example: 1024 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000040",
        "additionalComment": "ULONG MaxConnectionInfoLength (example: 64 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES ObjectAttributes (None, defaulted)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Optional: Length, RootDirectory, ObjectName, Attributes, SecurityDescriptor, SecurityQualityOfService.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to HANDLE PortHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtCreateWnfStateName": {
    "ntFunc": "NtCreateWnfStateName",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PSECURITY_DESCRIPTOR SecurityDescriptor (None, defaulted)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": "Optional security descriptor pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG MaximumStateSize (example: 4096 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID TypeId (None, defaulted)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": "Optional GUID pointer for type.",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN PersistData (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "ULONG DataScope (WnfDataScopeSession)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000003",
        "additionalComment": "ULONG Lifetime (WnfTemporaryStateName)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to C WNF_STATE_NAME StateName (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtDebugContinue": {
    "ntFunc": "NtDebugContinue",
    "pushes": [
      {
        "value": "0xC000013A",
        "additionalComment": "NTSTATUS Status (example: STATUS_CONTROL_C_EXIT)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PCLIENT_ID ClientId (None, defaulted)",
        "structurePointer": "CLIENT_ID",
        "structureRef": None,
        "structureValueExpectations": "Optional pointer to CLIENT_ID structure.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE DebugHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtDeleteBootEntry": {
    "ntFunc": "NtDeleteBootEntry",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to UNICODE_STRING Name (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct92",
        "structureValueExpectations": "UNICODE_STRING structure with buffer pointing to boot entry name.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct92": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Length in bytes (16 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0040",
            "fieldComment": "Maximum buffer size in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0040",
            "fieldComment": "Pointer to boot entry name string (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtDeleteDriverEntry": {
    "ntFunc": "NtDeleteDriverEntry",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to UNICODE_STRING Name (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct93",
        "structureValueExpectations": "UNICODE_STRING structure with buffer pointing to driver entry name.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct93": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0018",
            "fieldComment": "Length in bytes (12 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Maximum buffer size in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0050",
            "fieldComment": "Pointer to driver entry name string (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtDeleteWnfStateData": {
    "ntFunc": "NtDeleteWnfStateData",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "ExplicitScope (None, default scope)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xaabbccdd",
        "additionalComment": "PCWNF_STATE_NAME StateName (example state name value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtDeleteWnfStateName": {
    "ntFunc": "NtDeleteWnfStateName",
    "pushes": [
      {
        "value": "0xaabbccdd",
        "additionalComment": "PCWNF_STATE_NAME StateName (example state name value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtDirectGraphicsCall": {
    "ntFunc": "NtDirectGraphicsCall",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "ULONG Unknown (example nonzero value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "ULONG Unknown (example nonzero value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000003",
        "additionalComment": "ULONG Unknown (example nonzero value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000004",
        "additionalComment": "ULONG Unknown (example nonzero value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000005",
        "additionalComment": "ULONG Unknown (example nonzero value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtFilterBootOption": {
    "ntFunc": "NtFilterBootOption",
    "pushes": [
      {
        "value": "0x00000010",
        "additionalComment": "ULONG DataSize (example: 16 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "PVOID Data (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xdeadbeef"
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG ElementType (example: 1, e.g., BootApplication)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "ULONG ObjectType (example: 2, e.g., BootObject)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000003",
        "additionalComment": "ULONG FilterOperation (example: 3, e.g., FilterDelete)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtFilterToken": {
    "ntFunc": "NtFilterToken",
    "pushes": [
      {
        "value": "0xbadd0010",
        "additionalComment": "PHANDLE NewTokenHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "PTOKEN_GROUPS RestrictedSids (dummy pointer, typically None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "PTOKEN_PRIVILEGES PrivilegesToDelete (dummy pointer, typically None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "PTOKEN_GROUPS SidsToDisable (dummy pointer, typically None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Flags (default: 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ExistingTokenHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtFilterTokenEx": {
    "ntFunc": "NtFilterTokenEx",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to HANDLE NewTokenHandle (dummy pointer, will receive new token handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "RestrictedDeviceGroups (None, no device groups restricted)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "RestrictedDeviceAttributes (None, no device attributes restricted)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "RestrictedUserAttributes (None, no user attributes restricted)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "DeviceGroupsToDisable (None, no device groups to disable)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "DeviceClaimsToDisable (None, no device claims to disable)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "DisableDeviceClaimsCount (0, no device claims to disable)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "UserClaimsToDisable (None, no user claims to disable)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "DisableUserClaimsCount (0, no user claims to disable)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "RestrictedSids (None, no SIDs restricted)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PrivilegesToDelete (None, no privileges to delete)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "SidsToDisable (None, no SIDs to disable)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Flags (0, default behavior)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE TokenHandle (dummy handle to existing token)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtGetCachedSigningLevel": {
    "ntFunc": "NtGetCachedSigningLevel",
    "pushes": [
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to ULONG Flags (dummy pointer, will receive flags)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to ULONG ThumbprintSize (dummy pointer, will receive thumbprint size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000014"
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to UCHAR Thumbprint (dummy pointer, will receive thumbprint)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xdeadbeef"
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to BYTE SigningLevel (dummy pointer, will receive signing level)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x06"
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to ULONG Flags (dummy pointer, will receive flags)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00000888",
        "additionalComment": "HANDLE File (dummy file handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtGetCompleteWnfStateSubscription": {
    "ntFunc": "NtGetCompleteWnfStateSubscription",
    "pushes": [
      {
        "value": "0x00000030",
        "additionalComment": "DescriptorSize (typical size value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to NewDeliveryDescriptor (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "OldDescriptorStatus (0, default/unused)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "OldDescriptorEventMask (0, default/unused)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to ULONG OldSubscriptionId (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to WNF_STATE_NAME OldDescriptorStateName (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xaabbccdd"
      }
    ],
    "structures": {}
  },
  "NtGetContextThread": {
    "ntFunc": "NtGetContextThread",
    "pushes": [
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to CONTEXT structure (dummy pointer)",
        "structurePointer": "CONTEXT",
        "structureRef": "struct94",
        "structureValueExpectations": "Thread context structure for receiving thread state.",
        "pointedValue": None
      },
      {
        "value": "0x00000abc",
        "additionalComment": "HANDLE ThreadHandle (dummy thread handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct94": {
        "type": "CONTEXT",
        "fields": [
          {
            "fieldName": "ContextFlags",
            "fieldType": "ULONG",
            "fieldValue": "0x00010007",
            "fieldComment": "CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS"
          },
          {
            "fieldName": "Eip",
            "fieldType": "ULONG",
            "fieldValue": "0x00401000",
            "fieldComment": "Instruction pointer"
          },
          {
            "fieldName": "Esp",
            "fieldType": "ULONG",
            "fieldValue": "0x0012ffb0",
            "fieldComment": "Stack pointer"
          },
          {
            "fieldName": "Eax",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "General purpose register"
          }
        ]
      }
    }
  },
  "NtGetCurrentProcessorNumber": {
    "ntFunc": "NtGetCurrentProcessorNumber",
    "pushes": [],
    "structures": {}
  },
  "NtGetCurrentProcessorNumberEx": {
    "ntFunc": "NtGetCurrentProcessorNumberEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for optional PULONG ProcessorNumber parameter",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtGetDevicePowerState": {
    "ntFunc": "NtGetDevicePowerState",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None pointer for PDEVICE_POWER_STATE State (output parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000DEAD",
        "additionalComment": "HANDLE DeviceHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtImpersonateAnonymousToken": {
    "ntFunc": "NtImpersonateAnonymousToken",
    "pushes": [
      {
        "value": "0x0000BEEF",
        "additionalComment": "HANDLE ThreadHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtInitializeRegistry": {
    "ntFunc": "NtInitializeRegistry",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "Options = 1 (e.g., INITREG_CREATE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtInitiatePowerAction": {
    "ntFunc": "NtInitiatePowerAction",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "Asynch = TRUE",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Flags = 0 (no special flags)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "SYSTEM_POWER_STATE = PowerSystemSleeping1 (S1)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "POWER_ACTION = PowerActionSleep",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtIsSystemResumeAutomatic": {
    "ntFunc": "NtIsSystemResumeAutomatic",
    "pushes": [],
    "structures": {}
  },
  "NtLoadKeyEx": {
    "ntFunc": "NtLoadKeyEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to IO_STATUS_BLOCK IoStatusBlock (None, not used in this example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "CallbackReserved (None, reserved parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ObjectContext (None, reserved parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Reserved (None, reserved parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "TrustClassKey (None, not used in this example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Flags (0, default flags)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES SourceFile (None, not used in this example)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Optional OBJECT_ATTRIBUTES for source file. None if not used.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES TargetKey (None, not used in this example)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "OBJECT_ATTRIBUTES for target key. None if not used.",
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtLockProductActivationKeys": {
    "ntFunc": "NtLockProductActivationKeys",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to ULONG SafeMode (None, not used in this example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to ULONG ProductBuild (None, not used in this example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtLockRegistryKey": {
    "ntFunc": "NtLockRegistryKey",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE KeyHandle (None, not used in this example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtMakePermanentObject": {
    "ntFunc": "NtMakePermanentObject",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE Object (None, not used in this example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtManageHotPatch": {
    "ntFunc": "NtManageHotPatch",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Unknown parameter, commonly None",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "Unknown ULONG, sample nonzero value",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONGLONG (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x0000000000000002"
      },
      {
        "value": "0x00000010",
        "additionalComment": "Unknown ULONG, sample value",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtMapCMFModule": {
    "ntFunc": "NtMapCMFModule",
    "pushes": [
      {
        "value": "0xbadd0010",
        "additionalComment": "Optional pointer to pointer to mapped module (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00400000"
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Optional pointer to ULONG (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00001000"
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Optional pointer to ULONG (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Optional pointer to ULONG (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000002",
        "additionalComment": "ULONG Index, sample value",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG What, sample value",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtModifyBootEntry": {
    "ntFunc": "NtModifyBootEntry",
    "pushes": [
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to BOOT_ENTRY (dummy pointer)",
        "structurePointer": "BOOT_ENTRY",
        "structureRef": "struct95",
        "structureValueExpectations": "Boot entry structure with identifier, attributes, and file path.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct95": {
        "type": "BOOT_ENTRY",
        "fields": [
          {
            "fieldName": "Version",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Boot entry version"
          },
          {
            "fieldName": "Length",
            "fieldType": "ULONG",
            "fieldValue": "0x00000100",
            "fieldComment": "Size of BOOT_ENTRY"
          },
          {
            "fieldName": "Id",
            "fieldType": "ULONG",
            "fieldValue": "0x00000010",
            "fieldComment": "Boot entry identifier"
          },
          {
            "fieldName": "Attributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000002",
            "fieldComment": "Sample attribute flags"
          },
          {
            "fieldName": "FriendlyNameOffset",
            "fieldType": "ULONG",
            "fieldValue": "0x00000020",
            "fieldComment": "Offset to friendly name"
          },
          {
            "fieldName": "BootFilePathOffset",
            "fieldType": "ULONG",
            "fieldValue": "0x00000040",
            "fieldComment": "Offset to boot file path"
          }
        ]
      }
    }
  },
  "NtModifyDriverEntry": {
    "ntFunc": "NtModifyDriverEntry",
    "pushes": [
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to DRIVER_ENTRY (dummy pointer)",
        "structurePointer": "DRIVER_ENTRY",
        "structureRef": "struct96",
        "structureValueExpectations": "Driver entry structure with version, flags, and service name.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct96": {
        "type": "DRIVER_ENTRY",
        "fields": [
          {
            "fieldName": "Version",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Driver entry version"
          },
          {
            "fieldName": "Length",
            "fieldType": "ULONG",
            "fieldValue": "0x00000080",
            "fieldComment": "Size of DRIVER_ENTRY"
          },
          {
            "fieldName": "Id",
            "fieldType": "ULONG",
            "fieldValue": "0x00000005",
            "fieldComment": "Driver entry identifier"
          },
          {
            "fieldName": "Attributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Sample attribute flags"
          },
          {
            "fieldName": "ServiceNameOffset",
            "fieldType": "ULONG",
            "fieldValue": "0x00000010",
            "fieldComment": "Offset to service name"
          }
        ]
      }
    }
  },
  "NtNotifyChangeDirectoryFileEx": {
    "ntFunc": "NtNotifyChangeDirectoryFileEx",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "DIRECTORY_NOTIFY_INFORMATION_CLASS, e.g., DirectoryNotifyInformationClassBasic",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN WatchTree, TRUE",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000010A",
        "additionalComment": "ULONG CompletionFilter, e.g., FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG Length, sample buffer size",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to IO_STATUS_BLOCK (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct97",
        "structureValueExpectations": "Status and information fields for I/O completion.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to APC context (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00A0",
        "additionalComment": "Pointer to IO_APC_ROUTINE (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE Event (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000333",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct97": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "Operation status"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Operation-specific information"
          }
        ]
      }
    }
  },
  "NtNotifyChangeMultipleKeys": {
    "ntFunc": "NtNotifyChangeMultipleKeys",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Asynchronous = FALSE (synchronous operation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "BufferSize = 4096 bytes (typical buffer size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Buffer = None (no output buffer provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "WatchTree = TRUE (monitor subkeys recursively)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000010",
        "additionalComment": "CompletionFilter = REG_NOTIFY_CHANGE_LAST_SET",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to IO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct98",
        "structureValueExpectations": "Status and information fields for I/O completion.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ApcContext = None (no APC context)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ApcRoutine = None (no APC routine)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Event = None (no event handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "SubordinateObjects = None (no subordinate OBJECT_ATTRIBUTES)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "Count = 1 (monitoring one key)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000abcd",
        "additionalComment": "MasterKeyHandle (dummy handle value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct98": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "STATUS_SUCCESS (initial value)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "No information yet"
          }
        ]
      }
    }
  },
  "NtOpenKeyEx": {
    "ntFunc": "NtOpenKeyEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "OpenOptions = 0 (default options)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct99",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00020019",
        "additionalComment": "DesiredAccess = KEY_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to HANDLE KeyHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct99": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd0070",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtOpenKeyedEvent": {
    "ntFunc": "NtOpenKeyedEvent",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct100",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F0003",
        "additionalComment": "DesiredAccess = EVENT_ALL_ACCESS",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to HANDLE KeyedEventHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct100": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd0080",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtOpenRegistryTransaction": {
    "ntFunc": "NtOpenRegistryTransaction",
    "pushes": [
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct101",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x000F003F",
        "additionalComment": "DesiredAccess = TRANSACTION_ALL_ACCESS",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to HANDLE RegistryHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct101": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd0090",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtPlugPlayControl": {
    "ntFunc": "NtPlugPlayControl",
    "pushes": [
      {
        "value": "0x00001000",
        "additionalComment": "BufferSize = 4096 bytes (typical size for device info)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Buffer = None (no buffer provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000000D",
        "additionalComment": "Class = PlugPlayControlEnumerateDevice (example class value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtPssCaptureVaSpaceBulk": {
    "ntFunc": "NtPssCaptureVaSpaceBulk",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to SIZE_T ReturnLength (dummy pointer, may be None if not needed)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00001000"
      },
      {
        "value": "0x00002000",
        "additionalComment": "Length (SIZE_T), e.g., 8 KB",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to output Buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00405000"
      },
      {
        "value": "0x00400000",
        "additionalComment": "BaseAddress (PVOID), e.g., start of region",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryAuxiliaryCounterFrequency": {
    "ntFunc": "NtQueryAuxiliaryCounterFrequency",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to ULONGLONG lpAuxiliaryCounterFrequency (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x000F4240"
      }
    ],
    "structures": {}
  },
  "NtQueryDebugFilterState": {
    "ntFunc": "NtQueryDebugFilterState",
    "pushes": [
      {
        "value": "0x00000002",
        "additionalComment": "ULONG Level (e.g., 2 = warning)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG Component (e.g., 1 = default component)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryInformationByName": {
    "ntFunc": "NtQueryInformationByName",
    "pushes": [
      {
        "value": "0x00000005",
        "additionalComment": "FILE_INFORMATION_CLASS FileInformationClass (e.g., FileStandardInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000100",
        "additionalComment": "ULONG Length (256 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to FileInformation buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00406000"
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to IO_STATUS_BLOCK (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct102",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct102": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (no name specified)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtQueryInstallUILanguage": {
    "ntFunc": "NtQueryInstallUILanguage",
    "pushes": [
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to ULONG LanguageId (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000409"
      }
    ],
    "structures": {}
  },
  "NtQueryLicenseValue": {
    "ntFunc": "NtQueryLicenseValue",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG ReturnedLength (dummy pointer, will receive length of value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00000010",
        "additionalComment": "ULONG Length (buffer size in bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to buffer (dummy pointer, will receive value data)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xdeadbeef"
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to ULONG Type (dummy pointer, will receive value type)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to UNICODE_STRING Name (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct103",
        "structureValueExpectations": "UNICODE_STRING describing the license value name.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct103": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Length in bytes of the string"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0100",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtQueryOpenSubKeys": {
    "ntFunc": "NtQueryOpenSubKeys",
    "pushes": [
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to ULONG HandleCount (dummy pointer, will receive count)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000002"
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES TargetKey (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct104",
        "structureValueExpectations": "OBJECT_ATTRIBUTES describing the registry key.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct104": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd0110",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtQueryOpenSubKeysEx": {
    "ntFunc": "NtQueryOpenSubKeysEx",
    "pushes": [
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to ULONG ResultLength (dummy pointer, will receive length)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000020"
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to buffer (dummy pointer, will receive subkey info)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xdeadbeef"
      },
      {
        "value": "0x00000020",
        "additionalComment": "ULONG BufferLength (size of buffer in bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES TargetKey (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct105",
        "structureValueExpectations": "OBJECT_ATTRIBUTES describing the registry key.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct105": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd0120",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtQueryPortInformationProcess": {
    "ntFunc": "NtQueryPortInformationProcess",
    "pushes": [],
    "structures": {}
  },
  "NtQuerySecurityPolicy": {
    "ntFunc": "NtQuerySecurityPolicy",
    "pushes": [
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to ULONG Subsystem (dummy pointer, will receive subsystem value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0xbadd00a0",
        "additionalComment": "Pointer to BOOLEAN Enabled (dummy pointer, will receive enabled flag)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x01"
      },
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to ULONG Unknown (dummy pointer, will receive unknown value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd00c0",
        "additionalComment": "Pointer to UNICODE_STRING Policy (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct106",
        "structureValueExpectations": "UNICODE_STRING describing the policy name.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00d0",
        "additionalComment": "Pointer to UNICODE_STRING SubCategory (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct107",
        "structureValueExpectations": "UNICODE_STRING describing the subcategory.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00e0",
        "additionalComment": "Pointer to UNICODE_STRING Category (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct108",
        "structureValueExpectations": "UNICODE_STRING describing the category.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct106": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x000c",
            "fieldComment": "Length in bytes of the string"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0130",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      },
      "struct107": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0008",
            "fieldComment": "Length in bytes of the string"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0140",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      },
      "struct108": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x000a",
            "fieldComment": "Length in bytes of the string"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0150",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtQueryWnfStateNameInformation": {
    "ntFunc": "NtQueryWnfStateNameInformation",
    "pushes": [
      {
        "value": "0x00001000",
        "additionalComment": "ULONG InfoBufferSize (typical buffer size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to InfoBuffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID ExplicitScope (None, typical usage)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG NameInfoClass (WnfStateNameInfoBasic, typical usage)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xa3bcdef0",
        "additionalComment": "PCWNF_STATE_NAME StateName (example state name value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRenameKey": {
    "ntFunc": "NtRenameKey",
    "pushes": [
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to UNICODE_STRING ReplacementName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct109",
        "structureValueExpectations": "UNICODE_STRING structure describing the new key name.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE KeyHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct109": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Length in bytes of the string"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0020",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtResumeProcess": {
    "ntFunc": "NtResumeProcess",
    "pushes": [
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE hProcess (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRevertContainerImpersonation": {
    "ntFunc": "NtRevertContainerImpersonation",
    "pushes": [],
    "structures": {}
  },
  "NtRollbackRegistryTransaction": {
    "ntFunc": "NtRollbackRegistryTransaction",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "BOOL Wait (TRUE, wait for rollback to complete)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE RegistryHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSaveKeyEx": {
    "ntFunc": "NtSaveKeyEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Flags (default: 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000DEAD",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000BEEF",
        "additionalComment": "HANDLE KeyHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSaveMergedKeys": {
    "ntFunc": "NtSaveMergedKeys",
    "pushes": [
      {
        "value": "0x0000DEAD",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000BEEF",
        "additionalComment": "HANDLE LowPrecedenceKeyHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000FEED",
        "additionalComment": "HANDLE HighPrecedenceKeyHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSecureConnectPort": {
    "ntFunc": "NtSecureConnectPort",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG ConnectDataLength (dummy pointer, commonly None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID ConnectData (None, no connect data)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to ULONG MaxMsgLength (dummy pointer, commonly None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00001000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "PREMOTE_PORT_VIEW pSectionMapInfo (None, optional)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PSID SecurityInfo (None, optional)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PPORT_VIEW pSectionInfo (None, optional)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG QOS (default: 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to UNICODE_STRING Name (dummy pointer, commonly non-None)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct110",
        "structureValueExpectations": "UNICODE_STRING structure describing the port name.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to HANDLE PortHandle (dummy pointer, output)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct110": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Length in bytes of the string"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0040",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0060",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtSetBootOptions": {
    "ntFunc": "NtSetBootOptions",
    "pushes": [
      {
        "value": "0x00000020",
        "additionalComment": "ULONG BufferLength (example: 32 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "PVOID Buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtSetCachedSigningLevel": {
    "ntFunc": "NtSetCachedSigningLevel",
    "pushes": [
      {
        "value": "0x0000DEAD",
        "additionalComment": "HANDLE TargetFile (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "ULONG SourceFileCount (example: 2 files)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to HANDLE SourceFiles (dummy pointer to array)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x0000BEEF"
      },
      {
        "value": "0x00000006",
        "additionalComment": "BYTE InputSigningLevel (example: 6, SIGNING_LEVEL_ANTIMALWARE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG Flags (example: 1, e.g., CACHE_SIGNING_LEVEL_FLAG_USE_FOR_PROCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetCachedSigningLevel2": {
    "ntFunc": "NtSetCachedSigningLevel2",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to LevelInformation (dummy pointer, typically a structure or buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": "Buffer or structure describing signing level information.",
        "pointedValue": "0xbadd1000"
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE TargetFile (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "SourceFileCount (example: 2 source files)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to array of source file handles (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": "Pointer to array of handles to source files.",
        "pointedValue": "0x00000555"
      },
      {
        "value": "0x03",
        "additionalComment": "InputSigningLevel (example: SIGNING_LEVEL_3)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "Flags (example: 1, e.g., CACHE_SIGNING_LEVEL_FLAG_USE_FOR_PROCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetContextThread": {
    "ntFunc": "NtSetContextThread",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to CONTEXT structure (dummy pointer)",
        "structurePointer": "CONTEXT",
        "structureRef": "struct111",
        "structureValueExpectations": "Thread context structure (registers, flags, etc.)",
        "pointedValue": None
      },
      {
        "value": "0x00000666",
        "additionalComment": "HANDLE ThreadHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct111": {
        "type": "CONTEXT",
        "fields": [
          {
            "fieldName": "ContextFlags",
            "fieldType": "ULONG",
            "fieldValue": "0x00010007",
            "fieldComment": "CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS"
          },
          {
            "fieldName": "Eip",
            "fieldType": "ULONG",
            "fieldValue": "0x00401000",
            "fieldComment": "Instruction pointer"
          },
          {
            "fieldName": "Esp",
            "fieldType": "ULONG",
            "fieldValue": "0x0012FFB0",
            "fieldComment": "Stack pointer"
          },
          {
            "fieldName": "Eax",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "General purpose register"
          }
        ]
      }
    }
  },
  "NtSetDebugFilterState": {
    "ntFunc": "NtSetDebugFilterState",
    "pushes": [
      {
        "value": "0x01",
        "additionalComment": "State (TRUE, enable filter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "Level (example: 2, moderate verbosity)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000000A",
        "additionalComment": "Component (example: 10, arbitrary component ID)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetDefaultUILanguage": {
    "ntFunc": "NtSetDefaultUILanguage",
    "pushes": [
      {
        "value": "0x00000409",
        "additionalComment": "LanguageId (en-US, 0x409)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetIRTimer": {
    "ntFunc": "NtSetIRTimer",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to LARGE_INTEGER Time (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct112",
        "structureValueExpectations": "Absolute or relative time value.",
        "pointedValue": None
      },
      {
        "value": "0x00000777",
        "additionalComment": "HANDLE TimerHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct112": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x00000001DCD65000",
            "fieldComment": "Example: 2 seconds in 100-nanosecond intervals"
          }
        ]
      }
    }
  },
  "NtSetInformationDebugObject": {
    "ntFunc": "NtSetInformationDebugObject",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer, optional, often None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00000008",
        "additionalComment": "Length of Buffer (8 bytes, typical for small info classes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to Buffer (dummy pointer, typically to a structure or data)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00000001",
        "additionalComment": "DEBUGOBJECTINFOCLASS Class (DebugObjectFlagsInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE DebugHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetInformationSymbolicLink": {
    "ntFunc": "NtSetInformationSymbolicLink",
    "pushes": [
      {
        "value": "0x00000010",
        "additionalComment": "BufferLength (16 bytes, typical for a small structure or string)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to Buffer (dummy pointer, e.g., to a structure or data)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00000001",
        "additionalComment": "Class (SymbolicLinkGlobalInformation, typical value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE Handle (dummy handle to symbolic link object)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetLdtEntries": {
    "ntFunc": "NtSetLdtEntries",
    "pushes": [
      {
        "value": "0x0000FFFF",
        "additionalComment": "ULONG LdtEntry2H (typical high word for LDT entry)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000F000",
        "additionalComment": "ULONG LdtEntry2L (typical low word for LDT entry)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000020",
        "additionalComment": "ULONG Selector2 (selector index, e.g., 0x20)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000AAAA",
        "additionalComment": "ULONG LdtEntry1H (typical high word for LDT entry)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000A000",
        "additionalComment": "ULONG LdtEntry1L (typical low word for LDT entry)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000018",
        "additionalComment": "ULONG Selector1 (selector index, e.g., 0x18)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetSystemEnvironmentValueEx": {
    "ntFunc": "NtSetSystemEnvironmentValueEx",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "Attributes (EFI_VARIABLE_NON_VOLATILE, typical for UEFI variables)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000008",
        "additionalComment": "BufferLength (8 bytes, typical for a small value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to Buffer (dummy pointer, e.g., to value data)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x12345678"
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to GUID (dummy pointer, typically to a GUID structure)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xA1B2C3D4"
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to UNICODE_STRING Name (dummy pointer, typically to variable name)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0060"
      }
    ],
    "structures": {}
  },
  "NtSetSystemPowerState": {
    "ntFunc": "NtSetSystemPowerState",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "Flags (POWER_ACTION_OVERRIDE_APPS, typical flag)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "SYSTEM_POWER_STATE State (PowerSystemSleeping1, e.g., sleep)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000003",
        "additionalComment": "POWER_ACTION Action (PowerActionSleep, typical action)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetThreadExecutionState": {
    "ntFunc": "NtSetThreadExecutionState",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG PreviousState (dummy pointer, optional, often None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x80000000",
        "additionalComment": "ULONG State (ES_SYSTEM_REQUIRED | ES_CONTINUOUS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetUuidSeed": {
    "ntFunc": "NtSetUuidSeed",
    "pushes": [
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to UCHAR UuidSeed (dummy pointer, typically 16 bytes for UUID seed)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00112233"
      }
    ],
    "structures": {}
  },
  "NtSubscribeWnfStateChange": {
    "ntFunc": "NtSubscribeWnfStateChange",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to ULONG (dummy pointer, optional, often None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG EventMask (example: 1 for basic event mask)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000010",
        "additionalComment": "ULONG ChangeStamp (example: 0x10 for a plausible change stamp)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x41C64E6D",
        "additionalComment": "PCWNF_STATE_NAME StateName (example: plausible state name value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSuspendProcess": {
    "ntFunc": "NtSuspendProcess",
    "pushes": [
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtTranslateFilePath": {
    "ntFunc": "NtTranslateFilePath",
    "pushes": [
      {
        "value": "0x00000100",
        "additionalComment": "ULONG OutputFilePathLength (256 bytes, typical buffer size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to output file path buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG OutputType (example: 1 for FILE_PATH_TYPE_WIN32)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to input file path buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtUnloadKey2": {
    "ntFunc": "NtUnloadKey2",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Flags (default: 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES TargetKey (None, typical for default/unpopulated)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtUnloadKeyEx": {
    "ntFunc": "NtUnloadKeyEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE Event (None, no event signaled on completion)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES TargetKey (None, typical for default/unpopulated)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtUnsubscribeWnfStateChange": {
    "ntFunc": "NtUnsubscribeWnfStateChange",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PCWNF_STATE_NAME StateName (None, no state name specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtVdmControl": {
    "ntFunc": "NtVdmControl",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PVOID ControlData (None, no control data provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG ControlCode (default: 0, e.g., VdmStartExecution)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtWaitForAlertByThreadId": {
    "ntFunc": "NtWaitForAlertByThreadId",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PLARGE_INTEGER Time_Out (None, wait indefinitely)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": None,
        "structureValueExpectations": "Timeout interval as a relative or absolute time value.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE Handle (None, current thread)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtWaitForDebugEvent": {
    "ntFunc": "NtWaitForDebugEvent",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG Result (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to LARGE_INTEGER Time_Out (dummy pointer, None for infinite wait)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct113",
        "structureValueExpectations": "Timeout interval in 100-nanosecond units, or None for infinite.",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN Alertable (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE DebugHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct113": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000000000000",
            "fieldComment": "None for infinite wait"
          }
        ]
      }
    }
  },
  "NtLoadKey3": {
    "ntFunc": "NtLoadKey3",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "ULONG Unknown (example nonzero value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE KeyHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00020019",
        "additionalComment": "ACCESS_MASK DesiredAccess (KEY_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "ULONG LoadArgumentCount (example: 2 arguments)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to LoadArguments (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xdeadbeef"
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Flags (default 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES FileObjectAttributes (dummy pointer, commonly None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct114",
        "structureValueExpectations": "File object attributes, commonly None.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES KeyObjectAttributes (dummy pointer, commonly None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct115",
        "structureValueExpectations": "Key object attributes, commonly None.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct114": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          },
          {
            "fieldName": "Attributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "No attributes"
          },
          {
            "fieldName": "SecurityDescriptor",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      },
      "struct115": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          },
          {
            "fieldName": "Attributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "No attributes"
          },
          {
            "fieldName": "SecurityDescriptor",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtAlpcConnectPort": {
    "ntFunc": "NtAlpcConnectPort",
    "pushes": [
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to LARGE_INTEGER Time_Out (dummy pointer, commonly None)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct116",
        "structureValueExpectations": "Timeout interval in 100-nanosecond units, or None for infinite.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to ALPC_MESSAGE_ATTRIBUTES __INMessageAttributes (dummy pointer, commonly None)",
        "structurePointer": "ALPC_MESSAGE_ATTRIBUTES",
        "structureRef": "struct117",
        "structureValueExpectations": "Input message attributes, commonly None.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to ALPC_MESSAGE_ATTRIBUTES __OUTMessageAttributes (dummy pointer, commonly None)",
        "structurePointer": "ALPC_MESSAGE_ATTRIBUTES",
        "structureRef": "struct118",
        "structureValueExpectations": "Output message attributes, commonly None.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to ULONG BufferLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000400"
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to PORT_MESSAGE ConnectionMessage (dummy pointer)",
        "structurePointer": "PORT_MESSAGE",
        "structureRef": "struct119",
        "structureValueExpectations": "Connection message structure.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00a0",
        "additionalComment": "Pointer to SID RequiredServerSid (dummy pointer, commonly None)",
        "structurePointer": "SID",
        "structureRef": "struct120",
        "structureValueExpectations": "Required server SID, commonly None.",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG Flags (example: ALPC_CONNECTFLAG_SYNC_CONNECTION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to ALPC_PORT_ATTRIBUTES PortAttributes (dummy pointer)",
        "structurePointer": "ALPC_PORT_ATTRIBUTES",
        "structureRef": "struct121",
        "structureValueExpectations": "Port attributes structure.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00c0",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES ObjectAttributes (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct122",
        "structureValueExpectations": "Object attributes for the port.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00d0",
        "additionalComment": "Pointer to UNICODE_STRING PortName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct123",
        "structureValueExpectations": "Name of the ALPC port.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00e0",
        "additionalComment": "Pointer to HANDLE PortHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct116": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000000000000",
            "fieldComment": "None for infinite wait"
          }
        ]
      },
      "struct117": {
        "type": "ALPC_MESSAGE_ATTRIBUTES",
        "fields": [
          {
            "fieldName": "AllocatedAttributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "No attributes"
          },
          {
            "fieldName": "ValidAttributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "No valid attributes"
          }
        ]
      },
      "struct118": {
        "type": "ALPC_MESSAGE_ATTRIBUTES",
        "fields": [
          {
            "fieldName": "AllocatedAttributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "No attributes"
          },
          {
            "fieldName": "ValidAttributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "No valid attributes"
          }
        ]
      },
      "struct119": {
        "type": "PORT_MESSAGE",
        "fields": [
          {
            "fieldName": "u1.Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0040",
            "fieldComment": "Message length"
          },
          {
            "fieldName": "u1.ZeroInit",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "Zero initialized"
          },
          {
            "fieldName": "u2.Type",
            "fieldType": "USHORT",
            "fieldValue": "0x0001",
            "fieldComment": "Message type"
          },
          {
            "fieldName": "u2.DataInfoOffset",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "No data info"
          },
          {
            "fieldName": "ClientId.UniqueProcess",
            "fieldType": "HANDLE",
            "fieldValue": "0x99994444",
            "fieldComment": "Dummy process ID"
          },
          {
            "fieldName": "ClientId.UniqueThread",
            "fieldType": "HANDLE",
            "fieldValue": "0x00000000",
            "fieldComment": "Dummy thread ID"
          },
          {
            "fieldName": "MessageId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Message ID"
          },
          {
            "fieldName": "ClientViewSize",
            "fieldType": "SIZE_T",
            "fieldValue": "0x00000000",
            "fieldComment": "No client view"
          }
        ]
      },
      "struct120": {
        "type": "SID",
        "fields": [
          {
            "fieldName": "Revision",
            "fieldType": "BYTE",
            "fieldValue": "0x01",
            "fieldComment": "SID revision"
          },
          {
            "fieldName": "SubAuthorityCount",
            "fieldType": "BYTE",
            "fieldValue": "0x01",
            "fieldComment": "One subauthority"
          },
          {
            "fieldName": "IdentifierAuthority",
            "fieldType": "BYTE[6]",
            "fieldValue": "0x000000000005",
            "fieldComment": "NT Authority"
          },
          {
            "fieldName": "SubAuthority[0]",
            "fieldType": "ULONG",
            "fieldValue": "0x00000020",
            "fieldComment": "Example subauthority"
          }
        ]
      },
      "struct121": {
        "type": "ALPC_PORT_ATTRIBUTES",
        "fields": [
          {
            "fieldName": "Flags",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "ALPC_PORTFLG_ALLOW_LPC_REQUESTS"
          },
          {
            "fieldName": "SecurityQos.Length",
            "fieldType": "ULONG",
            "fieldValue": "0x0000000C",
            "fieldComment": "SECURITY_QUALITY_OF_SERVICE size"
          },
          {
            "fieldName": "MaxMessageLength",
            "fieldType": "ULONG",
            "fieldValue": "0x00001000",
            "fieldComment": "4KB max message"
          },
          {
            "fieldName": "MemoryBandwidth",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          },
          {
            "fieldName": "MaxPoolUsage",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          },
          {
            "fieldName": "MaxSectionSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          },
          {
            "fieldName": "MaxViewSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          },
          {
            "fieldName": "MaxTotalSectionSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Default"
          }
        ]
      },
      "struct122": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd0110",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      },
      "struct123": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "String length in bytes"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0022",
            "fieldComment": "Buffer size in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0120",
            "fieldComment": "Pointer to string buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtCancelDeviceWakeupRequest": {
    "ntFunc": "NtCancelDeviceWakeupRequest",
    "pushes": [
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE Device (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateChannel": {
    "ntFunc": "NtCreateChannel",
    "pushes": [
      {
        "value": "0xbadd00f0",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES ObjectAttributes (dummy pointer, commonly None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct124",
        "structureValueExpectations": "Object attributes for the channel, commonly None.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0100",
        "additionalComment": "Pointer to HANDLE ChannelHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct124": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          },
          {
            "fieldName": "Attributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "No attributes"
          },
          {
            "fieldName": "SecurityDescriptor",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtFreeUserPhysicalPages": {
    "ntFunc": "NtFreeUserPhysicalPages",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG UserPfnArray (dummy pointer, array of page frame numbers)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00123456"
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to ULONG NumberOfPages (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtGetPlugPlayEvent": {
    "ntFunc": "NtGetPlugPlayEvent",
    "pushes": [
      {
        "value": "0x00001000",
        "additionalComment": "EventBufferLength (4096 bytes typical buffer size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to PLUGPLAY_EVENT_BLOCK PnPEvent (dummy pointer)",
        "structurePointer": "PLUGPLAY_EVENT_BLOCK",
        "structureRef": "struct125",
        "structureValueExpectations": "Event GUID, event category, and event-specific data.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PnPContext (None, typical for no context)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PnPApcRoutine (None, no APC routine)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct125": {
        "type": "PLUGPLAY_EVENT_BLOCK",
        "fields": [
          {
            "fieldName": "EventGuid",
            "fieldType": "GUID",
            "fieldValue": "0xdeadbeef-0000-0000-0000-000000000001",
            "fieldComment": "Sample event GUID"
          },
          {
            "fieldName": "EventCategory",
            "fieldType": "ULONG",
            "fieldValue": "0x00000002",
            "fieldComment": "Hardware profile change event"
          },
          {
            "fieldName": "Result",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "No result"
          },
          {
            "fieldName": "Flags",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Flag set"
          },
          {
            "fieldName": "TotalSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000040",
            "fieldComment": "64 bytes"
          },
          {
            "fieldName": "DeviceObject",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtOpenChannel": {
    "ntFunc": "NtOpenChannel",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct126",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to HANDLE ChannelHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct126": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (no name)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtReplyWaitSendChannel": {
    "ntFunc": "NtReplyWaitSendChannel",
    "pushes": [
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to CHANNEL_MESSAGE (dummy pointer)",
        "structurePointer": "CHANNEL_MESSAGE",
        "structureRef": "struct127",
        "structureValueExpectations": "Message header and data fields.",
        "pointedValue": None
      },
      {
        "value": "0x00000040",
        "additionalComment": "Length (64 bytes, typical message size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to message text buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x41414141"
      }
    ],
    "structures": {
      "struct127": {
        "type": "CHANNEL_MESSAGE",
        "fields": [
          {
            "fieldName": "MessageType",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Request message"
          },
          {
            "fieldName": "DataLength",
            "fieldType": "ULONG",
            "fieldValue": "0x00000020",
            "fieldComment": "32 bytes"
          },
          {
            "fieldName": "Data",
            "fieldType": "BYTE[32]",
            "fieldValue": "0x41424344",
            "fieldComment": "Sample data"
          }
        ]
      }
    }
  },
  "NtSendWaitReplyChannel": {
    "ntFunc": "NtSendWaitReplyChannel",
    "pushes": [
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to CHANNEL_MESSAGE (dummy pointer)",
        "structurePointer": "CHANNEL_MESSAGE",
        "structureRef": "struct128",
        "structureValueExpectations": "Message header and data fields.",
        "pointedValue": None
      },
      {
        "value": "0x00000040",
        "additionalComment": "Length (64 bytes, typical message size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to message text buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x42424242"
      },
      {
        "value": "0x00000555",
        "additionalComment": "HANDLE ChannelHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct128": {
        "type": "CHANNEL_MESSAGE",
        "fields": [
          {
            "fieldName": "MessageType",
            "fieldType": "ULONG",
            "fieldValue": "0x00000002",
            "fieldComment": "Reply message"
          },
          {
            "fieldName": "DataLength",
            "fieldType": "ULONG",
            "fieldValue": "0x00000020",
            "fieldComment": "32 bytes"
          },
          {
            "fieldName": "Data",
            "fieldType": "BYTE[32]",
            "fieldValue": "0x44434241",
            "fieldComment": "Sample data"
          }
        ]
      }
    }
  },
  "NtSetContextChannel": {
    "ntFunc": "NtSetContextChannel",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None Context pointer (no context provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRequestDeviceWakeup": {
    "ntFunc": "NtRequestDeviceWakeup",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None Device handle (no device specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRequestWakeupLatency": {
    "ntFunc": "NtRequestWakeupLatency",
    "pushes": [
      {
        "value": "0x000003E8",
        "additionalComment": "LATENCY_TIME latency (1000 ms, typical value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtW32Call": {
    "ntFunc": "NtW32Call",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG OutputLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to output buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000008",
        "additionalComment": "InputLength (8 bytes, typical small input)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to input buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "ApiNumber (example: 1, typical for a known API call)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "KiUserApcDispatcher": {
    "ntFunc": "KiUserApcDispatcher",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None ContextBody pointer (no context provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None ContextStart pointer (no context provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None Unused3 pointer (reserved, unused)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None Unused2 pointer (reserved, unused)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None Unused1 pointer (reserved, unused)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAlertThread": {
    "ntFunc": "NtAlertThread",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE ThreadHandle (None, current thread)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCallbackReturn": {
    "ntFunc": "NtCallbackReturn",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "NTSTATUS Status (STATUS_SUCCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG ResultLength (0, no result)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID Result (None, no result buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueueApcThread": {
    "ntFunc": "NtQueueApcThread",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "ULONG ApcReserved (reserved, must be zero)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PIO_STATUS_BLOCK ApcStatusBlock (None, not used)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID ApcRoutineContext (None, no context)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PIO_APC_ROUTINE ApcRoutine (None, no routine)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE ThreadHandle (None, current thread)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtTestAlert": {
    "ntFunc": "NtTestAlert",
    "pushes": [],
    "structures": {}
  },
  "NtAddAtom": {
    "ntFunc": "NtAddAtom",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PRTL_ATOM Atom (None, output parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PWCHAR AtomName (None, no atom name)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtDeleteAtom": {
    "ntFunc": "NtDeleteAtom",
    "pushes": [
      {
        "value": "0x00004242",
        "additionalComment": "RTL_ATOM Atom (example atom value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtFindAtom": {
    "ntFunc": "NtFindAtom",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to RTL_ATOM Atom (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to WCHAR AtomName (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0020"
      }
    ],
    "structures": {}
  },
  "NtQueryInformationAtom": {
    "ntFunc": "NtQueryInformationAtom",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00000020",
        "additionalComment": "ULONG AtomInformationLength (example length)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to AtomInformation buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0050"
      },
      {
        "value": "0x00000002",
        "additionalComment": "ATOM_INFORMATION_CLASS AtomInformationClass (e.g., AtomBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00004242",
        "additionalComment": "RTL_ATOM Atom (example atom value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlCompressBuffer": {
    "ntFunc": "RtlCompressBuffer",
    "pushes": [
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to WorkspaceBuffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0070"
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to ULONG pDestinationSize (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00001000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Unknown (reserved, typically 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00002000",
        "additionalComment": "ULONG DestinationBufferLength (example: 8 KB)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to DestinationBuffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd00a0"
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG SourceBufferLength (example: 4 KB)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to SourceBuffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd00c0"
      },
      {
        "value": "0x00000201",
        "additionalComment": "ULONG CompressionFormat (COMPRESSION_FORMAT_LZNT1)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlDecompressBuffer": {
    "ntFunc": "RtlDecompressBuffer",
    "pushes": [
      {
        "value": "0xbadd00d0",
        "additionalComment": "Pointer to ULONG pDestinationSize (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00002000"
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG SourceBufferLength (example: 4 KB)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00e0",
        "additionalComment": "Pointer to SourceBuffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd00f0"
      },
      {
        "value": "0x00002000",
        "additionalComment": "ULONG DestinationBufferLength (example: 8 KB)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0100",
        "additionalComment": "Pointer to DestinationBuffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0110"
      },
      {
        "value": "0x00000201",
        "additionalComment": "ULONG CompressionFormat (COMPRESSION_FORMAT_LZNT1)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlGetCompressionWorkSpaceSize": {
    "ntFunc": "RtlGetCompressionWorkSpaceSize",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG pUnknown (dummy pointer, typically unused or reserved)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to ULONG pNeededBufferSize (dummy pointer, receives required workspace size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00004000"
      },
      {
        "value": "0x00000200",
        "additionalComment": "CompressionFormat (COMPRESSION_FORMAT_LZNT1)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "DbgPrint": {
    "ntFunc": "DbgPrint",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to LPCSTR Format string (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd1000"
      }
    ],
    "structures": {}
  },
  "NtSystemDebugControl": {
    "ntFunc": "NtSystemDebugControl",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer, receives output length)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG OutputBufferLength (4096 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to OutputBuffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd2000"
      },
      {
        "value": "0x00000020",
        "additionalComment": "ULONG InputBufferLength (32 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to InputBuffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd3000"
      },
      {
        "value": "0x0000000B",
        "additionalComment": "SYSDBG_COMMAND Command (e.g., SysDbgReadVirtual)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlCaptureStackBackTrace": {
    "ntFunc": "RtlCaptureStackBackTrace",
    "pushes": [
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to ULONG BackTraceHash (dummy pointer, receives hash value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x12345678"
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to BackTrace array (dummy pointer, receives stack addresses)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd4000"
      },
      {
        "value": "0x00000010",
        "additionalComment": "ULONG FramesToCapture (16 frames)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "ULONG FramesToSkip (skip 2 frames)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlGetCallersAddress": {
    "ntFunc": "RtlGetCallersAddress",
    "pushes": [
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to PVOID CallersCaller (dummy pointer, receives caller's caller address)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x7ffdf000"
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to PVOID CallersAddress (dummy pointer, receives caller's address)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x7ffde000"
      }
    ],
    "structures": {}
  },
  "NtDisplayString": {
    "ntFunc": "NtDisplayString",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None PUNICODE_STRING String (no string displayed)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRaiseException": {
    "ntFunc": "NtRaiseException",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HandleException = FALSE (do not handle in-process)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None PCONTEXT ThreadContext (no context provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None PEXCEPTION_RECORD ExceptionRecord (no exception record provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRaiseHardError": {
    "ntFunc": "NtRaiseHardError",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None PHARDERROR_RESPONSE Response (no response pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HARDERROR_RESPONSE_OPTION = 0 (default option)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None PVOID Parameters (no parameters)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None PUNICODE_STRING UnicodeStringParameterMask (no mask)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "NumberOfParameters = 0 (no parameters)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "NTSTATUS ErrorStatus = STATUS_SUCCESS (no error)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetDefaultHardErrorPort": {
    "ntFunc": "NtSetDefaultHardErrorPort",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None HANDLE PortHandle (no port set)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQuerySystemEnvironmentValue": {
    "ntFunc": "NtQuerySystemEnvironmentValue",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None PULONG RequiredLength (not requesting required length)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ValueBufferLength = 0 (no buffer provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None PWCHAR Value (no value buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None PUNICODE_STRING VariableName (no variable name specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetSystemEnvironmentValue": {
    "ntFunc": "NtSetSystemEnvironmentValue",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PUNICODE_STRING Value (None, typical for unset or default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PUNICODE_STRING VariableName (None, typical for unset or default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlCreateEnvironment": {
    "ntFunc": "RtlCreateEnvironment",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PVOID Environment (None, receives pointer to new environment block)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN Inherit (FALSE, do not inherit parent environment)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlDestroyEnvironment": {
    "ntFunc": "RtlDestroyEnvironment",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PVOID Environment (None, typical for default or uninitialized)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlExpandEnvironmentStrings_U": {
    "ntFunc": "RtlExpandEnvironmentStrings_U",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PULONG DestinationBufferLength (None, typical for default or uninitialized)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PUNICODE_STRING DestinationString (None, typical for default or uninitialized)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PUNICODE_STRING SourceString (None, typical for default or uninitialized)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID Environment (None, use current process environment)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlQueryEnvironmentVariable_U": {
    "ntFunc": "RtlQueryEnvironmentVariable_U",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PUNICODE_STRING VariableValue (None, typical for default or uninitialized)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PUNICODE_STRING VariableName (None, typical for default or uninitialized)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID Environment (None, use current process environment)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlSetCurrentEnvironment": {
    "ntFunc": "RtlSetCurrentEnvironment",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to PVOID OldEnvironment (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to PVOID NewEnvironment (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0020"
      }
    ],
    "structures": {}
  },
  "RtlSetEnvironmentVariable": {
    "ntFunc": "RtlSetEnvironmentVariable",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to UNICODE_STRING VariableValue (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct129",
        "structureValueExpectations": "UNICODE_STRING structure describing the value to set.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to UNICODE_STRING VariableName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct130",
        "structureValueExpectations": "UNICODE_STRING structure describing the variable name.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to environment block (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0060"
      }
    ],
    "structures": {
      "struct129": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Length in bytes of string"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd00d0",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      },
      "struct130": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x000c",
            "fieldComment": "Length in bytes of string"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd00e0",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "LdrGetDllHandle": {
    "ntFunc": "LdrGetDllHandle",
    "pushes": [
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to HMODULE (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to UNICODE_STRING ModuleFileName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct131",
        "structureValueExpectations": "UNICODE_STRING structure describing the DLL name.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Unused parameter, typically None",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to search path (PWSTR), typically None",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct131": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0014",
            "fieldComment": "Length in bytes of string"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd00f0",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "LdrGetProcedureAddress": {
    "ntFunc": "LdrGetProcedureAddress",
    "pushes": [
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to PVOID FunctionAddress (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "Ordinal, typically 0 if using FunctionName",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00a0",
        "additionalComment": "Pointer to ANSI_STRING FunctionName (dummy pointer)",
        "structurePointer": "ANSI_STRING",
        "structureRef": "struct132",
        "structureValueExpectations": "ANSI_STRING structure describing the function name.",
        "pointedValue": None
      },
      {
        "value": "0x77770000",
        "additionalComment": "ModuleHandle (dummy HMODULE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct132": {
        "type": "ANSI_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0008",
            "fieldComment": "Length in bytes of string"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PCHAR",
            "fieldValue": "0xbadd0100",
            "fieldComment": "Pointer to ANSI string buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "LdrLoadDll": {
    "ntFunc": "LdrLoadDll",
    "pushes": [
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to HMODULE ModuleHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd00c0",
        "additionalComment": "Pointer to UNICODE_STRING ModuleFileName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct133",
        "structureValueExpectations": "UNICODE_STRING structure describing the DLL name.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Flags, typically 0",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PathToFile (PWCHAR), typically None",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct133": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0012",
            "fieldComment": "Length in bytes of string"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0110",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "LdrQueryProcessModuleInformation": {
    "ntFunc": "LdrQueryProcessModuleInformation",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG RequiredSize (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00001000"
      },
      {
        "value": "0x00002000",
        "additionalComment": "ULONG BufferSize (8 KB typical buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to SYSTEM_MODULE_INFORMATION buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "LdrShutdownProcess": {
    "ntFunc": "LdrShutdownProcess",
    "pushes": [],
    "structures": {}
  },
  "LdrShutdownThread": {
    "ntFunc": "LdrShutdownThread",
    "pushes": [],
    "structures": {}
  },
  "LdrUnloadDll": {
    "ntFunc": "LdrUnloadDll",
    "pushes": [
      {
        "value": "0x10000000",
        "additionalComment": "HANDLE ModuleHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtLoadDriver": {
    "ntFunc": "NtLoadDriver",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to UNICODE_STRING DriverServiceName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct134",
        "structureValueExpectations": "UNICODE_STRING structure containing registry path to driver service.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct134": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0030",
            "fieldComment": "Length in bytes of the string"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0032",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0030",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtUnloadDriver": {
    "ntFunc": "NtUnloadDriver",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None (no driver service name provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlImageNtHeader": {
    "ntFunc": "RtlImageNtHeader",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None (no module address provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlImageRvaToVa": {
    "ntFunc": "RtlImageRvaToVa",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None (no IMAGE_SECTION_HEADER pointer provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Rva = 0 (no relative virtual address provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None (no module base address provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None (no IMAGE_NT_HEADERS pointer provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtFlushWriteBuffer": {
    "ntFunc": "NtFlushWriteBuffer",
    "pushes": [],
    "structures": {}
  },
  "NtShutdownSystem": {
    "ntFunc": "NtShutdownSystem",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "ShutdownAction = 0 (ShutdownNoReboot)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryDefaultLocale": {
    "ntFunc": "NtQueryDefaultLocale",
    "pushes": [
      {
        "value": "0x00000409",
        "additionalComment": "PLCID DefaultLocaleId (pointer to US English LCID, 0x409)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000409"
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN UserProfile (TRUE, query user profile locale)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetDefaultLocale": {
    "ntFunc": "NtSetDefaultLocale",
    "pushes": [
      {
        "value": "0x00000409",
        "additionalComment": "LCID DefaultLocaleId (US English)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN UserProfile (TRUE, set user profile locale)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlAllocateHeap": {
    "ntFunc": "RtlAllocateHeap",
    "pushes": [
      {
        "value": "0x00001000",
        "additionalComment": "ULONG Size (4096 bytes, typical page size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000008",
        "additionalComment": "ULONG Flags (HEAP_ZERO_MEMORY)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "PVOID HeapHandle (dummy heap handle pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00ee0000"
      }
    ],
    "structures": {}
  },
  "RtlCompactHeap": {
    "ntFunc": "RtlCompactHeap",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Flags (no flags, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "HANDLE HeapHandle (dummy heap handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlCreateHeap": {
    "ntFunc": "RtlCreateHeap",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "PRTL_HEAP_DEFINITION RtlHeapParams (dummy pointer, None for default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN Lock (TRUE, serialized heap)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG Commit (commit 4096 bytes initially)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00100000",
        "additionalComment": "ULONG Reserve (reserve 1MB for heap)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID Base (None, let system choose base address)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "ULONG Flags (HEAP_GROWABLE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlDestroyHeap": {
    "ntFunc": "RtlDestroyHeap",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HeapHandle (None, destroys default process heap)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlEnumProcessHeaps": {
    "ntFunc": "RtlEnumProcessHeaps",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Param (None, no user parameter passed to callback)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HeapEnumerationRoutine (None, no callback routine)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlFreeHeap": {
    "ntFunc": "RtlFreeHeap",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "MemoryPointer (None, no memory to free)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Flags (0, no special flags)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HeapHandle (None, default process heap)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlGetProcessHeaps": {
    "ntFunc": "RtlGetProcessHeaps",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HeapArray (None, caller wants heap count only)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000010",
        "additionalComment": "MaxNumberOfHeaps (16, typical small process)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlLockHeap": {
    "ntFunc": "RtlLockHeap",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HeapHandle (None, default process heap)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlProtectHeap": {
    "ntFunc": "RtlProtectHeap",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN Protect (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "PVOID HeapHandle (dummy heap handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlReAllocateHeap": {
    "ntFunc": "RtlReAllocateHeap",
    "pushes": [
      {
        "value": "0x00002000",
        "additionalComment": "ULONG Size (8 KB)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "PVOID MemoryPointer (dummy pointer to allocated memory)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000008",
        "additionalComment": "ULONG Flags (HEAP_ZERO_MEMORY)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "PVOID HeapHandle (dummy heap handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlSizeHeap": {
    "ntFunc": "RtlSizeHeap",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "PVOID MemoryPointer (dummy pointer to allocated memory)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Flags (default, 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "PVOID HeapHandle (dummy heap handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlUnlockHeap": {
    "ntFunc": "RtlUnlockHeap",
    "pushes": [
      {
        "value": "0xbadd0050",
        "additionalComment": "PVOID HeapHandle (dummy heap handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlValidateHeap": {
    "ntFunc": "RtlValidateHeap",
    "pushes": [
      {
        "value": "0xbadd0060",
        "additionalComment": "PVOID AddressToValidate (dummy pointer to memory block)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Flags (default, 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "PVOID HeapHandle (dummy heap handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlValidateProcessHeaps": {
    "ntFunc": "RtlValidateProcessHeaps",
    "pushes": [],
    "structures": {}
  },
  "RtlWalkHeap": {
    "ntFunc": "RtlWalkHeap",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "LPPROCESS_HEAP_ENTRY ProcessHeapEntry (None, typical for initial call)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID HeapHandle (None, means use process default heap)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAllocateVirtualMemory": {
    "ntFunc": "NtAllocateVirtualMemory",
    "pushes": [
      {
        "value": "0x00000040",
        "additionalComment": "ULONG Protect (PAGE_EXECUTE_READWRITE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG AllocationType (MEM_COMMIT)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "PSIZE_T RegionSize (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00002000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG_PTR ZeroBits (0, typical for user mode)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "PVOID BaseAddress (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00400000"
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle, current process)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtFlushVirtualMemory": {
    "ntFunc": "NtFlushVirtualMemory",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "PIO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct135",
        "structureValueExpectations": "Status and Information fields.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "PULONG NumberOfBytesToFlush (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00001000"
      },
      {
        "value": "0x00400000",
        "additionalComment": "PVOID BaseAddress (typical heap base address)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle, current process)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct135": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "Operation status (initialized to 0)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Additional info (initialized to 0)"
          }
        ]
      }
    }
  },
  "NtFreeVirtualMemory": {
    "ntFunc": "NtFreeVirtualMemory",
    "pushes": [
      {
        "value": "0x00008000",
        "additionalComment": "ULONG FreeType (MEM_RELEASE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "PSIZE_T RegionSize (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00002000"
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "PVOID BaseAddress (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00400000"
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle, current process)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtLockVirtualMemory": {
    "ntFunc": "NtLockVirtualMemory",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "LockOption (VM_LOCK_1, example value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG NumberOfBytesToLock (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00002000"
      },
      {
        "value": "0x00400000",
        "additionalComment": "BaseAddress (typical image base)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtProtectVirtualMemory": {
    "ntFunc": "NtProtectVirtualMemory",
    "pushes": [
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to ULONG OldAccessProtection (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000004"
      },
      {
        "value": "0x00000020",
        "additionalComment": "NewAccessProtection (PAGE_EXECUTE_READ, example value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to ULONG NumberOfBytesToProtect (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00001000"
      },
      {
        "value": "0x00400000",
        "additionalComment": "BaseAddress (typical image base)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryVirtualMemory": {
    "ntFunc": "NtQueryVirtualMemory",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to SIZE_T ReturnLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000040"
      },
      {
        "value": "0x00000040",
        "additionalComment": "MemoryInformationLength (example: 64 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to MEMORY_BASIC_INFORMATION (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "MemoryInformationClass (MemoryBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00400000",
        "additionalComment": "BaseAddress (typical image base)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtReadVirtualMemory": {
    "ntFunc": "NtReadVirtualMemory",
    "pushes": [
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to ULONG NumberOfBytesRead (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00001000"
      },
      {
        "value": "0x00001000",
        "additionalComment": "NumberOfBytesToRead (4096 bytes, typical page size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to Buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00400000",
        "additionalComment": "BaseAddress (typical image base)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtUnlockVirtualMemory": {
    "ntFunc": "NtUnlockVirtualMemory",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "LockType (VM_UNLOCK_1, example value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to ULONG NumberOfBytesToUnlock (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00002000"
      },
      {
        "value": "0x00400000",
        "additionalComment": "BaseAddress (typical image base)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtWriteVirtualMemory": {
    "ntFunc": "NtWriteVirtualMemory",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG NumberOfBytesWritten (dummy pointer, typically receives number of bytes written)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00000010",
        "additionalComment": "ULONG NumberOfBytesToWrite (16 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to buffer to write (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x41414141"
      },
      {
        "value": "0x00405000",
        "additionalComment": "PVOID BaseAddress (target address in remote process)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQuerySecurityObject": {
    "ntFunc": "NtQuerySecurityObject",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to ULONG LengthNeeded (dummy pointer, receives required length)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000100"
      },
      {
        "value": "0x00000100",
        "additionalComment": "ULONG Length (256 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to SECURITY_DESCRIPTOR buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00000001",
        "additionalComment": "SECURITY_INFORMATION (OWNER_SECURITY_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE Handle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetSecurityObject": {
    "ntFunc": "NtSetSecurityObject",
    "pushes": [
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to SECURITY_DESCRIPTOR (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00000004",
        "additionalComment": "SECURITY_INFORMATION (DACL_SECURITY_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE Handle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtDuplicateObject": {
    "ntFunc": "NtDuplicateObject",
    "pushes": [
      {
        "value": "0x00000002",
        "additionalComment": "ULONG Options (DUPLICATE_SAME_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN InheritHandle (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x001F0001",
        "additionalComment": "ACCESS_MASK DesiredAccess (SYNCHRONIZE | PROCESS_DUP_HANDLE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to HANDLE TargetHandle (dummy pointer, receives duplicated handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000555",
        "additionalComment": "HANDLE TargetProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to HANDLE SourceHandle (dummy pointer, points to handle to duplicate)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000444"
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE SourceProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtMakeTemporaryObject": {
    "ntFunc": "NtMakeTemporaryObject",
    "pushes": [
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ObjectHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryObject": {
    "ntFunc": "NtQueryObject",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer, optional, can be None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000040"
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG ObjectInformationLength (typical buffer size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to buffer for ObjectInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ObjectInformationClass (ObjectBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE Handle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetInformationObject": {
    "ntFunc": "NtSetInformationObject",
    "pushes": [
      {
        "value": "0x00000018",
        "additionalComment": "ULONG Length (typical structure size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to ObjectInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "ObjectInformationClass (ObjectNameInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000445",
        "additionalComment": "HANDLE ObjectHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSignalAndWaitForSingleObject": {
    "ntFunc": "NtSignalAndWaitForSingleObject",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to LARGE_INTEGER Time (dummy pointer, optional, can be None)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct136",
        "structureValueExpectations": "Timeout interval in 100-nanosecond units, negative for relative.",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN Alertable (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000446",
        "additionalComment": "HANDLE WaitableObject (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000447",
        "additionalComment": "HANDLE ObjectToSignal (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct136": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0xfffff830",
            "fieldComment": "Relative timeout of -20000 (2ms) in 100ns units"
          }
        ]
      }
    }
  },
  "NtWaitForMultipleObjects": {
    "ntFunc": "NtWaitForMultipleObjects",
    "pushes": [
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to LARGE_INTEGER TimeOut (dummy pointer, optional, can be None)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct137",
        "structureValueExpectations": "Timeout interval in 100-nanosecond units, negative for relative.",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN Alertable (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "OBJECT_WAIT_TYPE WaitType (WaitAll)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to array of HANDLEs (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "ULONG ObjectCount (waiting on 2 objects)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct137": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0xffffffffffffffd8",
            "fieldComment": "Relative timeout of -40 (4us) in 100ns units"
          }
        ]
      }
    }
  },
  "NtWaitForSingleObject": {
    "ntFunc": "NtWaitForSingleObject",
    "pushes": [
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to LARGE_INTEGER TimeOut (dummy pointer, optional, can be None)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct138",
        "structureValueExpectations": "Timeout interval in 100-nanosecond units, negative for relative.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN Alertable (FALSE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000448",
        "additionalComment": "HANDLE ObjectHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct138": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000000000000",
            "fieldComment": "None/zero timeout (wait forever)"
          }
        ]
      }
    }
  },
  "NtCreateDebugObject": {
    "ntFunc": "NtCreateDebugObject",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "KillProcessOnExit = FALSE (default, do not kill process on exit)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES = None (default, unnamed object)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000001F",
        "additionalComment": "DesiredAccess = DEBUG_ALL_ACCESS (realistic example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to HANDLE DebugObjectHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtDebugActiveProcess": {
    "ntFunc": "NtDebugActiveProcess",
    "pushes": [
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE DebugObjectHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x99994444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle, target process)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRemoveProcessDebug": {
    "ntFunc": "NtRemoveProcessDebug",
    "pushes": [
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE DebugObjectHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x99994444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle, target process)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateDirectoryObject": {
    "ntFunc": "NtCreateDirectoryObject",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES = None (default, unnamed object)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x000F000F",
        "additionalComment": "DesiredAccess = DIRECTORY_ALL_ACCESS (realistic example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to HANDLE DirectoryHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtOpenDirectoryObject": {
    "ntFunc": "NtOpenDirectoryObject",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct139",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00020000",
        "additionalComment": "DesiredAccess = DIRECTORY_QUERY (realistic example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to HANDLE DirectoryObjectHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct139": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd0040",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtQueryDirectoryObject": {
    "ntFunc": "NtQueryDirectoryObject",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG DataWritten (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to ULONG ObjectIndex (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN IgnoreInputIndex (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN GetNextIndex (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG BufferLength (4096 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to OBJDIR_INFORMATION DirObjInformation (dummy pointer)",
        "structurePointer": "OBJDIR_INFORMATION",
        "structureRef": "struct140",
        "structureValueExpectations": "Directory object information structure for output.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE DirectoryObjectHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct140": {
        "type": "OBJDIR_INFORMATION",
        "fields": [
          {
            "fieldName": "Name",
            "fieldType": "UNICODE_STRING",
            "fieldValue": "0xbadd0080",
            "fieldComment": "Pointer to UNICODE_STRING for object name (dummy pointer)"
          },
          {
            "fieldName": "TypeName",
            "fieldType": "UNICODE_STRING",
            "fieldValue": "0xbadd0090",
            "fieldComment": "Pointer to UNICODE_STRING for type name (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtClearEvent": {
    "ntFunc": "NtClearEvent",
    "pushes": [
      {
        "value": "0x00000E00",
        "additionalComment": "HANDLE EventHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateEvent": {
    "ntFunc": "NtCreateEvent",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN InitialState (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "EVENT_TYPE EventType (NotificationEvent)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct141",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F0003",
        "additionalComment": "ACCESS_MASK DesiredAccess (EVENT_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to HANDLE EventHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct141": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (no name specified)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtOpenEvent": {
    "ntFunc": "NtOpenEvent",
    "pushes": [
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct142",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F0003",
        "additionalComment": "ACCESS_MASK DesiredAccess (EVENT_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to HANDLE EventHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct142": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (no name specified)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtPulseEvent": {
    "ntFunc": "NtPulseEvent",
    "pushes": [
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to LONG PreviousState (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00000E00",
        "additionalComment": "HANDLE EventHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryEvent": {
    "ntFunc": "NtQueryEvent",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00000010",
        "additionalComment": "EventInformationLength (16 bytes, typical for EVENT_BASIC_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to EVENT_BASIC_INFORMATION structure (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "EventInformationClass (EventBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE EventHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtResetEvent": {
    "ntFunc": "NtResetEvent",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to LONG PreviousState (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE EventHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetEvent": {
    "ntFunc": "NtSetEvent",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to LONG PreviousState (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE EventHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetEventBoostPriority": {
    "ntFunc": "NtSetEventBoostPriority",
    "pushes": [
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE EventHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateEventPair": {
    "ntFunc": "NtCreateEventPair",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (None, default for unnamed event pair)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F0003",
        "additionalComment": "DesiredAccess (EVENT_PAIR_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to HANDLE EventPairHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtOpenEventPair": {
    "ntFunc": "NtOpenEventPair",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (None, default for unnamed event pair)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": None,
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F0003",
        "additionalComment": "DesiredAccess (EVENT_PAIR_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to HANDLE EventPairHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtSetHighEventPair": {
    "ntFunc": "NtSetHighEventPair",
    "pushes": [
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE EventPairHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetHighWaitLowEventPair": {
    "ntFunc": "NtSetHighWaitLowEventPair",
    "pushes": [
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE EventPairHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetHighWaitLowThread": {
    "ntFunc": "NtSetHighWaitLowThread",
    "pushes": [],
    "structures": {}
  },
  "NtSetLowEventPair": {
    "ntFunc": "NtSetLowEventPair",
    "pushes": [
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE EventPairHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetLowWaitHighEventPair": {
    "ntFunc": "NtSetLowWaitHighEventPair",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE EventPairHandle (None, typical for illustrative purposes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetLowWaitHighThread": {
    "ntFunc": "NtSetLowWaitHighThread",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE ThreadHandle (None, typical for illustrative purposes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtWaitHighEventPair": {
    "ntFunc": "NtWaitHighEventPair",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE EventPairHandle (None, typical for illustrative purposes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtWaitLowEventPair": {
    "ntFunc": "NtWaitLowEventPair",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE EventPairHandle (None, typical for illustrative purposes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCancelIoFile": {
    "ntFunc": "NtCancelIoFile",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to IO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct143",
        "structureValueExpectations": "Status and information fields for I/O completion.",
        "pointedValue": None
      },
      {
        "value": "0x00004444",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct143": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "STATUS_SUCCESS (default initial value)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Typically zero before I/O completion"
          }
        ]
      }
    }
  },
  "NtCreateFile": {
    "ntFunc": "NtCreateFile",
    "pushes": [
      {
        "value": "0x00000010",
        "additionalComment": "ULONG EaLength (no EA data)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID EaBuffer (None, no EA data)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000020",
        "additionalComment": "ULONG CreateOptions (FILE_NON_DIRECTORY_FILE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG CreateDisposition (FILE_SUPERSEDE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000007",
        "additionalComment": "ULONG ShareAccess (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000080",
        "additionalComment": "ULONG FileAttributes (FILE_ATTRIBUTE_NORMAL)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "PLARGE_INTEGER AllocationSize (dummy pointer, None for default size)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct144",
        "structureValueExpectations": "Allocation size in bytes, or None for default.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "PIO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct145",
        "structureValueExpectations": "Status and information fields.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "POBJECT_ATTRIBUTES ObjectAttributes (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct146",
        "structureValueExpectations": "Length, RootDirectory, ObjectName, Attributes, SecurityDescriptor, SecurityQualityOfService.",
        "pointedValue": None
      },
      {
        "value": "0x0012019F",
        "additionalComment": "ACCESS_MASK DesiredAccess (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "PHANDLE FileHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct144": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000000000000",
            "fieldComment": "Default allocation size (0 = use default)"
          }
        ]
      },
      "struct145": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "Will be set by system"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Will be set by system"
          }
        ]
      },
      "struct146": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd0100",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtCreateMailslotFile": {
    "ntFunc": "NtCreateMailslotFile",
    "pushes": [
      {
        "value": "0xbadd0040",
        "additionalComment": "PLARGE_INTEGER ReadTimeOut (dummy pointer, infinite timeout)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct147",
        "structureValueExpectations": "Timeout in 100-nanosecond intervals, or None for infinite.",
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG MaxMessageSize (4096 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00010000",
        "additionalComment": "ULONG MailslotQuota (65536 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000020",
        "additionalComment": "ULONG CreateOptions (FILE_NON_DIRECTORY_FILE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "PIO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct148",
        "structureValueExpectations": "Status and information fields.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "POBJECT_ATTRIBUTES ObjectAttributes (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct149",
        "structureValueExpectations": "Length, RootDirectory, ObjectName, Attributes, SecurityDescriptor, SecurityQualityOfService.",
        "pointedValue": None
      },
      {
        "value": "0x0012019F",
        "additionalComment": "ACCESS_MASK DesiredAccess (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "PHANDLE MailslotFileHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct147": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0xFFFFFFFFFFFFFFFF",
            "fieldComment": "Infinite timeout"
          }
        ]
      },
      "struct148": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "Will be set by system"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Will be set by system"
          }
        ]
      },
      "struct149": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd0110",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtCreateNamedPipeFile": {
    "ntFunc": "NtCreateNamedPipeFile",
    "pushes": [
      {
        "value": "0xbadd0080",
        "additionalComment": "PLARGE_INTEGER DefaultTimeOut (dummy pointer, infinite timeout)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct150",
        "structureValueExpectations": "Timeout in 100-nanosecond intervals, or None for infinite.",
        "pointedValue": None
      },
      {
        "value": "0x00010000",
        "additionalComment": "ULONG OutBufferSize (65536 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00010000",
        "additionalComment": "ULONG InBufferSize (65536 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x000000FF",
        "additionalComment": "ULONG MaxInstances (255 instances)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN NonBlocking (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN ReadModeMessage (TRUE, message mode)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN WriteModeMessage (TRUE, message mode)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000020",
        "additionalComment": "ULONG CreateOptions (FILE_NON_DIRECTORY_FILE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG CreateDisposition (FILE_SUPERSEDE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000007",
        "additionalComment": "ULONG ShareAccess (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "PIO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct151",
        "structureValueExpectations": "Status and information fields.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00a0",
        "additionalComment": "POBJECT_ATTRIBUTES ObjectAttributes (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct152",
        "structureValueExpectations": "Length, RootDirectory, ObjectName, Attributes, SecurityDescriptor, SecurityQualityOfService.",
        "pointedValue": None
      },
      {
        "value": "0x0012019F",
        "additionalComment": "ACCESS_MASK DesiredAccess (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00b0",
        "additionalComment": "PHANDLE NamedPipeFileHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct150": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0xFFFFFFFFFFFFFFFF",
            "fieldComment": "Infinite timeout"
          }
        ]
      },
      "struct151": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "Will be set by system"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Will be set by system"
          }
        ]
      },
      "struct152": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd0120",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtDeleteFile": {
    "ntFunc": "NtDeleteFile",
    "pushes": [
      {
        "value": "0xbadd00c0",
        "additionalComment": "POBJECT_ATTRIBUTES ObjectAttributes (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct153",
        "structureValueExpectations": "Length, RootDirectory, ObjectName, Attributes, SecurityDescriptor, SecurityQualityOfService.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct153": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd0130",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtDeviceIoControlFile": {
    "ntFunc": "NtDeviceIoControlFile",
    "pushes": [
      {
        "value": "0x00001000",
        "additionalComment": "ULONG OutputBufferLength (4096 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00d0",
        "additionalComment": "PVOID OutputBuffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd00e0"
      },
      {
        "value": "0x00000800",
        "additionalComment": "ULONG InputBufferLength (2048 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00e0",
        "additionalComment": "PVOID InputBuffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd00f0"
      },
      {
        "value": "0x0022200B",
        "additionalComment": "ULONG IoControlCode (IOCTL code example: FSCTL_GET_COMPRESSION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00f0",
        "additionalComment": "PIO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct154",
        "structureValueExpectations": "Status and information fields.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID ApcContext (None, no APC context)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PIO_APC_ROUTINE ApcRoutine (None, no APC routine)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE Event (None, no event)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000044",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct154": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "Will be set by system"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Will be set by system"
          }
        ]
      }
    }
  },
  "NtFlushBuffersFile": {
    "ntFunc": "NtFlushBuffersFile",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to IO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct155",
        "structureValueExpectations": "Status and information fields for I/O completion.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct155": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "STATUS_SUCCESS"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "No additional info"
          }
        ]
      }
    }
  },
  "NtFsControlFile": {
    "ntFunc": "NtFsControlFile",
    "pushes": [
      {
        "value": "0x00001000",
        "additionalComment": "ULONG OutputBufferLength (4096 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to OutputBuffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd1010"
      },
      {
        "value": "0x00000020",
        "additionalComment": "ULONG InputBufferLength (32 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to InputBuffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd1020"
      },
      {
        "value": "0x00090018",
        "additionalComment": "ULONG FsControlCode (FSCTL_GET_COMPRESSION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to IO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct156",
        "structureValueExpectations": "Status and information fields for I/O completion.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to ApcContext (dummy pointer, usually None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "PIO_APC_ROUTINE ApcRoutine (None, no APC)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE Event (None, no event)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct156": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0xC0000023",
            "fieldComment": "STATUS_BUFFER_TOO_SMALL"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000010",
            "fieldComment": "16 bytes transferred"
          }
        ]
      }
    }
  },
  "NtLockFile": {
    "ntFunc": "NtLockFile",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN ExclusiveLock (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN FailImmediately (FALSE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x000000AA",
        "additionalComment": "ULONG Key (arbitrary key value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to LARGE_INTEGER Length (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct157",
        "structureValueExpectations": "Length of the region to lock.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to LARGE_INTEGER ByteOffset (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct158",
        "structureValueExpectations": "Starting byte offset for the lock.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to IO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct159",
        "structureValueExpectations": "Status and information fields for I/O completion.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID ApcContext (None, no APC context)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PIO_APC_ROUTINE ApcRoutine (None, no APC routine)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE Event (None, no event)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct157": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000000001000",
            "fieldComment": "Length: 4096 bytes"
          }
        ]
      },
      "struct158": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000000000000",
            "fieldComment": "Offset: start of file"
          }
        ]
      },
      "struct159": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "STATUS_SUCCESS"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "No additional info"
          }
        ]
      }
    }
  },
  "NtNotifyChangeDirectoryFile": {
    "ntFunc": "NtNotifyChangeDirectoryFile",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN WatchTree (TRUE, watch subdirectories)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000010A",
        "additionalComment": "ULONG CompletionFilter (FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG BufferSize (4096 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to Buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd1080"
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to IO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct160",
        "structureValueExpectations": "Status and information fields for I/O completion.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID ApcContext (None, no APC context)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PIO_APC_ROUTINE ApcRoutine (None, no APC routine)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE Event (None, no event)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct160": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000103",
            "fieldComment": "STATUS_PENDING"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "No additional info"
          }
        ]
      }
    }
  },
  "NtOpenFile": {
    "ntFunc": "NtOpenFile",
    "pushes": [
      {
        "value": "0x00000020",
        "additionalComment": "ULONG OpenOptions (FILE_NON_DIRECTORY_FILE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000007",
        "additionalComment": "ULONG ShareAccess (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00a0",
        "additionalComment": "Pointer to IO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct161",
        "structureValueExpectations": "Status and information fields for I/O completion.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct162",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x00120089",
        "additionalComment": "ACCESS_MASK DesiredAccess (GENERIC_READ | SYNCHRONIZE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00c0",
        "additionalComment": "Pointer to HANDLE FileHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct161": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "STATUS_SUCCESS"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "No additional info"
          }
        ]
      },
      "struct162": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (no name)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtQueryAttributesFile": {
    "ntFunc": "NtQueryAttributesFile",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to FILE_BASIC_INFORMATION (dummy pointer)",
        "structurePointer": "FILE_BASIC_INFORMATION",
        "structureRef": "struct163",
        "structureValueExpectations": "Basic file attributes such as creation time, last access time, etc.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct164",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct163": {
        "type": "FILE_BASIC_INFORMATION",
        "fields": [
          {
            "fieldName": "CreationTime",
            "fieldType": "LARGE_INTEGER",
            "fieldValue": "0x01D8E3B5A2B0000",
            "fieldComment": "Sample file creation time"
          },
          {
            "fieldName": "LastAccessTime",
            "fieldType": "LARGE_INTEGER",
            "fieldValue": "0x01D8E3B5A2B1000",
            "fieldComment": "Sample last access time"
          },
          {
            "fieldName": "LastWriteTime",
            "fieldType": "LARGE_INTEGER",
            "fieldValue": "0x01D8E3B5A2B2000",
            "fieldComment": "Sample last write time"
          },
          {
            "fieldName": "ChangeTime",
            "fieldType": "LARGE_INTEGER",
            "fieldValue": "0x01D8E3B5A2B3000",
            "fieldComment": "Sample change time"
          },
          {
            "fieldName": "FileAttributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000020",
            "fieldComment": "FILE_ATTRIBUTE_ARCHIVE"
          }
        ]
      },
      "struct164": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd00d0",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtQueryDirectoryFile": {
    "ntFunc": "NtQueryDirectoryFile",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN RestartScan (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to UNICODE_STRING FileName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct165",
        "structureValueExpectations": "UNICODE_STRING structure describing the file name to query for.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN ReturnSingleEntry (FALSE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "FILE_INFORMATION_CLASS FileInformationClass (FileDirectoryInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG Length (4096 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to buffer for FileInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to IO_STATUS_BLOCK (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct166",
        "structureValueExpectations": "Status and information fields for the I/O operation.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID ApcContext (None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PIO_APC_ROUTINE ApcRoutine (None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE Event (None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct165": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Length in bytes of the string"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd00e0",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      },
      "struct166": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "Operation status (initialized to 0)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Operation information (initialized to 0)"
          }
        ]
      }
    }
  },
  "NtQueryEaFile": {
    "ntFunc": "NtQueryEaFile",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN RestartScan (FALSE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to ULONG EaIndex (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00000020",
        "additionalComment": "ULONG EaListLength (32 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to EaList buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN ReturnSingleEntry (FALSE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG Length (4096 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to Buffer for EA data (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to IO_STATUS_BLOCK (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct166",
        "structureValueExpectations": "Status and information fields for the I/O operation.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct166": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "Operation status (initialized to 0)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Operation information (initialized to 0)"
          }
        ]
      }
    }
  },
  "NtQueryFullAttributesFile": {
    "ntFunc": "NtQueryFullAttributesFile",
    "pushes": [
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to FILE_NETWORK_OPEN_INFORMATION (dummy pointer)",
        "structurePointer": "FILE_NETWORK_OPEN_INFORMATION",
        "structureRef": "struct167",
        "structureValueExpectations": "Network open information for the file (timestamps, size, attributes, etc).",
        "pointedValue": None
      },
      {
        "value": "0xbadd00a0",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct164",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct167": {
        "type": "FILE_NETWORK_OPEN_INFORMATION",
        "fields": [
          {
            "fieldName": "CreationTime",
            "fieldType": "LARGE_INTEGER",
            "fieldValue": "0x01D8E3B5A2B0000",
            "fieldComment": "Sample file creation time"
          },
          {
            "fieldName": "LastAccessTime",
            "fieldType": "LARGE_INTEGER",
            "fieldValue": "0x01D8E3B5A2B1000",
            "fieldComment": "Sample last access time"
          },
          {
            "fieldName": "LastWriteTime",
            "fieldType": "LARGE_INTEGER",
            "fieldValue": "0x01D8E3B5A2B2000",
            "fieldComment": "Sample last write time"
          },
          {
            "fieldName": "ChangeTime",
            "fieldType": "LARGE_INTEGER",
            "fieldValue": "0x01D8E3B5A2B3000",
            "fieldComment": "Sample change time"
          },
          {
            "fieldName": "AllocationSize",
            "fieldType": "LARGE_INTEGER",
            "fieldValue": "0x00002000",
            "fieldComment": "Sample allocation size"
          },
          {
            "fieldName": "EndOfFile",
            "fieldType": "LARGE_INTEGER",
            "fieldValue": "0x00001800",
            "fieldComment": "Sample end of file"
          },
          {
            "fieldName": "FileAttributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000020",
            "fieldComment": "FILE_ATTRIBUTE_ARCHIVE"
          }
        ]
      },
      "struct164": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd00d0",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtQueryInformationFile": {
    "ntFunc": "NtQueryInformationFile",
    "pushes": [
      {
        "value": "0x00000005",
        "additionalComment": "FILE_INFORMATION_CLASS FileInformationClass (FileStandardInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000100",
        "additionalComment": "ULONG Length (256 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to buffer for FileInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd00c0",
        "additionalComment": "Pointer to IO_STATUS_BLOCK (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct166",
        "structureValueExpectations": "Status and information fields for the I/O operation.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct166": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "Operation status (initialized to 0)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Operation information (initialized to 0)"
          }
        ]
      }
    }
  },
  "NtQueryOleDirectoryFile": {
    "ntFunc": "NtQueryOleDirectoryFile",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN RestartScan (FALSE, typical for initial query)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PUNICODE_STRING FileMask (None, no mask applied)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN ReturnSingleEntry (FALSE, return all entries)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "FILE_INFORMATION_CLASS FileDirectoryInformation",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG Length (4096 bytes, typical buffer size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "PVOID FileInformation (dummy pointer to output buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "PIO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct168",
        "structureValueExpectations": "Status and information fields for I/O result.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID ApcContext (None, no APC context)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PIO_APC_ROUTINE ApcRoutine (None, no APC routine)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE Event (None, synchronous operation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct168": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "STATUS_SUCCESS (initial value)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Number of bytes transferred (initial value)"
          }
        ]
      }
    }
  },
  "NtQueryVolumeInformationFile": {
    "ntFunc": "NtQueryVolumeInformationFile",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "FS_INFORMATION_CLASS FileFsVolumeInformation",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000200",
        "additionalComment": "ULONG Length (512 bytes, typical buffer size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "PVOID FsInformation (dummy pointer to output buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "PIO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct169",
        "structureValueExpectations": "Status and information fields for I/O result.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct169": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "STATUS_SUCCESS (initial value)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Number of bytes transferred (initial value)"
          }
        ]
      }
    }
  },
  "NtReadFile": {
    "ntFunc": "NtReadFile",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PULONG Key (None, not used for synchronous I/O)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PLARGE_INTEGER ByteOffset (None, read from current file position)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000100",
        "additionalComment": "ULONG Length (256 bytes to read)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "PVOID Buffer (dummy pointer to read buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "PIO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct170",
        "structureValueExpectations": "Status and information fields for I/O result.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID ApcContext (None, no APC context)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PIO_APC_ROUTINE ApcRoutine (None, no APC routine)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE Event (None, synchronous operation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct170": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "STATUS_SUCCESS (initial value)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Number of bytes transferred (initial value)"
          }
        ]
      }
    }
  },
  "NtReadFileScatter": {
    "ntFunc": "NtReadFileScatter",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PULONG Key (None, not used for synchronous I/O)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PLARGE_INTEGER ByteOffset (None, read from current file position)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000200",
        "additionalComment": "ULONG Length (512 bytes to read)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "FILE_SEGMENT_ELEMENT SegmentArray (dummy pointer to segment array)",
        "structurePointer": "FILE_SEGMENT_ELEMENT",
        "structureRef": "struct171",
        "structureValueExpectations": "Array of segment elements for scatter read.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "PIO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct172",
        "structureValueExpectations": "Status and information fields for I/O result.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID ApcContext (None, no APC context)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PIO_APC_ROUTINE ApcRoutine (None, no APC routine)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE Event (None, synchronous operation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct171": {
        "type": "FILE_SEGMENT_ELEMENT",
        "fields": [
          {
            "fieldName": "Buffer",
            "fieldType": "PVOID",
            "fieldValue": "0xbadd00a0",
            "fieldComment": "Dummy pointer to segment buffer"
          }
        ]
      },
      "struct172": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "STATUS_SUCCESS (initial value)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Number of bytes transferred (initial value)"
          }
        ]
      }
    }
  },
  "NtSetEaFile": {
    "ntFunc": "NtSetEaFile",
    "pushes": [
      {
        "value": "0x00000020",
        "additionalComment": "ULONG EaBufferSize (32 bytes, typical small EA buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "PVOID EaBuffer (dummy pointer to EA buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "PIO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct173",
        "structureValueExpectations": "Status and information fields for I/O result.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct173": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "STATUS_SUCCESS (initial value)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Number of bytes transferred (initial value)"
          }
        ]
      }
    }
  },
  "NtSetInformationFile": {
    "ntFunc": "NtSetInformationFile",
    "pushes": [
      {
        "value": "0x00000010",
        "additionalComment": "FileInformationClass: FileDispositionInformation",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000008",
        "additionalComment": "Length: 8 bytes (typical for FILE_DISPOSITION_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to FILE_DISPOSITION_INFORMATION (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to IO_STATUS_BLOCK (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct174",
        "structureValueExpectations": "Status and Information fields.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct174": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "Operation status (success)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000008",
            "fieldComment": "Number of bytes processed"
          }
        ]
      }
    }
  },
  "NtSetVolumeInformationFile": {
    "ntFunc": "NtSetVolumeInformationFile",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "FileSystemInformationClass: FileFsLabelInformation",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000020",
        "additionalComment": "Length: 32 bytes (typical for FS label info)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to FILE_FS_LABEL_INFORMATION (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0070"
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to IO_STATUS_BLOCK (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct175",
        "structureValueExpectations": "Status and Information fields.",
        "pointedValue": None
      },
      {
        "value": "0x00000445",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct175": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "Operation status (success)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000020",
            "fieldComment": "Number of bytes processed"
          }
        ]
      }
    }
  },
  "NtUnlockFile": {
    "ntFunc": "NtUnlockFile",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Key: 0 (no key used)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to LARGE_INTEGER Length (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct176",
        "structureValueExpectations": "Length of region to unlock.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to LARGE_INTEGER ByteOffset (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct177",
        "structureValueExpectations": "Starting offset of region to unlock.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to IO_STATUS_BLOCK (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct178",
        "structureValueExpectations": "Status and Information fields.",
        "pointedValue": None
      },
      {
        "value": "0x00000446",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct176": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000000001000",
            "fieldComment": "Length: 4096 bytes"
          }
        ]
      },
      "struct177": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000000000000",
            "fieldComment": "Offset: start of file"
          }
        ]
      },
      "struct178": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "Operation status (success)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00001000",
            "fieldComment": "Number of bytes processed"
          }
        ]
      }
    }
  },
  "NtWriteFile": {
    "ntFunc": "NtWriteFile",
    "pushes": [
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to ULONG Key (dummy pointer, optional, usually None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to LARGE_INTEGER ByteOffset (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct179",
        "structureValueExpectations": "Offset in file to write.",
        "pointedValue": None
      },
      {
        "value": "0x00000010",
        "additionalComment": "Length: 16 bytes",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to Buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd00a0"
      },
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to IO_STATUS_BLOCK (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct180",
        "structureValueExpectations": "Status and Information fields.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ApcContext: None (no APC context)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ApcRoutine: None (no APC routine)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Event: None (no event)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000447",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct179": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000000000020",
            "fieldComment": "Offset: 32 bytes into file"
          }
        ]
      },
      "struct180": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "Operation status (success)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000010",
            "fieldComment": "Number of bytes written"
          }
        ]
      }
    }
  },
  "NtWriteFileGather": {
    "ntFunc": "NtWriteFileGather",
    "pushes": [
      {
        "value": "0xbadd00c0",
        "additionalComment": "Pointer to ULONG Key (dummy pointer, optional, usually None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd00d0",
        "additionalComment": "Pointer to LARGE_INTEGER ByteOffset (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct181",
        "structureValueExpectations": "Offset in file to write.",
        "pointedValue": None
      },
      {
        "value": "0x00000020",
        "additionalComment": "Length: 32 bytes",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00e0",
        "additionalComment": "Pointer to FILE_SEGMENT_ELEMENT array (dummy pointer)",
        "structurePointer": "FILE_SEGMENT_ELEMENT",
        "structureRef": "struct182",
        "structureValueExpectations": "Array of segment elements for scatter/gather I/O.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00f0",
        "additionalComment": "Pointer to IO_STATUS_BLOCK (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct183",
        "structureValueExpectations": "Status and Information fields.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ApcContext: None (no APC context)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ApcRoutine: None (no APC routine)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Event: None (no event)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000448",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct181": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000000000040",
            "fieldComment": "Offset: 64 bytes into file"
          }
        ]
      },
      "struct182": {
        "type": "FILE_SEGMENT_ELEMENT",
        "fields": [
          {
            "fieldName": "Buffer",
            "fieldType": "PVOID",
            "fieldValue": "0xbadd0100",
            "fieldComment": "Pointer to buffer segment (dummy pointer)"
          }
        ]
      },
      "struct183": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "Operation status (success)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000020",
            "fieldComment": "Number of bytes written"
          }
        ]
      }
    }
  },
  "NtCreateIoCompletion": {
    "ntFunc": "NtCreateIoCompletion",
    "pushes": [
      {
        "value": "0x00000004",
        "additionalComment": "ULONG NumberOfConcurrentThreads (default: 4)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES ObjectAttributes (None, typical for unnamed completion port)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x001F0003",
        "additionalComment": "ACCESS_MASK DesiredAccess (IO_COMPLETION_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "PHANDLE IoCompletionHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtOpenIoCompletion": {
    "ntFunc": "NtOpenIoCompletion",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES ObjectAttributes (None, typical for unnamed completion port)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x001F0003",
        "additionalComment": "ACCESS_MASK DesiredAccess (IO_COMPLETION_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "PHANDLE IoCompletionHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtQueryIoCompletion": {
    "ntFunc": "NtQueryIoCompletion",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "PULONG RequiredLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000020"
      },
      {
        "value": "0x00000020",
        "additionalComment": "ULONG InformationBufferLength (32 bytes, typical for IO_COMPLETION_BASIC_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "PVOID IoCompletionInformation (dummy pointer to output buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "IO_COMPLETION_INFORMATION_CLASS InformationClass (IoCompletionBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE IoCompletionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRemoveIoCompletion": {
    "ntFunc": "NtRemoveIoCompletion",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PLARGE_INTEGER Timeout (None, wait indefinitely)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "PIO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "PULONG CompletionValue (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "PULONG CompletionKey (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xdeadbeef"
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE IoCompletionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCompactKeys": {
    "ntFunc": "NtCompactKeys",
    "pushes": [
      {
        "value": "0xbadd0070",
        "additionalComment": "HANDLE KeysArray[] (dummy pointer to array of handles)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00004444"
      },
      {
        "value": "0x00000002",
        "additionalComment": "ULONG NrOfKeys (2 keys in array)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCompressKey": {
    "ntFunc": "NtCompressKey",
    "pushes": [
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE Key (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateKey": {
    "ntFunc": "NtCreateKey",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG Disposition (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00000020",
        "additionalComment": "CreateOptions (REG_OPTION_NON_VOLATILE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to UNICODE_STRING Class (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct184",
        "structureValueExpectations": "UNICODE_STRING describing the class of the key, often None.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "TitleIndex (usually 0, reserved)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct185",
        "structureValueExpectations": "Length, RootDirectory, ObjectName, Attributes, SecurityDescriptor, SecurityQualityOfService.",
        "pointedValue": None
      },
      {
        "value": "0x000f003f",
        "additionalComment": "DesiredAccess (KEY_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to HANDLE KeyHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct184": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "Zero length (None class)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "Zero max length (None class)"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0x00000000",
            "fieldComment": "None pointer (no class string)"
          }
        ]
      },
      "struct185": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd0080",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtDeleteKey": {
    "ntFunc": "NtDeleteKey",
    "pushes": [
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE KeyHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtDeleteValueKey": {
    "ntFunc": "NtDeleteValueKey",
    "pushes": [
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to UNICODE_STRING ValueName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct186",
        "structureValueExpectations": "UNICODE_STRING describing the value name to delete.",
        "pointedValue": None
      },
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE KeyHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct186": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "16 bytes (8 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "32 bytes (16 UTF-16 chars)"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0090",
            "fieldComment": "Pointer to value name string (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtEnumerateKey": {
    "ntFunc": "NtEnumerateKey",
    "pushes": [
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to ULONG ResultLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000030"
      },
      {
        "value": "0x00000100",
        "additionalComment": "Length (256 bytes, typical buffer size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to buffer for KeyInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0070"
      },
      {
        "value": "0x00000002",
        "additionalComment": "KeyInformationClass (KeyNodeInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Index (first key, 0-based)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE KeyHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtEnumerateValueKey": {
    "ntFunc": "NtEnumerateValueKey",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG ResultLength (dummy pointer, optional out parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000020"
      },
      {
        "value": "0x00000100",
        "additionalComment": "ULONG Length (256 bytes, typical buffer size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to buffer for KeyValueInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0100"
      },
      {
        "value": "0x00000001",
        "additionalComment": "KeyValueInformationClass = KeyValueFullInformation",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Index (first value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE KeyHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtFlushKey": {
    "ntFunc": "NtFlushKey",
    "pushes": [
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE KeyHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtLoadKey": {
    "ntFunc": "NtLoadKey",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES HiveFileName (dummy pointer, typically non-None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct187",
        "structureValueExpectations": "Length/size field; optional root directory handle; pointer to UNICODE_STRING object name; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES DestinationKeyName (dummy pointer, typically non-None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct188",
        "structureValueExpectations": "Length/size field; optional root directory handle; pointer to UNICODE_STRING object name; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct187": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd00a0",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      },
      "struct188": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd00b0",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtLoadKey2": {
    "ntFunc": "NtLoadKey2",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "Flags (e.g., REG_NO_LAZY_FLUSH)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES HiveFileName (dummy pointer, typically non-None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct189",
        "structureValueExpectations": "Length/size field; optional root directory handle; pointer to UNICODE_STRING object name; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES DestinationKeyName (dummy pointer, typically non-None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct190",
        "structureValueExpectations": "Length/size field; optional root directory handle; pointer to UNICODE_STRING object name; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct189": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd00c0",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      },
      "struct190": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd00d0",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtNotifyChangeKey": {
    "ntFunc": "NtNotifyChangeKey",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN Asynchronous (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000100",
        "additionalComment": "ULONG RegChangesDataBufferLength (256 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to RegChangesDataBuffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0200"
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN WatchSubtree (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000010",
        "additionalComment": "ULONG NotifyFilter (REG_NOTIFY_CHANGE_LAST_SET)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to IO_STATUS_BLOCK (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct191",
        "structureValueExpectations": "Status and Information fields for I/O completion.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to ApcRoutineContext (dummy pointer, optional user context)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xdeadbeef"
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to IO_APC_ROUTINE (dummy pointer, optional callback)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0300"
      },
      {
        "value": "0x0000beef",
        "additionalComment": "HANDLE EventHandle (dummy handle, optional event)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE KeyHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct191": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "STATUS_SUCCESS (initial value)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "No information yet"
          }
        ]
      }
    }
  },
  "NtOpenKey": {
    "ntFunc": "NtOpenKey",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None (no OBJECT_ATTRIBUTES, open root key)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00020019",
        "additionalComment": "KEY_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to HANDLE KeyHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtQueryKey": {
    "ntFunc": "NtQueryKey",
    "pushes": [
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to ULONG ResultLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000040"
      },
      {
        "value": "0x00000100",
        "additionalComment": "Length of buffer (256 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to buffer for KeyInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "KeyInformationClass = KeyNodeInformation",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00004444",
        "additionalComment": "HANDLE KeyHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryMultipleValueKey": {
    "ntFunc": "NtQueryMultipleValueKey",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to ULONG RequiredLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000200"
      },
      {
        "value": "0x00000200",
        "additionalComment": "BufferLength (512 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to DataBuffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "NumberOfValues = 2",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to KEY_MULTIPLE_VALUE_INFORMATION array (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00004444",
        "additionalComment": "HANDLE KeyHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryValueKey": {
    "ntFunc": "NtQueryValueKey",
    "pushes": [
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to ULONG ResultLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000020"
      },
      {
        "value": "0x00000040",
        "additionalComment": "Length (64 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to KeyValueInformation buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "KeyValueInformationClass = KeyValueFullInformation",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None ValueName (query default value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00004444",
        "additionalComment": "HANDLE KeyHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtReplaceKey": {
    "ntFunc": "NtReplaceKey",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None BackupHiveFileName (no backup)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00004444",
        "additionalComment": "HANDLE KeyHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None NewHiveFileName (no new hive file)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRestoreKey": {
    "ntFunc": "NtRestoreKey",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "RestoreOption (default: 0, e.g. no special options)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE FileHandle (dummy handle to registry hive file)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000beef",
        "additionalComment": "HANDLE KeyHandle (dummy handle to registry key)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSaveKey": {
    "ntFunc": "NtSaveKey",
    "pushes": [
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE FileHandle (dummy handle to registry hive file)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000beef",
        "additionalComment": "HANDLE KeyHandle (dummy handle to registry key)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetInformationKey": {
    "ntFunc": "NtSetInformationKey",
    "pushes": [
      {
        "value": "0x00000010",
        "additionalComment": "ULONG DataLength (example: 16 bytes of data)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "PVOID KeyInformationData (dummy pointer to data buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xdeadbeef"
      },
      {
        "value": "0x00000001",
        "additionalComment": "KEY_SET_INFORMATION_CLASS InformationClass (KeyWriteTimeInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x0000beef",
        "additionalComment": "HANDLE KeyHandle (dummy handle to registry key)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetValueKey": {
    "ntFunc": "NtSetValueKey",
    "pushes": [
      {
        "value": "0x00000004",
        "additionalComment": "ULONG DataSize (example: 4 bytes of data)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "PVOID Data (dummy pointer to data buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x12345678"
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG Type (REG_SZ)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG TitleIndex (usually 0, reserved)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "PUNICODE_STRING ValueName (dummy pointer to UNICODE_STRING)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct192",
        "structureValueExpectations": "Length, MaximumLength, Buffer pointer to value name string.",
        "pointedValue": None
      },
      {
        "value": "0x0000beef",
        "additionalComment": "HANDLE KeyHandle (dummy handle to registry key)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct192": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Length in bytes of the string (8 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Maximum buffer size in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0040",
            "fieldComment": "Dummy pointer to value name string buffer"
          }
        ]
      }
    }
  },
  "NtUnloadKey": {
    "ntFunc": "NtUnloadKey",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "POBJECT_ATTRIBUTES DestinationKeyName (dummy pointer to OBJECT_ATTRIBUTES)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct193",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct193": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd0050",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "RtlFormatCurrentUserKeyPath": {
    "ntFunc": "RtlFormatCurrentUserKeyPath",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PUNICODE_STRING RegistryPath (None, output parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateKeyedEvent": {
    "ntFunc": "NtCreateKeyedEvent",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "ULONG Reserved (must be zero)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES ObjectAttributes (None, unnamed event)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x001F0003",
        "additionalComment": "ACCESS_MASK DesiredAccess (EVENT_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "PHANDLE KeyedEventHandle (dummy pointer, output parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000444"
      }
    ],
    "structures": {}
  },
  "NtReleaseKeyedEvent": {
    "ntFunc": "NtReleaseKeyedEvent",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PLARGE_INTEGER Timeout (None, wait forever)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN Alertable (FALSE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID Key (None, no key specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE KeyedEventHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtWaitForKeyedEvent": {
    "ntFunc": "NtWaitForKeyedEvent",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PLARGE_INTEGER Timeout (None, wait forever)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN Alertable (FALSE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID Key (None, no key specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE KeyedEventHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateMutant": {
    "ntFunc": "NtCreateMutant",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN InitialOwner (FALSE, caller does not own mutant initially)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES ObjectAttributes (None, unnamed mutant)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x001F0001",
        "additionalComment": "ACCESS_MASK DesiredAccess (MUTANT_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "PHANDLE MutantHandle (dummy pointer, output parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000445"
      }
    ],
    "structures": {}
  },
  "NtOpenMutant": {
    "ntFunc": "NtOpenMutant",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None (no OBJECT_ATTRIBUTES specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x001F0001",
        "additionalComment": "DesiredAccess (MUTANT_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to HANDLE MutantHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtQueryMutant": {
    "ntFunc": "NtQueryMutant",
    "pushes": [
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to ULONG ResultLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00000010",
        "additionalComment": "MutantInformationLength (size of MUTANT_BASIC_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to MUTANT_BASIC_INFORMATION (dummy pointer)",
        "structurePointer": "MUTANT_BASIC_INFORMATION",
        "structureRef": "struct194",
        "structureValueExpectations": "Holds state and count information about the mutant.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "MutantInformationClass (MutantBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE MutantHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct194": {
        "type": "MUTANT_BASIC_INFORMATION",
        "fields": [
          {
            "fieldName": "CurrentCount",
            "fieldType": "LONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Mutant is signaled (count = 1)"
          },
          {
            "fieldName": "OwnedByCaller",
            "fieldType": "BOOLEAN",
            "fieldValue": "0x01",
            "fieldComment": "TRUE (owned by caller)"
          },
          {
            "fieldName": "AbandonedState",
            "fieldType": "BOOLEAN",
            "fieldValue": "0x00",
            "fieldComment": "FALSE (not abandoned)"
          }
        ]
      }
    }
  },
  "NtReleaseMutant": {
    "ntFunc": "NtReleaseMutant",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to LONG PreviousCount (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE MutantHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAcceptConnectPort": {
    "ntFunc": "NtAcceptConnectPort",
    "pushes": [
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to LPC_SECTION_MEMORY ClientSharedMemory (dummy pointer)",
        "structurePointer": "LPC_SECTION_MEMORY",
        "structureRef": "struct195",
        "structureValueExpectations": "Describes client shared memory section.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to LPC_SECTION_OWNER_MEMORY ServerSharedMemory (dummy pointer)",
        "structurePointer": "LPC_SECTION_OWNER_MEMORY",
        "structureRef": "struct196",
        "structureValueExpectations": "Describes server shared memory section.",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "AcceptConnection = TRUE",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to LPC_MESSAGE ConnectionReply (dummy pointer)",
        "structurePointer": "LPC_MESSAGE",
        "structureRef": "struct197",
        "structureValueExpectations": "Reply message structure.",
        "pointedValue": None
      },
      {
        "value": "0x00000445",
        "additionalComment": "HANDLE AlternativeReceivePortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to HANDLE ServerPortHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct195": {
        "type": "LPC_SECTION_MEMORY",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "ULONG",
            "fieldValue": "0x00000018",
            "fieldComment": "Size of LPC_SECTION_MEMORY"
          },
          {
            "fieldName": "SectionHandle",
            "fieldType": "HANDLE",
            "fieldValue": "0x00000446",
            "fieldComment": "Dummy section handle"
          },
          {
            "fieldName": "SectionBase",
            "fieldType": "PVOID",
            "fieldValue": "0x10000000",
            "fieldComment": "Base address of section"
          },
          {
            "fieldName": "SectionSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00001000",
            "fieldComment": "Section size (4KB)"
          }
        ]
      },
      "struct196": {
        "type": "LPC_SECTION_OWNER_MEMORY",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "ULONG",
            "fieldValue": "0x00000020",
            "fieldComment": "Size of LPC_SECTION_OWNER_MEMORY"
          },
          {
            "fieldName": "SectionHandle",
            "fieldType": "HANDLE",
            "fieldValue": "0x00000447",
            "fieldComment": "Dummy section handle"
          },
          {
            "fieldName": "SectionBase",
            "fieldType": "PVOID",
            "fieldValue": "0x20000000",
            "fieldComment": "Base address of section"
          },
          {
            "fieldName": "SectionSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00002000",
            "fieldComment": "Section size (8KB)"
          },
          {
            "fieldName": "ClientBase",
            "fieldType": "PVOID",
            "fieldValue": "0x21000000",
            "fieldComment": "Client base address"
          },
          {
            "fieldName": "ClientSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00001000",
            "fieldComment": "Client section size (4KB)"
          }
        ]
      },
      "struct197": {
        "type": "LPC_MESSAGE",
        "fields": [
          {
            "fieldName": "DataLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Message data length"
          },
          {
            "fieldName": "TotalLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0030",
            "fieldComment": "Total message length"
          },
          {
            "fieldName": "Type",
            "fieldType": "USHORT",
            "fieldValue": "0x0001",
            "fieldComment": "Message type (LPC_REQUEST)"
          },
          {
            "fieldName": "DataInfoOffset",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "No data info"
          },
          {
            "fieldName": "ClientId",
            "fieldType": "CLIENT_ID",
            "fieldValue": "0xbadd0080",
            "fieldComment": "Pointer to CLIENT_ID (dummy pointer)"
          },
          {
            "fieldName": "MessageId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Message identifier"
          }
        ]
      }
    }
  },
  "NtCompleteConnectPort": {
    "ntFunc": "NtCompleteConnectPort",
    "pushes": [
      {
        "value": "0x00000445",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtConnectPort": {
    "ntFunc": "NtConnectPort",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG ConnectionInfoLength (dummy pointer, typically input/output)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000020"
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to connection info buffer (dummy pointer, optional, may be None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to ULONG MaximumMessageLength (dummy pointer, output)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00001000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "PLPC_SECTION_MEMORY ServerSharedMemory (None, optional)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PLPC_SECTION_OWNER_MEMORY ClientSharedMemory (None, optional)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PSECURITY_QUALITY_OF_SERVICE SecurityQos (None, optional, default for most clients)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to UNICODE_STRING ServerPortName (dummy pointer, required)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct198",
        "structureValueExpectations": "UNICODE_STRING describing the LPC port name.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to HANDLE ClientPortHandle (dummy pointer, output)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct198": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Length in bytes of the string"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0040",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd00b0",
            "fieldComment": "Pointer to LPC port name string (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtCreatePort": {
    "ntFunc": "NtCreatePort",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to ULONG Reserved (None, unused in user mode)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG MaxDataLength (4096 bytes typical for LPC)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000200",
        "additionalComment": "ULONG MaxConnectInfoLength (512 bytes typical)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer, required)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct199",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to HANDLE PortHandle (dummy pointer, output)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct199": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd00c0",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtImpersonateClientOfPort": {
    "ntFunc": "NtImpersonateClientOfPort",
    "pushes": [
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to LPC_MESSAGE Request (dummy pointer, required)",
        "structurePointer": "LPC_MESSAGE",
        "structureRef": "struct200",
        "structureValueExpectations": "LPC_MESSAGE structure containing client request.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct200": {
        "type": "LPC_MESSAGE",
        "fields": [
          {
            "fieldName": "DataLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Length of message data"
          },
          {
            "fieldName": "TotalLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Total length including header"
          },
          {
            "fieldName": "Type",
            "fieldType": "USHORT",
            "fieldValue": "0x0001",
            "fieldComment": "Message type (LPC_REQUEST)"
          },
          {
            "fieldName": "DataInfoOffset",
            "fieldType": "USHORT",
            "fieldValue": "0x0018",
            "fieldComment": "Offset to data info"
          },
          {
            "fieldName": "ClientId",
            "fieldType": "CLIENT_ID",
            "fieldValue": "0xbadd00d0",
            "fieldComment": "Pointer to CLIENT_ID (dummy pointer)"
          },
          {
            "fieldName": "MessageId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Message identifier"
          }
        ]
      }
    }
  },
  "NtListenPort": {
    "ntFunc": "NtListenPort",
    "pushes": [
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to LPC_MESSAGE ConnectionRequest (dummy pointer, output)",
        "structurePointer": "LPC_MESSAGE",
        "structureRef": "struct201",
        "structureValueExpectations": "LPC_MESSAGE structure to receive connection request.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct201": {
        "type": "LPC_MESSAGE",
        "fields": [
          {
            "fieldName": "DataLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Length of message data"
          },
          {
            "fieldName": "TotalLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Total length including header"
          },
          {
            "fieldName": "Type",
            "fieldType": "USHORT",
            "fieldValue": "0x0002",
            "fieldComment": "Message type (LPC_CONNECTION_REQUEST)"
          },
          {
            "fieldName": "DataInfoOffset",
            "fieldType": "USHORT",
            "fieldValue": "0x0018",
            "fieldComment": "Offset to data info"
          },
          {
            "fieldName": "ClientId",
            "fieldType": "CLIENT_ID",
            "fieldValue": "0xbadd00e0",
            "fieldComment": "Pointer to CLIENT_ID (dummy pointer)"
          },
          {
            "fieldName": "MessageId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000002",
            "fieldComment": "Message identifier"
          }
        ]
      }
    }
  },
  "NtQueryInformationPort": {
    "ntFunc": "NtQueryInformationPort",
    "pushes": [
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to ULONG ResultLength (dummy pointer, output)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00000010",
        "additionalComment": "ULONG Length (16 bytes typical for PORT_BASIC_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00a0",
        "additionalComment": "Pointer to PORT_INFORMATION buffer (dummy pointer, output)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "PORT_INFORMATION_CLASS PortInformationClass (PortBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtReadRequestData": {
    "ntFunc": "NtReadRequestData",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG ResultLength (dummy pointer, typically receives number of bytes read)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000020"
      },
      {
        "value": "0x00000020",
        "additionalComment": "ULONG Length (number of bytes to read, e.g., 32 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to buffer (dummy pointer, receives data)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xdeadbeef"
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG DataIndex (index of data to read, e.g., 1)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to LPC_MESSAGE Request (dummy pointer)",
        "structurePointer": "LPC_MESSAGE",
        "structureRef": "struct202",
        "structureValueExpectations": "Message header and data fields for the request.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct202": {
        "type": "LPC_MESSAGE",
        "fields": [
          {
            "fieldName": "DataLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Length of data in message (32 bytes)"
          },
          {
            "fieldName": "TotalLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0030",
            "fieldComment": "Total length including header"
          },
          {
            "fieldName": "Type",
            "fieldType": "USHORT",
            "fieldValue": "0x0001",
            "fieldComment": "Message type (e.g., LPC_REQUEST)"
          },
          {
            "fieldName": "DataInfoOffset",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Offset to data info"
          },
          {
            "fieldName": "ClientId",
            "fieldType": "CLIENT_ID",
            "fieldValue": "0xbadd0090",
            "fieldComment": "Pointer to CLIENT_ID (dummy pointer)"
          },
          {
            "fieldName": "MessageId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "Message identifier"
          },
          {
            "fieldName": "SectionSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Unused in this example"
          }
        ]
      }
    }
  },
  "NtReplyPort": {
    "ntFunc": "NtReplyPort",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to LPC_MESSAGE Reply (dummy pointer)",
        "structurePointer": "LPC_MESSAGE",
        "structureRef": "struct203",
        "structureValueExpectations": "Message header and data fields for the reply.",
        "pointedValue": None
      },
      {
        "value": "0x00000445",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct203": {
        "type": "LPC_MESSAGE",
        "fields": [
          {
            "fieldName": "DataLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Length of data in message (16 bytes)"
          },
          {
            "fieldName": "TotalLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Total length including header"
          },
          {
            "fieldName": "Type",
            "fieldType": "USHORT",
            "fieldValue": "0x0002",
            "fieldComment": "Message type (e.g., LPC_REPLY)"
          },
          {
            "fieldName": "DataInfoOffset",
            "fieldType": "USHORT",
            "fieldValue": "0x0008",
            "fieldComment": "Offset to data info"
          },
          {
            "fieldName": "ClientId",
            "fieldType": "CLIENT_ID",
            "fieldValue": "0xbadd00a0",
            "fieldComment": "Pointer to CLIENT_ID (dummy pointer)"
          },
          {
            "fieldName": "MessageId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000002",
            "fieldComment": "Message identifier"
          },
          {
            "fieldName": "SectionSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Unused in this example"
          }
        ]
      }
    }
  },
  "NtReplyWaitReceivePort": {
    "ntFunc": "NtReplyWaitReceivePort",
    "pushes": [
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to LPC_MESSAGE IncomingRequest (dummy pointer)",
        "structurePointer": "LPC_MESSAGE",
        "structureRef": "struct204",
        "structureValueExpectations": "Message header and data fields for the incoming request.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to LPC_MESSAGE Reply (dummy pointer)",
        "structurePointer": "LPC_MESSAGE",
        "structureRef": "struct205",
        "structureValueExpectations": "Message header and data fields for the reply.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to HANDLE ReceivePortHandle (dummy pointer, receives handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000446"
      },
      {
        "value": "0x00000446",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct204": {
        "type": "LPC_MESSAGE",
        "fields": [
          {
            "fieldName": "DataLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0018",
            "fieldComment": "Length of data in message (24 bytes)"
          },
          {
            "fieldName": "TotalLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0028",
            "fieldComment": "Total length including header"
          },
          {
            "fieldName": "Type",
            "fieldType": "USHORT",
            "fieldValue": "0x0003",
            "fieldComment": "Message type (e.g., LPC_CONNECTION_REQUEST)"
          },
          {
            "fieldName": "DataInfoOffset",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Offset to data info"
          },
          {
            "fieldName": "ClientId",
            "fieldType": "CLIENT_ID",
            "fieldValue": "0xbadd00b0",
            "fieldComment": "Pointer to CLIENT_ID (dummy pointer)"
          },
          {
            "fieldName": "MessageId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000003",
            "fieldComment": "Message identifier"
          },
          {
            "fieldName": "SectionSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Unused in this example"
          }
        ]
      },
      "struct205": {
        "type": "LPC_MESSAGE",
        "fields": [
          {
            "fieldName": "DataLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Length of data in message (16 bytes)"
          },
          {
            "fieldName": "TotalLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Total length including header"
          },
          {
            "fieldName": "Type",
            "fieldType": "USHORT",
            "fieldValue": "0x0002",
            "fieldComment": "Message type (e.g., LPC_REPLY)"
          },
          {
            "fieldName": "DataInfoOffset",
            "fieldType": "USHORT",
            "fieldValue": "0x0008",
            "fieldComment": "Offset to data info"
          },
          {
            "fieldName": "ClientId",
            "fieldType": "CLIENT_ID",
            "fieldValue": "0xbadd00c0",
            "fieldComment": "Pointer to CLIENT_ID (dummy pointer)"
          },
          {
            "fieldName": "MessageId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000004",
            "fieldComment": "Message identifier"
          },
          {
            "fieldName": "SectionSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Unused in this example"
          }
        ]
      }
    }
  },
  "NtReplyWaitReplyPort": {
    "ntFunc": "NtReplyWaitReplyPort",
    "pushes": [
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to LPC_MESSAGE Reply (dummy pointer)",
        "structurePointer": "LPC_MESSAGE",
        "structureRef": "struct206",
        "structureValueExpectations": "Message header and data fields for the reply.",
        "pointedValue": None
      },
      {
        "value": "0x00000447",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct206": {
        "type": "LPC_MESSAGE",
        "fields": [
          {
            "fieldName": "DataLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Length of data in message (16 bytes)"
          },
          {
            "fieldName": "TotalLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Total length including header"
          },
          {
            "fieldName": "Type",
            "fieldType": "USHORT",
            "fieldValue": "0x0002",
            "fieldComment": "Message type (e.g., LPC_REPLY)"
          },
          {
            "fieldName": "DataInfoOffset",
            "fieldType": "USHORT",
            "fieldValue": "0x0008",
            "fieldComment": "Offset to data info"
          },
          {
            "fieldName": "ClientId",
            "fieldType": "CLIENT_ID",
            "fieldValue": "0xbadd00d0",
            "fieldComment": "Pointer to CLIENT_ID (dummy pointer)"
          },
          {
            "fieldName": "MessageId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000005",
            "fieldComment": "Message identifier"
          },
          {
            "fieldName": "SectionSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Unused in this example"
          }
        ]
      }
    }
  },
  "NtRequestPort": {
    "ntFunc": "NtRequestPort",
    "pushes": [
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to LPC_MESSAGE Request (dummy pointer)",
        "structurePointer": "LPC_MESSAGE",
        "structureRef": "struct207",
        "structureValueExpectations": "Message header and data fields for the request.",
        "pointedValue": None
      },
      {
        "value": "0x00000448",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct207": {
        "type": "LPC_MESSAGE",
        "fields": [
          {
            "fieldName": "DataLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Length of data in message (32 bytes)"
          },
          {
            "fieldName": "TotalLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0030",
            "fieldComment": "Total length including header"
          },
          {
            "fieldName": "Type",
            "fieldType": "USHORT",
            "fieldValue": "0x0001",
            "fieldComment": "Message type (e.g., LPC_REQUEST)"
          },
          {
            "fieldName": "DataInfoOffset",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Offset to data info"
          },
          {
            "fieldName": "ClientId",
            "fieldType": "CLIENT_ID",
            "fieldValue": "0xbadd00e0",
            "fieldComment": "Pointer to CLIENT_ID (dummy pointer)"
          },
          {
            "fieldName": "MessageId",
            "fieldType": "ULONG",
            "fieldValue": "0x00000006",
            "fieldComment": "Message identifier"
          },
          {
            "fieldName": "SectionSize",
            "fieldType": "ULONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Unused in this example"
          }
        ]
      }
    }
  },
  "NtRequestWaitReplyPort": {
    "ntFunc": "NtRequestWaitReplyPort",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to LPC_MESSAGE IncomingReply (dummy pointer, commonly None for no reply expected)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to LPC_MESSAGE Request (dummy pointer, typically points to a valid LPC_MESSAGE structure)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtWriteRequestData": {
    "ntFunc": "NtWriteRequestData",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to ULONG ResultLength (dummy pointer, may be None if not needed)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000020"
      },
      {
        "value": "0x00000010",
        "additionalComment": "ULONG Length (16 bytes, typical small message)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to buffer (dummy pointer, points to data to write)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xdeadbeef"
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG DataIndex (0 for first data entry)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to LPC_MESSAGE Request (dummy pointer, typically points to a valid LPC_MESSAGE structure)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE PortHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateProcess": {
    "ntFunc": "NtCreateProcess",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE ExceptionPort (None, not used in most cases)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE DebugPort (None, not used in most cases)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE SectionHandle (None, process will not be based on a section)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN InheritObjectTable (TRUE, inherit handle table from parent)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ParentProcess (dummy handle, typically a valid process handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer, commonly None for default attributes)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct208",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F0FFF",
        "additionalComment": "ACCESS_MASK DesiredAccess (PROCESS_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to HANDLE ProcessHandle (dummy pointer, receives new process handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct208": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (no name)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtFlushInstructionCache": {
    "ntFunc": "NtFlushInstructionCache",
    "pushes": [
      {
        "value": "0x00001000",
        "additionalComment": "ULONG NumberOfBytesToFlush (4096 bytes, typical page size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00400000",
        "additionalComment": "PVOID BaseAddress (typical image base address)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtOpenProcess": {
    "ntFunc": "NtOpenProcess",
    "pushes": [
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to CLIENT_ID (dummy pointer)",
        "structurePointer": "CLIENT_ID",
        "structureRef": "struct209",
        "structureValueExpectations": "UniqueProcess and UniqueThread identifiers.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer, commonly None for default attributes)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct210",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F0FFF",
        "additionalComment": "ACCESS_MASK AccessMask (PROCESS_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to HANDLE ProcessHandle (dummy pointer, receives process handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct209": {
        "type": "CLIENT_ID",
        "fields": [
          {
            "fieldName": "UniqueProcess",
            "fieldType": "HANDLE",
            "fieldValue": "0x99995555",
            "fieldComment": "Dummy process identifier value"
          },
          {
            "fieldName": "UniqueThread",
            "fieldType": "HANDLE",
            "fieldValue": "0x00000000",
            "fieldComment": "None or unused example value"
          }
        ]
      },
      "struct210": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (no name)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtQueryInformationProcess": {
    "ntFunc": "NtQueryInformationProcess",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00000010",
        "additionalComment": "ProcessInformationLength (16 bytes, typical for PROCESS_BASIC_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to PROCESS_BASIC_INFORMATION (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "ProcessInformationClass (ProcessBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetInformationProcess": {
    "ntFunc": "NtSetInformationProcess",
    "pushes": [
      {
        "value": "0x00000008",
        "additionalComment": "ProcessInformationLength (8 bytes, typical for setting a ULONG value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to process information buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00000001",
        "additionalComment": "ProcessInformationClass (ProcessBreakOnTermination)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtTerminateProcess": {
    "ntFunc": "NtTerminateProcess",
    "pushes": [
      {
        "value": "0xC0000005",
        "additionalComment": "NTSTATUS ExitStatus (STATUS_ACCESS_VIOLATION as example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlCreateUserProcess": {
    "ntFunc": "RtlCreateUserProcess",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to RTL_USER_PROCESS_INFORMATION (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE ExceptionPort (None, not used in most cases)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE DebugPort (None, not used in most cases)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN InheritHandles (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ParentProcess (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PSECURITY_DESCRIPTOR ThreadSecurityDescriptor (None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PSECURITY_DESCRIPTOR ProcessSecurityDescriptor (None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to RTL_USER_PROCESS_PARAMETERS (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0050"
      },
      {
        "value": "0x00000030",
        "additionalComment": "ULONG ObjectAttributes (OBJ_CASE_INSENSITIVE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to UNICODE_STRING ImagePath (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct211",
        "structureValueExpectations": "Points to a UNICODE_STRING describing the image path.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct211": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Length in bytes of the string"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0040",
            "fieldComment": "Maximum length in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0090",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtCreateProfile": {
    "ntFunc": "NtCreateProfile",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "KAFFINITY Affinity (CPU 0)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "KPROFILE_SOURCE ProfileSource (ProfileTime)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG BufferSize (4096 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to Buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000010",
        "additionalComment": "ULONG BucketSize (16 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00020000",
        "additionalComment": "ULONG ImageSize (128 KB)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00400000",
        "additionalComment": "PVOID ImageBase (typical PE base address)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE Process (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to HANDLE ProfileHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtQueryIntervalProfile": {
    "ntFunc": "NtQueryIntervalProfile",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Pointer to ULONG Interval (None, typical for querying only)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "KPROFILE_SOURCE ProfileSource (ProfileTime, common value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetIntervalProfile": {
    "ntFunc": "NtSetIntervalProfile",
    "pushes": [
      {
        "value": "0x00002710",
        "additionalComment": "ULONG Interval (10,000, typical timer interval)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "KPROFILE_SOURCE Source (ProfileTime, common value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtStartProfile": {
    "ntFunc": "NtStartProfile",
    "pushes": [
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE ProfileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtStopProfile": {
    "ntFunc": "NtStopProfile",
    "pushes": [
      {
        "value": "0x0000abcd",
        "additionalComment": "HANDLE ProfileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateSection": {
    "ntFunc": "NtCreateSection",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to HANDLE SectionHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x000F001F",
        "additionalComment": "ACCESS_MASK DesiredAccess (SECTION_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer, commonly None for anonymous section)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct212",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to LARGE_INTEGER MaximumSize (dummy pointer, commonly used for section size)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct213",
        "structureValueExpectations": "QuadPart field specifying maximum section size.",
        "pointedValue": None
      },
      {
        "value": "0x00000004",
        "additionalComment": "ULONG SectionPageProtection (PAGE_READWRITE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x08000000",
        "additionalComment": "ULONG AllocationAttributes (SEC_COMMIT)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE FileHandle (None, anonymous section)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct212": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (anonymous section)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      },
      "struct213": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000010000000",
            "fieldComment": "256 MB section size"
          }
        ]
      }
    }
  },
  "NtExtendSection": {
    "ntFunc": "NtExtendSection",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to LARGE_INTEGER NewSectionSize (dummy pointer, commonly None for no change)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct214",
        "structureValueExpectations": "New size for the section in bytes, or None to not change.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE SectionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct214": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x00020000",
            "fieldComment": "New section size: 128 KB"
          }
        ]
      }
    }
  },
  "NtMapViewOfSection": {
    "ntFunc": "NtMapViewOfSection",
    "pushes": [
      {
        "value": "0x00000040",
        "additionalComment": "ULONG Protect (PAGE_EXECUTE_READWRITE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG AllocationType (MEM_COMMIT)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000002",
        "additionalComment": "DWORD InheritDisposition (ViewShare)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to ULONG ViewSize (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00002000"
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to LARGE_INTEGER SectionOffset (dummy pointer, commonly None for start of section)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct215",
        "structureValueExpectations": "Offset into section, or None for start.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG CommitSize (0 for default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG ZeroBits (0 for default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to PVOID BaseAddress (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00400000"
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle, typically current process)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000555",
        "additionalComment": "HANDLE SectionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct215": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x00000000",
            "fieldComment": "Offset 0 (start of section)"
          }
        ]
      }
    }
  },
  "NtOpenSection": {
    "ntFunc": "NtOpenSection",
    "pushes": [
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct216",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x000F0000",
        "additionalComment": "ACCESS_MASK DesiredAccess (SECTION_MAP_READ | SECTION_MAP_WRITE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to HANDLE SectionHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct216": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (no name, open by handle)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtQuerySection": {
    "ntFunc": "NtQuerySection",
    "pushes": [
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to ULONG ResultLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000040"
      },
      {
        "value": "0x00000040",
        "additionalComment": "ULONG InformationBufferSize (64 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to buffer for section information (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "SECTION_INFORMATION_CLASS (SectionBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000555",
        "additionalComment": "HANDLE SectionHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtUnmapViewOfSection": {
    "ntFunc": "NtUnmapViewOfSection",
    "pushes": [
      {
        "value": "0x00400000",
        "additionalComment": "PVOID BaseAddress (example mapped address)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle, typically current process)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateSemaphore": {
    "ntFunc": "NtCreateSemaphore",
    "pushes": [
      {
        "value": "0x00000010",
        "additionalComment": "ULONG MaximumCount (example: 16)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG InitialCount (example: 1)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer, often None for unnamed semaphore)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct217",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F0003",
        "additionalComment": "ACCESS_MASK DesiredAccess (example: SEMAPHORE_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to HANDLE SemaphoreHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct217": {
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
            "fieldComment": "None (unnamed semaphore)"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (unnamed semaphore)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtOpenSemaphore": {
    "ntFunc": "NtOpenSemaphore",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer, typically points to named semaphore)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct218",
        "structureValueExpectations": "Length/size field; optional root directory handle; pointer to UNICODE_STRING object name; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F0003",
        "additionalComment": "ACCESS_MASK DesiredAccess (example: SEMAPHORE_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to HANDLE SemaphoreHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct218": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd00a0",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer for named semaphore)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtQuerySemaphore": {
    "ntFunc": "NtQuerySemaphore",
    "pushes": [
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00000010",
        "additionalComment": "ULONG SemaphoreInformationLength (example: 16 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to buffer for SemaphoreInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "SEMAPHORE_INFORMATION_CLASS SemaphoreBasicInformation",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE SemaphoreHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtReleaseSemaphore": {
    "ntFunc": "NtReleaseSemaphore",
    "pushes": [
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to ULONG PreviousCount (dummy pointer, can be None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG ReleaseCount (example: 1)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE SemaphoreHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateSymbolicLinkObject": {
    "ntFunc": "NtCreateSymbolicLinkObject",
    "pushes": [
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to UNICODE_STRING DestinationName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct219",
        "structureValueExpectations": "UNICODE_STRING structure describing the symbolic link target name.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct220",
        "structureValueExpectations": "Length/size field; optional root directory handle; pointer to UNICODE_STRING object name; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x000F0001",
        "additionalComment": "ACCESS_MASK DesiredAccess (example: SYMBOLIC_LINK_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to HANDLE pHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct219": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0014",
            "fieldComment": "Length in bytes (example: 20 bytes for 10 WCHARs)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Maximum length in bytes (example: 32 bytes)"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd00b0",
            "fieldComment": "Pointer to wide string buffer (dummy pointer)"
          }
        ]
      },
      "struct220": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0xbadd00c0",
            "fieldComment": "Pointer to UNICODE_STRING (dummy pointer for symbolic link name)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtOpenSymbolicLinkObject": {
    "ntFunc": "NtOpenSymbolicLinkObject",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "None (no OBJECT_ATTRIBUTES, open by name not provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00020019",
        "additionalComment": "SYMBOLIC_LINK_QUERY | STANDARD_RIGHTS_READ (realistic DesiredAccess)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to HANDLE SymbolicLinkHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtQuerySymbolicLinkObject": {
    "ntFunc": "NtQuerySymbolicLinkObject",
    "pushes": [
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to ULONG DataWritten (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to UNICODE_STRING LinkTarget (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct221",
        "structureValueExpectations": "UNICODE_STRING buffer for the symbolic link target.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE SymbolicLinkHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct221": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "Length in bytes of the string"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "Maximum buffer size in bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0090",
            "fieldComment": "Pointer to buffer (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtAlertResumeThread": {
    "ntFunc": "NtAlertResumeThread",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to ULONG SuspendCount (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00005555",
        "additionalComment": "HANDLE ThreadHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtContinue": {
    "ntFunc": "NtContinue",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "FALSE (do not raise alert)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to CONTEXT structure (dummy pointer)",
        "structurePointer": "CONTEXT",
        "structureRef": "struct222",
        "structureValueExpectations": "Thread context structure with register state.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct222": {
        "type": "CONTEXT",
        "fields": [
          {
            "fieldName": "ContextFlags",
            "fieldType": "DWORD",
            "fieldValue": "0x00010007",
            "fieldComment": "CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS"
          },
          {
            "fieldName": "Eip",
            "fieldType": "DWORD",
            "fieldValue": "0x00401000",
            "fieldComment": "Instruction pointer"
          },
          {
            "fieldName": "Esp",
            "fieldType": "DWORD",
            "fieldValue": "0x0012FFB0",
            "fieldComment": "Stack pointer"
          }
        ]
      }
    }
  },
  "NtCreateThread": {
    "ntFunc": "NtCreateThread",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "TRUE (create suspended)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to INITIAL_TEB (dummy pointer)",
        "structurePointer": "INITIAL_TEB",
        "structureRef": "struct223",
        "structureValueExpectations": "Stack base/limit and TEB allocation info.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to CONTEXT (dummy pointer)",
        "structurePointer": "CONTEXT",
        "structureRef": "struct224",
        "structureValueExpectations": "Initial thread context (registers, etc).",
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to CLIENT_ID (dummy pointer)",
        "structurePointer": "CLIENT_ID",
        "structureRef": "struct225",
        "structureValueExpectations": "UniqueProcess and UniqueThread identifiers.",
        "pointedValue": None
      },
      {
        "value": "0x00004444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "None (no OBJECT_ATTRIBUTES, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x001F03FF",
        "additionalComment": "THREAD_ALL_ACCESS (realistic DesiredAccess)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to HANDLE ThreadHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct223": {
        "type": "INITIAL_TEB",
        "fields": [
          {
            "fieldName": "StackBase",
            "fieldType": "PVOID",
            "fieldValue": "0x0012F000",
            "fieldComment": "Top of stack"
          },
          {
            "fieldName": "StackLimit",
            "fieldType": "PVOID",
            "fieldValue": "0x0012C000",
            "fieldComment": "Bottom of stack"
          },
          {
            "fieldName": "StackCommit",
            "fieldType": "PVOID",
            "fieldValue": "0x0012D000",
            "fieldComment": "Committed stack"
          }
        ]
      },
      "struct224": {
        "type": "CONTEXT",
        "fields": [
          {
            "fieldName": "ContextFlags",
            "fieldType": "DWORD",
            "fieldValue": "0x00010007",
            "fieldComment": "CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS"
          },
          {
            "fieldName": "Eip",
            "fieldType": "DWORD",
            "fieldValue": "0x00402000",
            "fieldComment": "Instruction pointer"
          },
          {
            "fieldName": "Esp",
            "fieldType": "DWORD",
            "fieldValue": "0x0012FFA0",
            "fieldComment": "Stack pointer"
          }
        ]
      },
      "struct225": {
        "type": "CLIENT_ID",
        "fields": [
          {
            "fieldName": "UniqueProcess",
            "fieldType": "HANDLE",
            "fieldValue": "0x99995555",
            "fieldComment": "Dummy process identifier value"
          },
          {
            "fieldName": "UniqueThread",
            "fieldType": "HANDLE",
            "fieldValue": "0x00006666",
            "fieldComment": "Dummy thread identifier value"
          }
        ]
      }
    }
  },
  "NtDelayExecution": {
    "ntFunc": "NtDelayExecution",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to LARGE_INTEGER DelayInterval (dummy pointer, commonly negative for relative delay)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct226",
        "structureValueExpectations": "Negative value for relative delay in 100-nanosecond intervals.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Alertable = FALSE (wait is not alertable)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct226": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0xFFFFFFFFFFDCD650",
            "fieldComment": "Relative delay of -2,000,000 (200ms) in 100-nanosecond units"
          }
        ]
      }
    }
  },
  "NtImpersonateThread": {
    "ntFunc": "NtImpersonateThread",
    "pushes": [
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to SECURITY_QUALITY_OF_SERVICE (dummy pointer)",
        "structurePointer": "SECURITY_QUALITY_OF_SERVICE",
        "structureRef": "struct227",
        "structureValueExpectations": "Impersonation level, context tracking, effective only.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ThreadToImpersonate (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000333",
        "additionalComment": "HANDLE ThreadHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct227": {
        "type": "SECURITY_QUALITY_OF_SERVICE",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "ULONG",
            "fieldValue": "0x0000000C",
            "fieldComment": "Size of SECURITY_QUALITY_OF_SERVICE"
          },
          {
            "fieldName": "ImpersonationLevel",
            "fieldType": "SECURITY_IMPERSONATION_LEVEL",
            "fieldValue": "0x00000002",
            "fieldComment": "SecurityImpersonation"
          },
          {
            "fieldName": "ContextTrackingMode",
            "fieldType": "BOOLEAN",
            "fieldValue": "0x01",
            "fieldComment": "TRUE"
          },
          {
            "fieldName": "EffectiveOnly",
            "fieldType": "BOOLEAN",
            "fieldValue": "0x00",
            "fieldComment": "FALSE"
          }
        ]
      }
    }
  },
  "NtOpenThread": {
    "ntFunc": "NtOpenThread",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to CLIENT_ID (dummy pointer)",
        "structurePointer": "CLIENT_ID",
        "structureRef": "struct228",
        "structureValueExpectations": "UniqueProcess and UniqueThread identifiers.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct229",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x001F03FF",
        "additionalComment": "AccessMask (THREAD_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to HANDLE ThreadHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct228": {
        "type": "CLIENT_ID",
        "fields": [
          {
            "fieldName": "UniqueProcess",
            "fieldType": "HANDLE",
            "fieldValue": "0x99995555",
            "fieldComment": "Dummy process identifier value"
          },
          {
            "fieldName": "UniqueThread",
            "fieldType": "HANDLE",
            "fieldValue": "0x88887777",
            "fieldComment": "Dummy thread identifier value"
          }
        ]
      },
      "struct229": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (no object name)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtQueryInformationThread": {
    "ntFunc": "NtQueryInformationThread",
    "pushes": [
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000010"
      },
      {
        "value": "0x00000010",
        "additionalComment": "ThreadInformationLength (16 bytes, typical for THREAD_BASIC_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to THREAD_BASIC_INFORMATION (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": "Buffer for thread information structure.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ThreadInformationClass (ThreadBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000333",
        "additionalComment": "HANDLE ThreadHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtRegisterThreadTerminatePort": {
    "ntFunc": "NtRegisterThreadTerminatePort",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE PortHandle (None, no port registered)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtResumeThread": {
    "ntFunc": "NtResumeThread",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG SuspendCount (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000001"
      },
      {
        "value": "0x00004444",
        "additionalComment": "HANDLE ThreadHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetInformationThread": {
    "ntFunc": "NtSetInformationThread",
    "pushes": [
      {
        "value": "0x00000008",
        "additionalComment": "ULONG ThreadInformationLength (example: 8 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "PVOID ThreadInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000002"
      },
      {
        "value": "0x00000009",
        "additionalComment": "THREADINFOCLASS ThreadInformationClass (ThreadPriority)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00004444",
        "additionalComment": "HANDLE ThreadHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSuspendThread": {
    "ntFunc": "NtSuspendThread",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to ULONG PreviousSuspendCount (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00004444",
        "additionalComment": "HANDLE ThreadHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtTerminateThread": {
    "ntFunc": "NtTerminateThread",
    "pushes": [
      {
        "value": "0xC0000005",
        "additionalComment": "NTSTATUS ExitStatus (STATUS_ACCESS_VIOLATION example)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00004444",
        "additionalComment": "HANDLE ThreadHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtYieldExecution": {
    "ntFunc": "NtYieldExecution",
    "pushes": [],
    "structures": {}
  },
  "RtlCreateUserThread": {
    "ntFunc": "RtlCreateUserThread",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PCLIENT_ID ClientID (None, optional parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PHANDLE ThreadHandle (None, output parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID StartParameter (None, no parameter passed to thread start routine)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID StartAddress (None, invalid, but often set to a function pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PULONG StackCommit (None, use default stack commit size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PULONG StackReserved (None, use default stack reserve size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG StackZeroBits (0, use default stack zero bits)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN CreateSuspended (FALSE, thread starts immediately)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PSECURITY_DESCRIPTOR SecurityDescriptor (None, default security)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE ProcessHandle (None, invalid, should be a valid process handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCancelTimer": {
    "ntFunc": "NtCancelTimer",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PBOOLEAN CurrentState (None, optional output parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE TimerHandle (None, invalid, should be a valid timer handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtCreateTimer": {
    "ntFunc": "NtCreateTimer",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "TIMER_TYPE TimerType (NotificationTimer, default)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES ObjectAttributes (None, unnamed timer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00100000",
        "additionalComment": "ACCESS_MASK DesiredAccess (TIMER_ALL_ACCESS, sample value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "PHANDLE TimerHandle (dummy pointer, output parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtOpenTimer": {
    "ntFunc": "NtOpenTimer",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "POBJECT_ATTRIBUTES ObjectAttributes (None, unnamed timer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00100000",
        "additionalComment": "ACCESS_MASK DesiredAccess (TIMER_ALL_ACCESS, sample value)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "PHANDLE TimerHandle (dummy pointer, output parameter)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {}
  },
  "NtQueryTimer": {
    "ntFunc": "NtQueryTimer",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000020"
      },
      {
        "value": "0x00000018",
        "additionalComment": "TimerInformationLength (24 bytes, typical for TIMER_BASIC_INFORMATION)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to TIMER_BASIC_INFORMATION structure (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "TimerInformationClass (TimerBasicInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE TimerHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetTimer": {
    "ntFunc": "NtSetTimer",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to BOOLEAN PreviousState (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00"
      },
      {
        "value": "0x000003E8",
        "additionalComment": "Period (1000 ms, 1 second)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ResumeTimer (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "TimerContext (None, no context pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "TimerApcRoutine (None, no APC routine)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to LARGE_INTEGER DueTime (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct230",
        "structureValueExpectations": "Relative or absolute time in 100-nanosecond intervals.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE TimerHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct230": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0xfffff5e100000000",
            "fieldComment": "Relative time: -1 hour in 100-nanosecond intervals"
          }
        ]
      }
    }
  },
  "NtAdjustGroupsToken": {
    "ntFunc": "NtAdjustGroupsToken",
    "pushes": [
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to ULONG RequiredLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000030"
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to TOKEN_GROUPS PreviousGroups (dummy pointer)",
        "structurePointer": "TOKEN_GROUPS",
        "structureRef": "struct231",
        "structureValueExpectations": "Previous group membership information.",
        "pointedValue": None
      },
      {
        "value": "0x00000030",
        "additionalComment": "PreviousGroupsLength (48 bytes, enough for 2 groups)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to TOKEN_GROUPS TokenGroups (dummy pointer)",
        "structurePointer": "TOKEN_GROUPS",
        "structureRef": "struct232",
        "structureValueExpectations": "New group membership information.",
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ResetToDefault (FALSE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE TokenHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct231": {
        "type": "TOKEN_GROUPS",
        "fields": [
          {
            "fieldName": "GroupCount",
            "fieldType": "ULONG",
            "fieldValue": "0x00000002",
            "fieldComment": "Two groups"
          },
          {
            "fieldName": "Groups[0].Sid",
            "fieldType": "PSID",
            "fieldValue": "0xbadd0150",
            "fieldComment": "Pointer to SID (dummy pointer)"
          },
          {
            "fieldName": "Groups[0].Attributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000020",
            "fieldComment": "SE_GROUP_ENABLED"
          },
          {
            "fieldName": "Groups[1].Sid",
            "fieldType": "PSID",
            "fieldValue": "0xbadd0160",
            "fieldComment": "Pointer to SID (dummy pointer)"
          },
          {
            "fieldName": "Groups[1].Attributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000010",
            "fieldComment": "SE_GROUP_OWNER"
          }
        ]
      },
      "struct232": {
        "type": "TOKEN_GROUPS",
        "fields": [
          {
            "fieldName": "GroupCount",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "One group"
          },
          {
            "fieldName": "Groups[0].Sid",
            "fieldType": "PSID",
            "fieldValue": "0xbadd0170",
            "fieldComment": "Pointer to SID (dummy pointer)"
          },
          {
            "fieldName": "Groups[0].Attributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000020",
            "fieldComment": "SE_GROUP_ENABLED"
          }
        ]
      }
    }
  },
  "NtAdjustPrivilegesToken": {
    "ntFunc": "NtAdjustPrivilegesToken",
    "pushes": [
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to ULONG RequiredLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000018"
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to TOKEN_PRIVILEGES PreviousPrivileges (dummy pointer)",
        "structurePointer": "TOKEN_PRIVILEGES",
        "structureRef": "struct233",
        "structureValueExpectations": "Previous privilege state information.",
        "pointedValue": None
      },
      {
        "value": "0x00000018",
        "additionalComment": "PreviousPrivilegesLength (24 bytes, enough for 1 privilege)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to TOKEN_PRIVILEGES TokenPrivileges (dummy pointer)",
        "structurePointer": "TOKEN_PRIVILEGES",
        "structureRef": "struct234",
        "structureValueExpectations": "Privileges to adjust.",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "DisableAllPrivileges (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE TokenHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct233": {
        "type": "TOKEN_PRIVILEGES",
        "fields": [
          {
            "fieldName": "PrivilegeCount",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "One privilege"
          },
          {
            "fieldName": "Privileges[0].Luid.LowPart",
            "fieldType": "ULONG",
            "fieldValue": "0x00000017",
            "fieldComment": "SE_SHUTDOWN_PRIVILEGE"
          },
          {
            "fieldName": "Privileges[0].Luid.HighPart",
            "fieldType": "LONG",
            "fieldValue": "0x00000000",
            "fieldComment": "High part"
          },
          {
            "fieldName": "Privileges[0].Attributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000002",
            "fieldComment": "SE_PRIVILEGE_ENABLED"
          }
        ]
      },
      "struct234": {
        "type": "TOKEN_PRIVILEGES",
        "fields": [
          {
            "fieldName": "PrivilegeCount",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "One privilege"
          },
          {
            "fieldName": "Privileges[0].Luid.LowPart",
            "fieldType": "ULONG",
            "fieldValue": "0x00000012",
            "fieldComment": "SE_TCB_PRIVILEGE"
          },
          {
            "fieldName": "Privileges[0].Luid.HighPart",
            "fieldType": "LONG",
            "fieldValue": "0x00000000",
            "fieldComment": "High part"
          },
          {
            "fieldName": "Privileges[0].Attributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000002",
            "fieldComment": "SE_PRIVILEGE_ENABLED"
          }
        ]
      }
    }
  },
  "NtCreateToken": {
    "ntFunc": "NtCreateToken",
    "pushes": [
      {
        "value": "0xbadd00a0",
        "additionalComment": "Pointer to TOKEN_SOURCE (dummy pointer)",
        "structurePointer": "TOKEN_SOURCE",
        "structureRef": "struct235",
        "structureValueExpectations": "Source name and identifier.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to TOKEN_DEFAULT_DACL (dummy pointer)",
        "structurePointer": "TOKEN_DEFAULT_DACL",
        "structureRef": "struct236",
        "structureValueExpectations": "Default DACL for the token.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00c0",
        "additionalComment": "Pointer to TOKEN_PRIMARY_GROUP (dummy pointer)",
        "structurePointer": "TOKEN_PRIMARY_GROUP",
        "structureRef": "struct237",
        "structureValueExpectations": "Primary group SID.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00d0",
        "additionalComment": "Pointer to TOKEN_OWNER (dummy pointer)",
        "structurePointer": "TOKEN_OWNER",
        "structureRef": "struct238",
        "structureValueExpectations": "Owner SID.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00e0",
        "additionalComment": "Pointer to TOKEN_PRIVILEGES (dummy pointer)",
        "structurePointer": "TOKEN_PRIVILEGES",
        "structureRef": "struct239",
        "structureValueExpectations": "Privileges for the token.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00f0",
        "additionalComment": "Pointer to TOKEN_GROUPS (dummy pointer)",
        "structurePointer": "TOKEN_GROUPS",
        "structureRef": "struct240",
        "structureValueExpectations": "Group SIDs for the token.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0100",
        "additionalComment": "Pointer to TOKEN_USER (dummy pointer)",
        "structurePointer": "TOKEN_USER",
        "structureRef": "struct241",
        "structureValueExpectations": "User SID.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0110",
        "additionalComment": "Pointer to LARGE_INTEGER ExpirationTime (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct242",
        "structureValueExpectations": "Token expiration time.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0120",
        "additionalComment": "Pointer to LUID AuthenticationId (dummy pointer)",
        "structurePointer": "LUID",
        "structureRef": "struct243",
        "structureValueExpectations": "Authentication identifier.",
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "TokenType (TokenPrimary)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0130",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct244",
        "structureValueExpectations": "Token object attributes.",
        "pointedValue": None
      },
      {
        "value": "0x000F01FF",
        "additionalComment": "DesiredAccess (TOKEN_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0140",
        "additionalComment": "Pointer to HANDLE TokenHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      }
    ],
    "structures": {
      "struct235": {
        "type": "TOKEN_SOURCE",
        "fields": [
          {
            "fieldName": "SourceName",
            "fieldType": "CHAR[8]",
            "fieldValue": "0x4c6f676f6e616d65",
            "fieldComment": "'Logoname' (example)"
          },
          {
            "fieldName": "SourceIdentifier.LowPart",
            "fieldType": "ULONG",
            "fieldValue": "0x12345678",
            "fieldComment": "Low part"
          },
          {
            "fieldName": "SourceIdentifier.HighPart",
            "fieldType": "LONG",
            "fieldValue": "0x00000000",
            "fieldComment": "High part"
          }
        ]
      },
      "struct236": {
        "type": "TOKEN_DEFAULT_DACL",
        "fields": [
          {
            "fieldName": "DefaultDacl",
            "fieldType": "PACL",
            "fieldValue": "0xbadd0180",
            "fieldComment": "Pointer to ACL (dummy pointer)"
          }
        ]
      },
      "struct237": {
        "type": "TOKEN_PRIMARY_GROUP",
        "fields": [
          {
            "fieldName": "PrimaryGroup",
            "fieldType": "PSID",
            "fieldValue": "0xbadd0190",
            "fieldComment": "Pointer to SID (dummy pointer)"
          }
        ]
      },
      "struct238": {
        "type": "TOKEN_OWNER",
        "fields": [
          {
            "fieldName": "Owner",
            "fieldType": "PSID",
            "fieldValue": "0xbadd01a0",
            "fieldComment": "Pointer to SID (dummy pointer)"
          }
        ]
      },
      "struct239": {
        "type": "TOKEN_PRIVILEGES",
        "fields": [
          {
            "fieldName": "PrivilegeCount",
            "fieldType": "ULONG",
            "fieldValue": "0x00000002",
            "fieldComment": "Two privileges"
          },
          {
            "fieldName": "Privileges[0].Luid.LowPart",
            "fieldType": "ULONG",
            "fieldValue": "0x00000017",
            "fieldComment": "SE_SHUTDOWN_PRIVILEGE"
          },
          {
            "fieldName": "Privileges[0].Luid.HighPart",
            "fieldType": "LONG",
            "fieldValue": "0x00000000",
            "fieldComment": "High part"
          },
          {
            "fieldName": "Privileges[0].Attributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000002",
            "fieldComment": "SE_PRIVILEGE_ENABLED"
          },
          {
            "fieldName": "Privileges[1].Luid.LowPart",
            "fieldType": "ULONG",
            "fieldValue": "0x00000012",
            "fieldComment": "SE_TCB_PRIVILEGE"
          },
          {
            "fieldName": "Privileges[1].Luid.HighPart",
            "fieldType": "LONG",
            "fieldValue": "0x00000000",
            "fieldComment": "High part"
          },
          {
            "fieldName": "Privileges[1].Attributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000002",
            "fieldComment": "SE_PRIVILEGE_ENABLED"
          }
        ]
      },
      "struct240": {
        "type": "TOKEN_GROUPS",
        "fields": [
          {
            "fieldName": "GroupCount",
            "fieldType": "ULONG",
            "fieldValue": "0x00000001",
            "fieldComment": "One group"
          },
          {
            "fieldName": "Groups[0].Sid",
            "fieldType": "PSID",
            "fieldValue": "0xbadd01b0",
            "fieldComment": "Pointer to SID (dummy pointer)"
          },
          {
            "fieldName": "Groups[0].Attributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000020",
            "fieldComment": "SE_GROUP_ENABLED"
          }
        ]
      },
      "struct241": {
        "type": "TOKEN_USER",
        "fields": [
          {
            "fieldName": "User.Sid",
            "fieldType": "PSID",
            "fieldValue": "0xbadd01c0",
            "fieldComment": "Pointer to SID (dummy pointer)"
          },
          {
            "fieldName": "User.Attributes",
            "fieldType": "ULONG",
            "fieldValue": "0x00000020",
            "fieldComment": "SE_GROUP_ENABLED"
          }
        ]
      },
      "struct242": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x7fffffffffffffff",
            "fieldComment": "Maximum expiration time"
          }
        ]
      },
      "struct243": {
        "type": "LUID",
        "fields": [
          {
            "fieldName": "LowPart",
            "fieldType": "ULONG",
            "fieldValue": "0x0000abcd",
            "fieldComment": "Low part of LUID"
          },
          {
            "fieldName": "HighPart",
            "fieldType": "LONG",
            "fieldValue": "0x00000000",
            "fieldComment": "High part of LUID"
          }
        ]
      },
      "struct244": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtDuplicateToken": {
    "ntFunc": "NtDuplicateToken",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to HANDLE NewTokenHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "TokenType = TokenPrimary",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "EffectiveOnly = TRUE",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to OBJECT_ATTRIBUTES (dummy pointer, commonly None)",
        "structurePointer": "OBJECT_ATTRIBUTES",
        "structureRef": "struct245",
        "structureValueExpectations": "Length/size field; optional root directory handle; optional UNICODE_STRING object name pointer; attribute flags; optional security descriptor pointer; optional security quality of service pointer.",
        "pointedValue": None
      },
      {
        "value": "0x000F01FF",
        "additionalComment": "DesiredAccess = TOKEN_ALL_ACCESS",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ExistingTokenHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct245": {
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
            "fieldComment": "None"
          },
          {
            "fieldName": "ObjectName",
            "fieldType": "PUNICODE_STRING",
            "fieldValue": "0x00000000",
            "fieldComment": "None (no object name)"
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
            "fieldComment": "None"
          },
          {
            "fieldName": "SecurityQualityOfService",
            "fieldType": "PVOID",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          }
        ]
      }
    }
  },
  "NtOpenProcessToken": {
    "ntFunc": "NtOpenProcessToken",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to HANDLE TokenHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00020008",
        "additionalComment": "DesiredAccess = TOKEN_QUERY | TOKEN_DUPLICATE",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtOpenThreadToken": {
    "ntFunc": "NtOpenThreadToken",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to HANDLE TokenHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "OpenAsSelf = TRUE",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00020008",
        "additionalComment": "DesiredAccess = TOKEN_QUERY | TOKEN_DUPLICATE",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000555",
        "additionalComment": "HANDLE ThreadHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryInformationToken": {
    "ntFunc": "NtQueryInformationToken",
    "pushes": [
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000020"
      },
      {
        "value": "0x00000020",
        "additionalComment": "TokenInformationLength = 32 bytes",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to TokenInformation buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "TokenInformationClass = TokenUser",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000666",
        "additionalComment": "HANDLE TokenHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetInformationToken": {
    "ntFunc": "NtSetInformationToken",
    "pushes": [
      {
        "value": "0x00000020",
        "additionalComment": "TokenInformationLength = 32 bytes",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to TokenInformation buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000006",
        "additionalComment": "TokenInformationClass = TokenGroups",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000666",
        "additionalComment": "HANDLE TokenHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAccessCheckAndAuditAlarm": {
    "ntFunc": "NtAccessCheckAndAuditAlarm",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to BOOLEAN GenerateOnClose (dummy pointer, will receive TRUE/FALSE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to ULONG AccessStatus (dummy pointer, will receive access status)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to ULONG GrantedAccess (dummy pointer, will receive granted access mask)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "ObjectCreation = FALSE",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to GENERIC_MAPPING (dummy pointer)",
        "structurePointer": "GENERIC_MAPPING",
        "structureRef": "struct246",
        "structureValueExpectations": "GENERIC_READ/WRITE/EXECUTE/ALL mappings.",
        "pointedValue": None
      },
      {
        "value": "0x00120089",
        "additionalComment": "DesiredAccess (SYNCHRONIZE | READ_CONTROL | DELETE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to SECURITY_DESCRIPTOR (dummy pointer)",
        "structurePointer": "SECURITY_DESCRIPTOR",
        "structureRef": "struct247",
        "structureValueExpectations": "Owner, group, DACL, SACL fields.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to UNICODE_STRING ObjectName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct248",
        "structureValueExpectations": "Object name string.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to UNICODE_STRING ObjectTypeName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct249",
        "structureValueExpectations": "Object type name string.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ObjectHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to UNICODE_STRING SubsystemName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct250",
        "structureValueExpectations": "Subsystem name string.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct246": {
        "type": "GENERIC_MAPPING",
        "fields": [
          {
            "fieldName": "GenericRead",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x80000000",
            "fieldComment": "GENERIC_READ"
          },
          {
            "fieldName": "GenericWrite",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x40000000",
            "fieldComment": "GENERIC_WRITE"
          },
          {
            "fieldName": "GenericExecute",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x20000000",
            "fieldComment": "GENERIC_EXECUTE"
          },
          {
            "fieldName": "GenericAll",
            "fieldType": "ACCESS_MASK",
            "fieldValue": "0x10000000",
            "fieldComment": "GENERIC_ALL"
          }
        ]
      },
      "struct247": {
        "type": "SECURITY_DESCRIPTOR",
        "fields": [
          {
            "fieldName": "Revision",
            "fieldType": "UCHAR",
            "fieldValue": "0x01",
            "fieldComment": "SECURITY_DESCRIPTOR_REVISION"
          },
          {
            "fieldName": "Sbz1",
            "fieldType": "UCHAR",
            "fieldValue": "0x00",
            "fieldComment": "Reserved"
          },
          {
            "fieldName": "Control",
            "fieldType": "USHORT",
            "fieldValue": "0x8004",
            "fieldComment": "SE_DACL_PRESENT | SE_SELF_RELATIVE"
          },
          {
            "fieldName": "Owner",
            "fieldType": "PSID",
            "fieldValue": "0xbadd0130",
            "fieldComment": "Pointer to SID (dummy pointer)"
          },
          {
            "fieldName": "Group",
            "fieldType": "PSID",
            "fieldValue": "0xbadd0140",
            "fieldComment": "Pointer to SID (dummy pointer)"
          },
          {
            "fieldName": "Sacl",
            "fieldType": "PACL",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          },
          {
            "fieldName": "Dacl",
            "fieldType": "PACL",
            "fieldValue": "0xbadd0150",
            "fieldComment": "Pointer to ACL (dummy pointer)"
          }
        ]
      },
      "struct248": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "16 bytes (8 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "32 bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0160",
            "fieldComment": "Pointer to object name string (dummy pointer)"
          }
        ]
      },
      "struct249": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0012",
            "fieldComment": "18 bytes (9 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "32 bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0170",
            "fieldComment": "Pointer to object type name string (dummy pointer)"
          }
        ]
      },
      "struct250": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0014",
            "fieldComment": "20 bytes (10 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "32 bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0180",
            "fieldComment": "Pointer to subsystem name string (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtCloseObjectAuditAlarm": {
    "ntFunc": "NtCloseObjectAuditAlarm",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "GenerateOnClose = TRUE",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ObjectHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to UNICODE_STRING SubsystemName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct251",
        "structureValueExpectations": "Subsystem name string.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct251": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0014",
            "fieldComment": "20 bytes (10 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "32 bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0190",
            "fieldComment": "Pointer to subsystem name string (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtDeleteObjectAuditAlarm": {
    "ntFunc": "NtDeleteObjectAuditAlarm",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "GenerateOnClose = FALSE",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ObjectHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to UNICODE_STRING SubsystemName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct252",
        "structureValueExpectations": "Subsystem name string.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct252": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0014",
            "fieldComment": "20 bytes (10 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "32 bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd01a0",
            "fieldComment": "Pointer to subsystem name string (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtOpenObjectAuditAlarm": {
    "ntFunc": "NtOpenObjectAuditAlarm",
    "pushes": [
      {
        "value": "0xbadd00a0",
        "additionalComment": "Pointer to BOOLEAN GenerateOnClose (dummy pointer, will receive TRUE/FALSE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000001",
        "additionalComment": "AccessGranted = TRUE",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ObjectCreation = FALSE",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00b0",
        "additionalComment": "Pointer to PRIVILEGE_SET (dummy pointer)",
        "structurePointer": "PRIVILEGE_SET",
        "structureRef": "struct253",
        "structureValueExpectations": "Privilege count and LUID_AND_ATTRIBUTES array.",
        "pointedValue": None
      },
      {
        "value": "0x00120089",
        "additionalComment": "GrantedAccess (SYNCHRONIZE | READ_CONTROL | DELETE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00120089",
        "additionalComment": "DesiredAccess (SYNCHRONIZE | READ_CONTROL | DELETE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000445",
        "additionalComment": "HANDLE ClientToken (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd00c0",
        "additionalComment": "Pointer to SECURITY_DESCRIPTOR (dummy pointer)",
        "structurePointer": "SECURITY_DESCRIPTOR",
        "structureRef": "struct254",
        "structureValueExpectations": "Owner, group, DACL, SACL fields.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00d0",
        "additionalComment": "Pointer to UNICODE_STRING ObjectName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct255",
        "structureValueExpectations": "Object name string.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00e0",
        "additionalComment": "Pointer to UNICODE_STRING ObjectTypeName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct256",
        "structureValueExpectations": "Object type name string.",
        "pointedValue": None
      },
      {
        "value": "0xbadd00f0",
        "additionalComment": "Pointer to HANDLE ObjectHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0100",
        "additionalComment": "Pointer to UNICODE_STRING SubsystemName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct257",
        "structureValueExpectations": "Subsystem name string.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct253": {
        "type": "PRIVILEGE_SET",
        "fields": [
          {
            "fieldName": "PrivilegeCount",
            "fieldType": "DWORD",
            "fieldValue": "0x00000001",
            "fieldComment": "One privilege"
          },
          {
            "fieldName": "Control",
            "fieldType": "DWORD",
            "fieldValue": "0x00000001",
            "fieldComment": "PRIVILEGE_SET_ALL_NECESSARY"
          },
          {
            "fieldName": "Privilege[0].Luid.LowPart",
            "fieldType": "DWORD",
            "fieldValue": "0x00000017",
            "fieldComment": "SE_TCB_PRIVILEGE (example)"
          },
          {
            "fieldName": "Privilege[0].Luid.HighPart",
            "fieldType": "LONG",
            "fieldValue": "0x00000000",
            "fieldComment": "High part of LUID"
          },
          {
            "fieldName": "Privilege[0].Attributes",
            "fieldType": "DWORD",
            "fieldValue": "0x00000002",
            "fieldComment": "SE_PRIVILEGE_ENABLED"
          }
        ]
      },
      "struct254": {
        "type": "SECURITY_DESCRIPTOR",
        "fields": [
          {
            "fieldName": "Revision",
            "fieldType": "UCHAR",
            "fieldValue": "0x01",
            "fieldComment": "SECURITY_DESCRIPTOR_REVISION"
          },
          {
            "fieldName": "Sbz1",
            "fieldType": "UCHAR",
            "fieldValue": "0x00",
            "fieldComment": "Reserved"
          },
          {
            "fieldName": "Control",
            "fieldType": "USHORT",
            "fieldValue": "0x8004",
            "fieldComment": "SE_DACL_PRESENT | SE_SELF_RELATIVE"
          },
          {
            "fieldName": "Owner",
            "fieldType": "PSID",
            "fieldValue": "0xbadd01b0",
            "fieldComment": "Pointer to SID (dummy pointer)"
          },
          {
            "fieldName": "Group",
            "fieldType": "PSID",
            "fieldValue": "0xbadd01c0",
            "fieldComment": "Pointer to SID (dummy pointer)"
          },
          {
            "fieldName": "Sacl",
            "fieldType": "PACL",
            "fieldValue": "0x00000000",
            "fieldComment": "None"
          },
          {
            "fieldName": "Dacl",
            "fieldType": "PACL",
            "fieldValue": "0xbadd01d0",
            "fieldComment": "Pointer to ACL (dummy pointer)"
          }
        ]
      },
      "struct255": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0010",
            "fieldComment": "16 bytes (8 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "32 bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd01e0",
            "fieldComment": "Pointer to object name string (dummy pointer)"
          }
        ]
      },
      "struct256": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0012",
            "fieldComment": "18 bytes (9 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "32 bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd01f0",
            "fieldComment": "Pointer to object type name string (dummy pointer)"
          }
        ]
      },
      "struct257": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0014",
            "fieldComment": "20 bytes (10 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "32 bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0200",
            "fieldComment": "Pointer to subsystem name string (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtPrivilegeObjectAuditAlarm": {
    "ntFunc": "NtPrivilegeObjectAuditAlarm",
    "pushes": [
      {
        "value": "0x00000001",
        "additionalComment": "AccessGranted = TRUE",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0110",
        "additionalComment": "Pointer to PRIVILEGE_SET ClientPrivileges (dummy pointer)",
        "structurePointer": "PRIVILEGE_SET",
        "structureRef": "struct258",
        "structureValueExpectations": "Privilege count and LUID_AND_ATTRIBUTES array.",
        "pointedValue": None
      },
      {
        "value": "0x00120089",
        "additionalComment": "DesiredAccess (SYNCHRONIZE | READ_CONTROL | DELETE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000445",
        "additionalComment": "HANDLE ClientToken (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ObjectHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0120",
        "additionalComment": "Pointer to UNICODE_STRING SubsystemName (dummy pointer)",
        "structurePointer": "UNICODE_STRING",
        "structureRef": "struct259",
        "structureValueExpectations": "Subsystem name string.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct258": {
        "type": "PRIVILEGE_SET",
        "fields": [
          {
            "fieldName": "PrivilegeCount",
            "fieldType": "DWORD",
            "fieldValue": "0x00000001",
            "fieldComment": "One privilege"
          },
          {
            "fieldName": "Control",
            "fieldType": "DWORD",
            "fieldValue": "0x00000001",
            "fieldComment": "PRIVILEGE_SET_ALL_NECESSARY"
          },
          {
            "fieldName": "Privilege[0].Luid.LowPart",
            "fieldType": "DWORD",
            "fieldValue": "0x00000017",
            "fieldComment": "SE_TCB_PRIVILEGE (example)"
          },
          {
            "fieldName": "Privilege[0].Luid.HighPart",
            "fieldType": "LONG",
            "fieldValue": "0x00000000",
            "fieldComment": "High part of LUID"
          },
          {
            "fieldName": "Privilege[0].Attributes",
            "fieldType": "DWORD",
            "fieldValue": "0x00000002",
            "fieldComment": "SE_PRIVILEGE_ENABLED"
          }
        ]
      },
      "struct259": {
        "type": "UNICODE_STRING",
        "fields": [
          {
            "fieldName": "Length",
            "fieldType": "USHORT",
            "fieldValue": "0x0014",
            "fieldComment": "20 bytes (10 UTF-16 chars)"
          },
          {
            "fieldName": "MaximumLength",
            "fieldType": "USHORT",
            "fieldValue": "0x0020",
            "fieldComment": "32 bytes"
          },
          {
            "fieldName": "Buffer",
            "fieldType": "PWSTR",
            "fieldValue": "0xbadd0210",
            "fieldComment": "Pointer to subsystem name string (dummy pointer)"
          }
        ]
      }
    }
  },
  "NtPrivilegedServiceAuditAlarm": {
    "ntFunc": "NtPrivilegedServiceAuditAlarm",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "AccessGranted = FALSE",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ClientPrivileges = None (no privileges specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ClientToken = None (no client token)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ServiceName = None (no service name)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "SubsystemName = None (no subsystem name)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAccessCheck": {
    "ntFunc": "NtAccessCheck",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "AccessStatus = None (no status output)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "GrantedAccess = None (no granted access output)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "BufferLength = None (no buffer length output)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "RequiredPrivilegesBuffer = None (no privileges buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "GenericMapping = None (no generic mapping provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "DesiredAccess = 0x00000000 (no access requested)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ClientToken = None (no client token)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "SecurityDescriptor = None (no security descriptor)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAllocateLocallyUniqueId": {
    "ntFunc": "NtAllocateLocallyUniqueId",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "LocallyUniqueId = None (no output buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtAllocateUuids": {
    "ntFunc": "NtAllocateUuids",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Sequence = None (no output buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Range = None (no output buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "Time = None (no output buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtPrivilegeCheck": {
    "ntFunc": "NtPrivilegeCheck",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "Result = None (no output buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "RequiredPrivileges = None (no privileges specified)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ClientToken = None (no client token)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQuerySystemInformation": {
    "ntFunc": "NtQuerySystemInformation",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG ReturnLength (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00001000"
      },
      {
        "value": "0x00001000",
        "additionalComment": "SystemInformationLength (4096 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to buffer for SystemInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0020"
      },
      {
        "value": "0x00000005",
        "additionalComment": "SystemInformationClass (SystemProcessInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtSetSystemInformation": {
    "ntFunc": "NtSetSystemInformation",
    "pushes": [
      {
        "value": "0x00000010",
        "additionalComment": "SystemInformationLength (16 bytes)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to buffer for SystemInformation (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xbadd0040"
      },
      {
        "value": "0x00000011",
        "additionalComment": "SystemInformationClass (SystemTimeAdjustmentInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtGetTickCount": {
    "ntFunc": "NtGetTickCount",
    "pushes": [],
    "structures": {}
  },
  "NtQueryPerformanceCounter": {
    "ntFunc": "NtQueryPerformanceCounter",
    "pushes": [
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to LARGE_INTEGER PerformanceFrequency (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct260",
        "structureValueExpectations": "Frequency of the high-resolution performance counter.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to LARGE_INTEGER PerformanceCounter (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct261",
        "structureValueExpectations": "Current value of the high-resolution performance counter.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct260": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x989680",
            "fieldComment": "Performance frequency (1,000,000 Hz typical)"
          }
        ]
      },
      "struct261": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x123456789ABCDEF0",
            "fieldComment": "Sample performance counter value"
          }
        ]
      }
    }
  },
  "NtQuerySystemTime": {
    "ntFunc": "NtQuerySystemTime",
    "pushes": [
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to LARGE_INTEGER SystemTime (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct262",
        "structureValueExpectations": "Current system time as a 64-bit value (100-nanosecond intervals since Jan 1, 1601 UTC).",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct262": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x01D9F1E2B3C4D5E6",
            "fieldComment": "Sample system time value"
          }
        ]
      }
    }
  },
  "NtQueryTimerResolution": {
    "ntFunc": "NtQueryTimerResolution",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to ULONG CurrentResolution (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x000003E8"
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to ULONG MaximumResolution (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00002710"
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to ULONG MinimumResolution (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000064"
      }
    ],
    "structures": {}
  },
  "NtSetSystemTime": {
    "ntFunc": "NtSetSystemTime",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to LARGE_INTEGER PreviousTime (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct263",
        "structureValueExpectations": "Previous system time value (optional, can be None).",
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to LARGE_INTEGER SystemTime (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct264",
        "structureValueExpectations": "New system time value to set.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct263": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000000000000",
            "fieldComment": "Previous system time (None/unused in this example)"
          }
        ]
      },
      "struct264": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x01D9A5B1C0000000",
            "fieldComment": "New system time (FILETIME format, e.g., 2024-06-01 00:00:00 UTC)"
          }
        ]
      }
    }
  },
  "NtSetTimerResolution": {
    "ntFunc": "NtSetTimerResolution",
    "pushes": [
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to ULONG CurrentResolution (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x000003E8"
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN SetResolution (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x000003E8",
        "additionalComment": "ULONG DesiredResolution (1000, in 100-ns units)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "RtlTimeFieldsToTime": {
    "ntFunc": "RtlTimeFieldsToTime",
    "pushes": [
      {
        "value": "0xbadd0060",
        "additionalComment": "Pointer to LARGE_INTEGER Time (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct265",
        "structureValueExpectations": "Receives the converted time value.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0070",
        "additionalComment": "Pointer to TIME_FIELDS (dummy pointer)",
        "structurePointer": "TIME_FIELDS",
        "structureRef": "struct266",
        "structureValueExpectations": "Fields representing date and time.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct265": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x0000000000000000",
            "fieldComment": "Receives the converted time value"
          }
        ]
      },
      "struct266": {
        "type": "TIME_FIELDS",
        "fields": [
          {
            "fieldName": "Year",
            "fieldType": "USHORT",
            "fieldValue": "0x07E8",
            "fieldComment": "2024"
          },
          {
            "fieldName": "Month",
            "fieldType": "USHORT",
            "fieldValue": "0x06",
            "fieldComment": "June"
          },
          {
            "fieldName": "Day",
            "fieldType": "USHORT",
            "fieldValue": "0x01",
            "fieldComment": "1st"
          },
          {
            "fieldName": "Hour",
            "fieldType": "USHORT",
            "fieldValue": "0x00",
            "fieldComment": "Midnight"
          },
          {
            "fieldName": "Minute",
            "fieldType": "USHORT",
            "fieldValue": "0x00",
            "fieldComment": "00"
          },
          {
            "fieldName": "Second",
            "fieldType": "USHORT",
            "fieldValue": "0x00",
            "fieldComment": "00"
          },
          {
            "fieldName": "Milliseconds",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "0"
          },
          {
            "fieldName": "Weekday",
            "fieldType": "USHORT",
            "fieldValue": "0x06",
            "fieldComment": "Saturday"
          }
        ]
      }
    }
  },
  "RtlTimeToTimeFields": {
    "ntFunc": "RtlTimeToTimeFields",
    "pushes": [
      {
        "value": "0xbadd0080",
        "additionalComment": "Pointer to TIME_FIELDS (dummy pointer)",
        "structurePointer": "TIME_FIELDS",
        "structureRef": "struct267",
        "structureValueExpectations": "Receives the broken-down time fields.",
        "pointedValue": None
      },
      {
        "value": "0xbadd0090",
        "additionalComment": "Pointer to LARGE_INTEGER Time (dummy pointer)",
        "structurePointer": "LARGE_INTEGER",
        "structureRef": "struct268",
        "structureValueExpectations": "Time value to convert.",
        "pointedValue": None
      }
    ],
    "structures": {
      "struct267": {
        "type": "TIME_FIELDS",
        "fields": [
          {
            "fieldName": "Year",
            "fieldType": "USHORT",
            "fieldValue": "0x07E8",
            "fieldComment": "2024"
          },
          {
            "fieldName": "Month",
            "fieldType": "USHORT",
            "fieldValue": "0x06",
            "fieldComment": "June"
          },
          {
            "fieldName": "Day",
            "fieldType": "USHORT",
            "fieldValue": "0x01",
            "fieldComment": "1st"
          },
          {
            "fieldName": "Hour",
            "fieldType": "USHORT",
            "fieldValue": "0x00",
            "fieldComment": "Midnight"
          },
          {
            "fieldName": "Minute",
            "fieldType": "USHORT",
            "fieldValue": "0x00",
            "fieldComment": "00"
          },
          {
            "fieldName": "Second",
            "fieldType": "USHORT",
            "fieldValue": "0x00",
            "fieldComment": "00"
          },
          {
            "fieldName": "Milliseconds",
            "fieldType": "USHORT",
            "fieldValue": "0x0000",
            "fieldComment": "0"
          },
          {
            "fieldName": "Weekday",
            "fieldType": "USHORT",
            "fieldValue": "0x06",
            "fieldComment": "Saturday"
          }
        ]
      },
      "struct268": {
        "type": "LARGE_INTEGER",
        "fields": [
          {
            "fieldName": "QuadPart",
            "fieldType": "LONGLONG",
            "fieldValue": "0x01D9A5B1C0000000",
            "fieldComment": "Time value to convert (FILETIME format, e.g., 2024-06-01 00:00:00 UTC)"
          }
        ]
      }
    }
  },
  "NtClose": {
    "ntFunc": "NtClose",
    "pushes": [
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE Handle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtFlushBuffersFileEx": {
    "ntFunc": "NtFlushBuffersFileEx",
    "pushes": [
      {
        "value": "0xbadd0000",
        "additionalComment": "Pointer to IO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000010",
        "additionalComment": "ULONG ParametersSize (16 bytes, typical for FSCTLs)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "Pointer to Parameters buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0xdeadbeef"
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG Flags (example: FLUSH_FLAGS_FILE_DATA_ONLY)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000888",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtOpenProcessTokenEx": {
    "ntFunc": "NtOpenProcessTokenEx",
    "pushes": [
      {
        "value": "0xbadd0020",
        "additionalComment": "Pointer to HANDLE TokenHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000040",
        "additionalComment": "ULONG HandleAttributes (OBJ_CASE_INSENSITIVE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x000F01FF",
        "additionalComment": "ACCESS_MASK DesiredAccess (TOKEN_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE ProcessHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtOpenThreadTokenEx": {
    "ntFunc": "NtOpenThreadTokenEx",
    "pushes": [
      {
        "value": "0xbadd0030",
        "additionalComment": "Pointer to HANDLE TokenHandle (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000040",
        "additionalComment": "ULONG HandleAttributes (OBJ_CASE_INSENSITIVE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "BOOLEAN OpenAsSelf (TRUE)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x000F01FF",
        "additionalComment": "ACCESS_MASK DesiredAccess (TOKEN_ALL_ACCESS)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00005555",
        "additionalComment": "HANDLE ThreadHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryDirectoryFileEx": {
    "ntFunc": "NtQueryDirectoryFileEx",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "PUNICODE_STRING FileName (None, query all entries)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000001",
        "additionalComment": "ULONG QueryFlags (SL_RESTART_SCAN)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000005",
        "additionalComment": "FILE_INFORMATION_CLASS FileInformationClass (FileDirectoryInformation)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG Length (4096 bytes buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0040",
        "additionalComment": "Pointer to FileInformation buffer (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0xbadd0050",
        "additionalComment": "Pointer to IO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": "0x00000000"
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID ApcContext (None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PIO_APC_ROUTINE ApcRoutine (None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "HANDLE Event (None)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000888",
        "additionalComment": "HANDLE FileHandle (dummy handle)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {}
  },
  "NtQueryQuotaInformationFile": {
    "ntFunc": "NtQueryQuotaInformationFile",
    "pushes": [
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN RestartScan (FALSE, typical for initial call)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PSID StartSid (None, enumerate all SIDs)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "ULONG SidListLength (0, no SID list provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "PVOID SidList (None, no SID list provided)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00000000",
        "additionalComment": "BOOLEAN ReturnSingleEntry (FALSE, return all entries)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0x00001000",
        "additionalComment": "ULONG Length (4096 bytes, typical buffer size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0000",
        "additionalComment": "PVOID Buffer (dummy pointer to output buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0010",
        "additionalComment": "PIO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct269",
        "structureValueExpectations": "Status and information fields for I/O result.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE FileHandle (dummy handle to open file)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct269": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "STATUS_SUCCESS (initial value)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Number of bytes transferred (initial value)"
          }
        ]
      }
    }
  },
  "NtSetQuotaInformationFile": {
    "ntFunc": "NtSetQuotaInformationFile",
    "pushes": [
      {
        "value": "0x00000020",
        "additionalComment": "ULONG Length (32 bytes, typical quota info size)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0020",
        "additionalComment": "PVOID Buffer (dummy pointer to quota info buffer)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      },
      {
        "value": "0xbadd0030",
        "additionalComment": "PIO_STATUS_BLOCK IoStatusBlock (dummy pointer)",
        "structurePointer": "IO_STATUS_BLOCK",
        "structureRef": "struct270",
        "structureValueExpectations": "Status and information fields for I/O result.",
        "pointedValue": None
      },
      {
        "value": "0x00000444",
        "additionalComment": "HANDLE FileHandle (dummy handle to open file)",
        "structurePointer": None,
        "structureRef": None,
        "structureValueExpectations": None,
        "pointedValue": None
      }
    ],
    "structures": {
      "struct270": {
        "type": "IO_STATUS_BLOCK",
        "fields": [
          {
            "fieldName": "Status",
            "fieldType": "NTSTATUS",
            "fieldValue": "0x00000000",
            "fieldComment": "STATUS_SUCCESS (initial value)"
          },
          {
            "fieldName": "Information",
            "fieldType": "ULONG_PTR",
            "fieldValue": "0x00000000",
            "fieldComment": "Number of bytes transferred (initial value)"
          }
        ]
      }
    }
  }
}

# print (syscallPossibleValues["NtAllocateVirtualMemory"])