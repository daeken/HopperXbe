//
//  XbeLoader.m
//  XbeLoader
//
//  Created by Vincent Bénony on 03/03/2014.
//  Copyright (c) 2014 Cryptic Apps. All rights reserved.
//

#import "XbeLoader.h"

@implementation XbeLoader {
    NSObject<HPHopperServices> *_services;
}

- (instancetype)initWithHopperServices:(NSObject<HPHopperServices> *)services {
    if (self = [super init]) {
        _services = services;
    }
    return self;
}

- (HopperUUID *)pluginUUID {
    return [_services UUIDWithString:@"6e1f7209-fb34-4c3f-96cd-6d4eb44beb34"];
}

- (HopperPluginType)pluginType {
    return Plugin_Loader;
}

- (NSString *)pluginName {
    return @"XBE";
}

- (NSString *)pluginDescription {
    return @"XBE File Loader";
}

- (NSString *)pluginAuthor {
    return @"Cody Brocious";
}

- (NSString *)pluginCopyright {
    return @"©2015 - Cody Brocious";
}

- (NSString *)pluginVersion {
    return @"0.0.1";
}

- (CPUEndianess)endianess {
    return CPUEndianess_Little;
}

- (BOOL)canLoadDebugFiles {
    return NO;
}

// Returns an array of DetectedFileType objects.
- (NSArray *)detectedTypesForData:(NSData *)data {
    if ([data length] < 4) return @[];

    const void *bytes = (const void *)[data bytes];
    if (OSReadLittleInt32(bytes, 0) == 0x48454258) { // XBEH
        NSObject<HPDetectedFileType> *type = [_services detectedType];
        [type setFileDescription:@"XBE"];
        [type setAddressWidth:AW_32bits];
        [type setCpuFamily:@"intel"];
        [type setCpuSubFamily:@"x86"];
        [type setShortDescriptionString:@"XBE"];
        return @[type];
    }

    return @[];
}

static NSString *imports[] = {
    @"AvGetSavedDataAddress",
    @"AvSendTVEncoderOption",
    @"AvSetDisplayMode",
    @"AvSetSavedDataAddress",
    @"DbgBreakPoint",
    @"DbgBreakPointWithStatus",
    @"DbgLoadImageSymbols",
    @"DbgPrint",
    @"HalReadSMCTrayState",
    @"DbgPrompt",
    @"DbgUnLoadImageSymbols",
    @"ExAcquireReadWriteLockExclusive",
    @"ExAcquireReadWriteLockShared",
    @"ExAllocatePool",
    @"ExAllocatePoolWithTag",
    @"ExEventObjectType",
    @"ExFreePool",
    @"ExInitializeReadWriteLock",
    @"ExInterlockedAddLargeInteger",
    @"ExInterlockedAddLargeStatistic",
    @"ExInterlockedCompareExchange64",
    @"ExMutantObjectType",
    @"ExQueryPoolBlockSize",
    @"ExQueryNonVolatileSetting",
    @"ExReadWriteRefurbInfo",
    @"ExRaiseException",
    @"ExRaiseStatus",
    @"ExReleaseReadWriteLock",
    @"ExSaveNonVolatileSetting",
    @"ExSemaphoreObjectType",
    @"ExTimerObjectType",
    @"ExfInterlockedInsertHeadList",
    @"ExfInterlockedInsertTailList",
    @"ExfInterlockedRemoveHeadList",
    @"FscGetCacheSize",
    @"FscInvalidateIdleBlocks",
    @"FscSetCacheSize",
    @"HalClearSoftwareInterrupt",
    @"HalDisableSystemInterrupt",
    @"HalDiskCachePartitionCount",
    @"HalDiskModelNumber",
    @"HalDiskSerialNumber",
    @"HalEnableSystemInterrupt",
    @"HalGetInterruptVector",
    @"HalReadSMBusValue",
    @"HalReadWritePCISpace",
    @"HalRegisterShutdownNotification",
    @"HalRequestSoftwareInterrupt",
    @"HalReturnToFirmware",
    @"HalWriteSMBusValue",
    @"InterlockedCompareExchange",
    @"InterlockedDecrement",
    @"InterlockedIncrement",
    @"InterlockedExchange",
    @"InterlockedExchangeAdd",
    @"InterlockedFlushSList",
    @"InterlockedPopEntrySList",
    @"InterlockedPushEntrySList",
    @"IoAllocateIrp",
    @"IoBuildAsynchronousFsdRequest",
    @"IoBuildDeviceIoControlRequest",
    @"IoBuildSynchronousFsdRequest",
    @"IoCheckShareAccess",
    @"IoCompletionObjectType",
    @"IoCreateDevice",
    @"IoCreateFile",
    @"IoCreateSymbolicLink",
    @"IoDeleteDevice",
    @"IoDeleteSymbolicLink",
    @"IoDeviceObjectType",
    @"IoFileObjectType",
    @"IoFreeIrp",
    @"IoInitializeIrp",
    @"IoInvalidDeviceRequest",
    @"IoQueryFileInformation",
    @"IoQueryVolumeInformation",
    @"IoQueueThreadIrp",
    @"IoRemoveShareAccess",
    @"IoSetIoCompletion",
    @"IoSetShareAccess",
    @"IoStartNextPacket",
    @"IoStartNextPacketByKey",
    @"IoStartPacket",
    @"IoSynchronousDeviceIoControlRequest",
    @"IoSynchronousFsdRequest",
    @"IofCallDriver",
    @"IofCompleteRequest",
    @"KdDebuggerEnabled",
    @"KdDebuggerNotPresent",
    @"IoDismountVolume",
    @"IoDismountVolumeByName",
    @"KeAlertResumeThread",
    @"KeAlertThread",
    @"KeBoostPriorityThread",
    @"KeBugCheck",
    @"KeBugCheckEx",
    @"KeCancelTimer",
    @"KeConnectInterrupt",
    @"KeDelayExecutionThread",
    @"KeDisconnectInterrupt",
    @"KeEnterCriticalRegion",
    @"MmGlobalData",
    @"KeGetCurrentIrql",
    @"KeGetCurrentThread",
    @"KeInitializeApc",
    @"KeInitializeDeviceQueue",
    @"KeInitializeDpc",
    @"KeInitializeEvent",
    @"KeInitializeInterrupt",
    @"KeInitializeMutant",
    @"KeInitializeQueue",
    @"KeInitializeSemaphore",
    @"KeInitializeTimerEx",
    @"KeInsertByKeyDeviceQueue",
    @"KeInsertDeviceQueue",
    @"KeInsertHeadQueue",
    @"KeInsertQueue",
    @"KeInsertQueueApc",
    @"KeInsertQueueDpc",
    @"KeInterruptTime",
    @"KeIsExecutingDpc",
    @"KeLeaveCriticalRegion",
    @"KePulseEvent",
    @"KeQueryBasePriorityThread",
    @"KeQueryInterruptTime",
    @"KeQueryPerformanceCounter",
    @"KeQueryPerformanceFrequency",
    @"KeQuerySystemTime",
    @"KeRaiseIrqlToDpcLevel",
    @"KeRaiseIrqlToSynchLevel",
    @"KeReleaseMutant",
    @"KeReleaseSemaphore",
    @"KeRemoveByKeyDeviceQueue",
    @"KeRemoveDeviceQueue",
    @"KeRemoveEntryDeviceQueue",
    @"KeRemoveQueue",
    @"KeRemoveQueueDpc",
    @"KeResetEvent",
    @"KeRestoreFloatingPointState",
    @"KeResumeThread",
    @"KeRundownQueue",
    @"KeSaveFloatingPointState",
    @"KeSetBasePriorityThread",
    @"KeSetDisableBoostThread",
    @"KeSetEvent",
    @"KeSetEventBoostPriority",
    @"KeSetPriorityProcess",
    @"KeSetPriorityThread",
    @"KeSetTimer",
    @"KeSetTimerEx",
    @"KeStallExecutionProcessor",
    @"KeSuspendThread",
    @"KeSynchronizeExecution",
    @"KeSystemTime",
    @"KeTestAlertThread",
    @"KeTickCount",
    @"KeTimeIncrement",
    @"KeWaitForMultipleObjects",
    @"KeWaitForSingleObject",
    @"KfRaiseIrql",
    @"KfLowerIrql",
    @"KiBugCheckData",
    @"KiUnlockDispatcherDatabase",
    @"LaunchDataPage",
    @"MmAllocateContiguousMemory",
    @"MmAllocateContiguousMemoryEx",
    @"MmAllocateSystemMemory",
    @"MmClaimGpuInstanceMemory",
    @"MmCreateKernelStack",
    @"MmDeleteKernelStack",
    @"MmFreeContiguousMemory",
    @"MmFreeSystemMemory",
    @"MmGetPhysicalAddress",
    @"MmIsAddressValid",
    @"MmLockUnlockBufferPages",
    @"MmLockUnlockPhysicalPage",
    @"MmMapIoSpace",
    @"MmPersistContiguousMemory",
    @"MmQueryAddressProtect",
    @"MmQueryAllocationSize",
    @"MmQueryStatistics",
    @"MmSetAddressProtect",
    @"MmUnmapIoSpace",
    @"NtAllocateVirtualMemory",
    @"NtCancelTimer",
    @"NtClearEvent",
    @"NtClose",
    @"NtCreateDirectoryObject",
    @"NtCreateEvent",
    @"NtCreateFile",
    @"NtCreateIoCompletion",
    @"NtCreateMutant",
    @"NtCreateSemaphore",
    @"NtCreateTimer",
    @"NtDeleteFile",
    @"NtDeviceIoControlFile",
    @"NtDuplicateObject",
    @"NtFlushBuffersFile",
    @"NtFreeVirtualMemory",
    @"NtFsControlFile",
    @"NtOpenDirectoryObject",
    @"NtOpenFile",
    @"NtOpenSymbolicLinkObject",
    @"NtProtectVirtualMemory",
    @"NtPulseEvent",
    @"NtQueueApcThread",
    @"NtQueryDirectoryFile",
    @"NtQueryDirectoryObject",
    @"NtQueryEvent",
    @"NtQueryFullAttributesFile",
    @"NtQueryInformationFile",
    @"NtQueryIoCompletion",
    @"NtQueryMutant",
    @"NtQuerySemaphore",
    @"NtQuerySymbolicLinkObject",
    @"NtQueryTimer",
    @"NtQueryVirtualMemory",
    @"NtQueryVolumeInformationFile",
    @"NtReadFile",
    @"NtReadFileScatter",
    @"NtReleaseMutant",
    @"NtReleaseSemaphore",
    @"NtRemoveIoCompletion",
    @"NtResumeThread",
    @"NtSetEvent",
    @"NtSetInformationFile",
    @"NtSetIoCompletion",
    @"NtSetSystemTime",
    @"NtSetTimerEx",
    @"NtSignalAndWaitForSingleObjectEx",
    @"NtSuspendThread",
    @"NtUserIoApcDispatcher",
    @"NtWaitForSingleObject",
    @"NtWaitForSingleObjectEx",
    @"NtWaitForMultipleObjectsEx",
    @"NtWriteFile",
    @"NtWriteFileGather",
    @"NtYieldExecution",
    @"ObCreateObject",
    @"ObDirectoryObjectType",
    @"ObInsertObject",
    @"ObMakeTemporaryObject",
    @"ObOpenObjectByName",
    @"ObOpenObjectByPointer",
    @"ObpObjectHandleTable",
    @"ObReferenceObjectByHandle",
    @"ObReferenceObjectByName",
    @"ObReferenceObjectByPointer",
    @"ObSymbolicLinkObjectType",
    @"ObfDereferenceObject",
    @"ObfReferenceObject",
    @"PhyGetLinkState",
    @"PhyInitialize",
    @"PsCreateSystemThread",
    @"PsCreateSystemThreadEx",
    @"PsQueryStatistics",
    @"PsSetCreateThreadNotifyRoutine",
    @"PsTerminateSystemThread",
    @"PsThreadObjectType",
    @"RtlAnsiStringToUnicodeString",
    @"RtlAppendStringToString",
    @"RtlAppendUnicodeStringToString",
    @"RtlAppendUnicodeToString",
    @"RtlAssert",
    @"RtlCaptureContext",
    @"RtlCaptureStackBackTrace",
    @"RtlCharToInteger",
    @"RtlCompareMemory",
    @"RtlCompareMemoryUlong",
    @"RtlCompareString",
    @"RtlCompareUnicodeString",
    @"RtlCopyString",
    @"RtlCopyUnicodeString",
    @"RtlCreateUnicodeString",
    @"RtlDowncaseUnicodeChar",
    @"RtlDowncaseUnicodeString",
    @"RtlEnterCriticalSection",
    @"RtlEnterCriticalSectionAndRegion",
    @"RtlEqualString",
    @"RtlEqualUnicodeString",
    @"RtlExtendedIntegerMultiply",
    @"RtlExtendedLargeIntegerDivide",
    @"RtlExtendedMagicDivide",
    @"RtlFillMemory",
    @"RtlFillMemoryUlong",
    @"RtlFreeAnsiString",
    @"RtlFreeUnicodeString",
    @"RtlGetCallersAddress",
    @"RtlInitAnsiString",
    @"RtlInitUnicodeString",
    @"RtlInitializeCriticalSection",
    @"RtlIntegerToChar",
    @"RtlIntegerToUnicodeString",
    @"RtlLeaveCriticalSection",
    @"RtlLeaveCriticalSectionAndRegion",
    @"RtlLowerChar",
    @"RtlMapGenericMask",
    @"RtlMoveMemory",
    @"RtlMultiByteToUnicodeN",
    @"RtlMultiByteToUnicodeSize",
    @"RtlNtStatusToDosError",
    @"RtlRaiseException",
    @"RtlRaiseStatus",
    @"RtlTimeFieldsToTime",
    @"RtlTimeToTimeFields",
    @"RtlTryEnterCriticalSection",
    @"RtlUlongByteSwap",
    @"RtlUnicodeStringToAnsiString",
    @"RtlUnicodeStringToInteger",
    @"RtlUnicodeToMultiByteN",
    @"RtlUnicodeToMultiByteSize",
    @"RtlUnwind",
    @"RtlUpcaseUnicodeChar",
    @"RtlUpcaseUnicodeString",
    @"RtlUpcaseUnicodeToMultiByteN",
    @"RtlUpperChar",
    @"RtlUpperString",
    @"RtlUshortByteSwap",
    @"RtlWalkFrameChain",
    @"RtlZeroMemory",
    @"XboxEEPROMKey",
    @"XboxHardwareInfo",
    @"XboxHDKey",
    @"XboxKrnlVersion",
    @"XboxSignatureKey",
    @"XeImageFileName",
    @"XeLoadSection",
    @"XeUnloadSection",
    @"READ_PORT_BUFFER_UCHAR",
    @"READ_PORT_BUFFER_USHORT",
    @"READ_PORT_BUFFER_ULONG",
    @"WRITE_PORT_BUFFER_UCHAR",
    @"WRITE_PORT_BUFFER_USHORT",
    @"WRITE_PORT_BUFFER_ULONG",
    @"XcSHAInit",
    @"XcSHAUpdate",
    @"XcSHAFinal",
    @"XcRC4Key",
    @"XcRC4Crypt",
    @"XcHMAC",
    @"XcPKEncPublic",
    @"XcPKDecPrivate",
    @"XcPKGetKeyLen",
    @"XcVerifyPKCS1Signature",
    @"XcModExp",
    @"XcDESKeyParity",
    @"XcKeyTable",
    @"XcBlockCrypt",
    @"XcBlockCryptCBC",
    @"XcCryptService",
    @"XcUpdateCrypto",
    @"RtlRip",
    @"XboxLANKey",
    @"XboxAlternateSignatureKeys",
    @"XePublicKeyData",
    @"HalBootSMCVideoMode",
    @"IdexChannelObject",
    @"HalIsResetOrShutdownPending",
    @"IoMarkIrpMustComplete",
    @"HalInitiateShutdown",
    @"snprintf",
    @"sprintf",
    @"vsnprintf",
    @"vsprintf",
    @"HalEnableSecureTrayEject",
    @"HalWriteSMCScratchRegister",
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    nil,
    @"MmDbgAllocateMemory",
    @"MmDbgFreeMemory",
    @"MmDbgQueryAvailablePages",
    @"MmDbgReleaseAddress",
    @"MmDbgWriteCheck"
};

typedef struct XbeHeader {
    uint32_t magic;
    uint8_t signature[256];
    uint32_t base, soh, soi, soih;
    uint32_t timedate, certaddr, numsects, secthdrs, flags;
    uint32_t oep, tls;
    uint32_t stack_commit, heap_reserve, heap_commit, pe_base;
    uint32_t pe_soi, pe_csum, pe_timedate;
    uint32_t debug_pathname, debug_filename, debug_ufilename;
    uint32_t thunk, imports, numvers, libvers, kvers, xapivers;
    uint32_t logoaddr, logosize;
} XbeHeader;

typedef struct XbeSection {
    uint32_t flags, vaddr, vsize, raddr, rsize;
    uint32_t nameaddr, nameref, headref, tailref;
    uint8_t digest[20];
} XbeSection;

#define DEBUGXOR 0x94859D4B
#define RETAILXOR 0xA8FC57AB
#define DEBUGTHUNKXOR 0xEFB1F152
#define RETAILTHUNKXOR 0x5B6D40B6

- (FileLoaderLoadingStatus)loadData:(NSData *)data usingDetectedFileType:(DetectedFileType *)fileType options:(FileLoaderOptions)options forFile:(NSObject<HPDisassembledFile> *)file usingCallback:(FileLoadingCallbackInfo)callback {
    const void *bytes = (const void *)[data bytes];
    const XbeHeader *header = (XbeHeader *) bytes;
    if (header->magic != 0x48454258) return DIS_BadFormat; // XBEH
    
    file.cpuFamily = @"intel";
    file.cpuSubFamily = @"x86";
    [file setAddressSpaceWidthInBits:32];
    const XbeSection *sects = bytes + (header->secthdrs - header->base);

    int retail = -1;

    for(int i = 0; i < header->numsects; ++i) {
        const char *name = bytes + (sects[i].nameaddr - header->base);
        NSObject<HPSegment> *segment = [file addSegmentAt:sects[i].vaddr size:sects[i].vsize];
        NSObject<HPSection> *section = [segment addSectionAt:sects[i].vaddr size:sects[i].vsize];
        segment.segmentName = [NSString stringWithCString:name encoding:NSASCIIStringEncoding];
        section.sectionName = [NSString stringWithCString:name encoding:NSASCIIStringEncoding];
        NSString *comment = [NSString stringWithFormat:@"\n\nSection %@\n\n", segment.segmentName];
        [file setComment:comment atVirtualAddress:sects[i].vaddr reason:CCReason_Automatic];

        if(sects[i].rsize != 0) {
            NSData *segmentData = [NSData dataWithBytes:bytes+(sects[i].raddr) length:sects[i].rsize];
            segment.mappedData = segmentData;
            segment.fileOffset = section.fileOffset = sects[i].raddr;
            segment.fileLength = section.fileLength = sects[i].rsize;

            uint32_t ep = header->oep ^ RETAILXOR;
            if(ep >= sects[i].vaddr && ep < sects[i].vaddr+sects[i].vsize)
                retail = 1;
            ep = header->oep ^ DEBUGXOR;
            if(ep >= sects[i].vaddr && ep < sects[i].vaddr+sects[i].vsize)
                retail = 0;
        }
    }

    uint32_t thunkp = header->thunk;

    if(retail == 0) {
        [file addEntryPoint:header->oep ^ DEBUGXOR];
        thunkp ^= DEBUGTHUNKXOR;
    }
    else if(retail == 1) {
        [file addEntryPoint:header->oep ^ RETAILXOR];
        thunkp ^= RETAILTHUNKXOR;
    }

    if(retail != -1) {
        NSLog(@"Thunk at %x", thunkp);
        for(int i = 0; i < header->numsects; ++i) {
            if(sects[i].vaddr <= thunkp && sects[i].vaddr+sects[i].vsize > thunkp) {
                NSLog(@"Found thunk section...");
                const uint32_t *thunk = (const uint32_t *) (bytes + (thunkp - sects[i].vaddr + sects[i].raddr));
                while(*thunk != 0) {
                    [file setType:Type_Int32 atVirtualAddress:thunkp forLength:4];
                    uint32_t imp = *thunk & ~0x80000000;
                    if(imp < 379) {
                        NSString *name = imports[imp-1];
                        if(name != nil)
                            [file setName:name forVirtualAddress:thunkp reason:NCReason_Import];
                    }
                    thunk++;
                    thunkp += 4;
                }
                break;
            }
        }
    }

    return DIS_OK;
}

- (void)fixupRebasedFile:(NSObject<HPDisassembledFile> *)file withSlide:(int64_t)slide originalFileData:(NSData *)fileData {
    
}

- (FileLoaderLoadingStatus)loadDebugData:(NSData *)data forFile:(NSObject<HPDisassembledFile> *)file usingCallback:(FileLoadingCallbackInfo)callback {
    return DIS_NotSupported;
}

- (NSData *)extractFromData:(NSData *)data usingDetectedFileType:(DetectedFileType *)fileType returnAdjustOffset:(uint64_t *)adjustOffset {
    return nil;
}

@end
