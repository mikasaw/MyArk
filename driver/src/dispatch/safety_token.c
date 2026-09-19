// MyArk Core Driver: SAFETY_TOKEN session key + HMAC validation.
//
// See safety_token.h. The MAC message is the token's non-signature fields
// packed little-endian: Magic(4) | Pid(4) | Operation(4) | Timestamp(8).

#include <ntddk.h>
#include <wdf.h>
#include <bcrypt.h>
#include "Trace.h"
#include "myark_config.h"
#include "MyArkSafetyToken.h"
#include "MyArkPoolAlloc.h"
#include "safety_token.h"

static BCRYPT_ALG_HANDLE g_TokenAlgHandle    = NULL;
static PUCHAR            g_TokenHashObject   = NULL;
static ULONG             g_TokenHashObjectSize = 0;
static UCHAR             g_SessionKey[MYARK_SAFETY_TOKEN_KEY_SIZE] = { 0 };
static BOOLEAN           g_SessionKeyValid   = FALSE;

#define MYARK_TOKEN_POOL_TAG    'kTaM'   // 'MaTk'

#ifndef BCRYPT_USE_SYSTEM_PREFERRED_RNGS
#define BCRYPT_USE_SYSTEM_PREFERRED_RNGS  0x00000002
#endif

NTSTATUS
MyArkSafetyTokenInit(
    VOID)
{
    NTSTATUS status;
    ULONG    objectLength = 0;
    ULONG    cbProperty   = 0;

    if (g_TokenAlgHandle != NULL) {
        return STATUS_SUCCESS;
    }

    status = BCryptOpenAlgorithmProvider(&g_TokenAlgHandle,
                                         BCRYPT_SHA256_ALGORITHM,
                                         NULL,
                                         BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DISPATCH,
                    "SafetyToken: BCryptOpenAlgorithmProvider failed: 0x%08X",
                    status);
        g_TokenAlgHandle = NULL;
        return status;
    }

    status = BCryptGetProperty(g_TokenAlgHandle,
                               BCRYPT_OBJECT_LENGTH,
                               (PUCHAR)&objectLength,
                               sizeof(objectLength),
                               &cbProperty,
                               0);
    if (!NT_SUCCESS(status) || objectLength == 0) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DISPATCH,
                    "SafetyToken: BCryptGetProperty(OBJECT_LENGTH) failed: 0x%08X",
                    status);
        BCryptCloseAlgorithmProvider(g_TokenAlgHandle, 0);
        g_TokenAlgHandle = NULL;
        return NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status;
    }

    //
    // ExAllocatePoolWithTag (not ExAllocatePool2): the kernel on Win10
    // 1904x does not export ExAllocatePool2, and the driver must load
    // there -- only the process/thread modules are build-gated.
    //
    g_TokenHashObject = (PUCHAR)MyArkAllocatePool(NonPagedPoolNx,
                                                  objectLength,
                                                  MYARK_TOKEN_POOL_TAG);
    if (g_TokenHashObject == NULL) {
        BCryptCloseAlgorithmProvider(g_TokenAlgHandle, 0);
        g_TokenAlgHandle = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_TokenHashObjectSize = objectLength;

    status = BCryptGenRandom(NULL,
                             g_SessionKey,
                             sizeof(g_SessionKey),
                             BCRYPT_USE_SYSTEM_PREFERRED_RNGS);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DISPATCH,
                    "SafetyToken: BCryptGenRandom failed: 0x%08X",
                    status);
        ExFreePoolWithTag(g_TokenHashObject, MYARK_TOKEN_POOL_TAG);
        g_TokenHashObject = NULL;
        g_TokenHashObjectSize = 0;
        BCryptCloseAlgorithmProvider(g_TokenAlgHandle, 0);
        g_TokenAlgHandle = NULL;
        return status;
    }
    g_SessionKeyValid = TRUE;

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DISPATCH,
                "SafetyToken: session key provisioned (%lu-byte hash object)",
                objectLength);

    return STATUS_SUCCESS;
}

VOID
MyArkSafetyTokenUnload(
    VOID)
{
    if (g_TokenHashObject != NULL) {
        ExFreePoolWithTag(g_TokenHashObject, MYARK_TOKEN_POOL_TAG);
        g_TokenHashObject = NULL;
        g_TokenHashObjectSize = 0;
    }
    if (g_TokenAlgHandle != NULL) {
        BCryptCloseAlgorithmProvider(g_TokenAlgHandle, 0);
        g_TokenAlgHandle = NULL;
    }
    g_SessionKeyValid = FALSE;
}

NTSTATUS
MyArkSafetyTokenGetSessionKey(
    _Out_writes_bytes_(MYARK_SAFETY_TOKEN_KEY_SIZE) PUCHAR KeyOut)
{
    if (!g_SessionKeyValid || KeyOut == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    RtlCopyMemory(KeyOut, g_SessionKey, MYARK_SAFETY_TOKEN_KEY_SIZE);
    return STATUS_SUCCESS;
}

//
// Compute HMAC-SHA256(sessionKey, Magic|Pid|Operation|Timestamp) into
// Digest (MYARK_SAFETY_TOKEN_SIGNATURE_SIZE bytes). The shared algorithm
// handle and hash-object buffer are safe to use without locking because
// every handler runs one-at-a-time on the sequential default queue.
//
static
NTSTATUS
MyArkSafetyTokenComputeDigest(
    _In_ PMYARK_SAFETY_TOKEN Token,
    _Out_writes_bytes_(MYARK_SAFETY_TOKEN_SIGNATURE_SIZE) PUCHAR Digest)
{
    BCRYPT_HASH_HANDLE hashHandle = NULL;
    NTSTATUS           status;
    UCHAR              message[4 + 4 + 4 + 8];

    RtlCopyMemory(message + 0,  &Token->Magic,      sizeof(Token->Magic));
    RtlCopyMemory(message + 4,  &Token->Pid,        sizeof(Token->Pid));
    RtlCopyMemory(message + 8,  &Token->Operation,  sizeof(Token->Operation));
    RtlCopyMemory(message + 12, &Token->Timestamp,  sizeof(Token->Timestamp));

    status = BCryptCreateHash(g_TokenAlgHandle,
                              &hashHandle,
                              g_TokenHashObject,
                              g_TokenHashObjectSize,
                              (PUCHAR)g_SessionKey,
                              sizeof(g_SessionKey),
                              0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = BCryptHashData(hashHandle, message, sizeof(message), 0);
    if (NT_SUCCESS(status)) {
        status = BCryptFinishHash(hashHandle,
                                  Digest,
                                  MYARK_SAFETY_TOKEN_SIGNATURE_SIZE,
                                  0);
    }

    BCryptDestroyHash(hashHandle);
    return status;
}

static
BOOLEAN
MyArkSafetyTokenDigestEquals(
    _In_reads_bytes_(MYARK_SAFETY_TOKEN_SIGNATURE_SIZE) PCUCHAR A,
    _In_reads_bytes_(MYARK_SAFETY_TOKEN_SIGNATURE_SIZE) PCUCHAR B)
{
    UCHAR diff = 0;
    for (ULONG i = 0; i < MYARK_SAFETY_TOKEN_SIGNATURE_SIZE; i++) {
        diff |= (UCHAR)(A[i] ^ B[i]);
    }
    return diff == 0;
}

NTSTATUS
MyArkSafetyTokenValidate(
    _In_ PMYARK_SAFETY_TOKEN Token,
    _In_ UINT32              ExpectedOperation,
    _In_ UINT32              ExpectedPid)
{
    LARGE_INTEGER  now;
    LONGLONG       delta;
    UCHAR          digest[MYARK_SAFETY_TOKEN_SIGNATURE_SIZE];
    NTSTATUS       status;

    if (Token == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_SessionKeyValid || g_TokenAlgHandle == NULL) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DISPATCH,
                    "SafetyToken: validator used before init");
        return STATUS_ACCESS_DENIED;
    }

    if (Token->Magic != MYARK_SAFETY_TOKEN_MAGIC) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DISPATCH,
                    "SafetyToken: bad magic 0x%08X",
                    (unsigned long)Token->Magic);
        return STATUS_ACCESS_DENIED;
    }

    if (Token->Pid != ExpectedPid || Token->Operation != ExpectedOperation) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DISPATCH,
                    "SafetyToken: binding mismatch (pid=%lu/%lu op=%lu/%lu)",
                    (unsigned long)Token->Pid,
                    (unsigned long)ExpectedPid,
                    (unsigned long)Token->Operation,
                    (unsigned long)ExpectedOperation);
        return STATUS_ACCESS_DENIED;
    }

    KeQuerySystemTime(&now);
    delta = now.QuadPart - Token->Timestamp.QuadPart;
    if (delta < -MYARK_SAFETY_TOKEN_TIME_WINDOW_100NS ||
        delta >  MYARK_SAFETY_TOKEN_TIME_WINDOW_100NS) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DISPATCH,
                    "SafetyToken: timestamp outside freshness window");
        return STATUS_ACCESS_DENIED;
    }

    status = MyArkSafetyTokenComputeDigest(Token, digest);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DISPATCH,
                    "SafetyToken: HMAC computation failed: 0x%08X",
                    status);
        return STATUS_ACCESS_DENIED;
    }

    if (!MyArkSafetyTokenDigestEquals(digest, Token->Signature)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DISPATCH,
                    "SafetyToken: HMAC mismatch");
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

