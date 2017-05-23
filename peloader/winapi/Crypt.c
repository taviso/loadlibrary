#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

typedef struct _CRYPT_BIT_BLOB {
  DWORD cbData;
  BYTE  *pbData;
  DWORD cUnusedBits;
} CRYPT_BIT_BLOB, *PCRYPT_BIT_BLOB;

typedef struct _CRYPTOAPI_BLOB {
  DWORD cbData;
  BYTE  *pbData;
} CRYPT_INTEGER_BLOB, *PCRYPT_INTEGER_BLOB,
  CRYPT_UINT_BLOB, *PCRYPT_UINT_BLOB,
  CRYPT_OBJID_BLOB, *PCRYPT_OBJID_BLOB,
  CERT_NAME_BLOB, CERT_RDN_VALUE_BLOB,
  *PCERT_NAME_BLOB, *PCERT_RDN_VALUE_BLOB,
  CERT_BLOB, *PCERT_BLOB,
  CRL_BLOB, *PCRL_BLOB,
  DATA_BLOB, *PDATA_BLOB,
  CRYPT_DATA_BLOB, *PCRYPT_DATA_BLOB,
  CRYPT_HASH_BLOB, *PCRYPT_HASH_BLOB,
  CRYPT_DIGEST_BLOB, *PCRYPT_DIGEST_BLOB,
  CRYPT_DER_BLOB, PCRYPT_DER_BLOB,
  CRYPT_ATTR_BLOB, *PCRYPT_ATTR_BLOB;

typedef struct _CRYPT_ALGORITHM_IDENTIFIER {
  PVOID            pszObjId;
  CRYPT_OBJID_BLOB Parameters;
} CRYPT_ALGORITHM_IDENTIFIER, *PCRYPT_ALGORITHM_IDENTIFIER;

typedef struct _CERT_PUBLIC_KEY_INFO {
  CRYPT_ALGORITHM_IDENTIFIER Algorithm;
  CRYPT_BIT_BLOB             PublicKey;
} CERT_PUBLIC_KEY_INFO, *PCERT_PUBLIC_KEY_INFO;

typedef struct _CERT_EXTENSION {
  PVOID            pszObjId;
  BOOL             fCritical;
  CRYPT_OBJID_BLOB Value;
} CERT_EXTENSION, *PCERT_EXTENSION;

typedef struct _CERT_INFO {
  DWORD                      dwVersion;
  CRYPT_INTEGER_BLOB         SerialNumber;
  CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
  CERT_NAME_BLOB             Issuer;
  FILETIME                   NotBefore;
  FILETIME                   NotAfter;
  CERT_NAME_BLOB             Subject;
  CERT_PUBLIC_KEY_INFO       SubjectPublicKeyInfo;
  CRYPT_BIT_BLOB             IssuerUniqueId;
  CRYPT_BIT_BLOB             SubjectUniqueId;
  DWORD                      cExtension;
  PCERT_EXTENSION            rgExtension;
} CERT_INFO, *PCERT_INFO;

typedef struct _CERT_CONTEXT {
  DWORD      dwCertEncodingType;
  BYTE       *pbCertEncoded;
  DWORD      cbCertEncoded;
  PCERT_INFO pCertInfo;
  HANDLE     hCertStore;
} CERT_CONTEXT, *PCERT_CONTEXT;

static NTSTATUS WINAPI BCryptOpenAlgorithmProvider(PVOID phAlgorithm, PWCHAR pszAlgId, PWCHAR pszImplementation, DWORD dwFlags)
{
    return STATUS_SUCCESS;
}

static NTSTATUS WINAPI BCryptCloseAlgorithmProvider(HANDLE hAlgorithm, ULONG dwFlags)
{
    return STATUS_SUCCESS;
}

static NTSTATUS WINAPI BCryptGenRandom(PVOID phAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags)
{
    static int randomfd = -1;

    void __constructor init()
    {
        randomfd = open("/dev/urandom", O_RDONLY);
    }

    void __destructor fini()
    {
        close(randomfd);
    }

    DebugLog("%p, %p, %lu, %#x [fd=%d]", phAlgorithm, pbBuffer, cbBuffer, dwFlags, randomfd);

    if (read(randomfd, pbBuffer, cbBuffer) != cbBuffer) {
        DebugLog("failed to generate random data, %m");
    }

    return STATUS_SUCCESS;
}

static BOOL WINAPI CertStrToNameW(DWORD dwCertEncodingType, PVOID pszX500, DWORD dwStrType, void *pvReserved, BYTE *pbEncoded, DWORD *pcbEncoded, PVOID ppszError)
{
    uint16_t CertName[] = L"Totally Legitimate Certificate Name";
    char *name = CreateAnsiFromWide(pszX500);

    DebugLog("%u, %p [%s], %u, %p, %p, %p, %p", dwCertEncodingType, pszX500, name, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError);
    free(name);

    *pcbEncoded = sizeof(CertName);

    if (pbEncoded) {
        memcpy(pbEncoded, CertName, sizeof(CertName));
    }

    return TRUE;
}

static HANDLE WINAPI CertOpenStore(PCHAR lpszStoreProvider, DWORD dwMsgAndCertEncodingType, PVOID hCryptProv, DWORD dwFlags, PVOID pvPara)
{
    return (HANDLE) 'STOR';
}

static PVOID WINAPI CertFindCertificateInStore(HANDLE hCertStore, DWORD dwCertEncodingType, DWORD dwFindFlags, DWORD dwFindType, PVOID pvFindPara, PVOID pPrevCertContext)
{
    static CERT_INFO FakeInfo = {0};
    static CERT_CONTEXT FakeCert = {0};

    DebugLog("%p, %u, %#x, %#x, %p, %p", hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, pvFindPara, pPrevCertContext);

    FakeCert.pCertInfo = &FakeInfo;
    FakeCert.pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId = "1.2.840.113549.1.1.1";

    return &FakeCert;
}

static BOOL WINAPI CertCloseStore(HANDLE hCertStore, DWORD dwFlags)
{
    return TRUE;
}

static BOOL WINAPI CryptAcquireContextW(PVOID phProv, PWCHAR pszContainer, PWCHAR pszProvider, DWORD dwProvType, DWORD dwFlags)
{
    return TRUE;
}

static BOOL WINAPI CertFreeCertificateContext(PVOID pCertContext)
{
    return TRUE;
}

static BOOL WINAPI CryptCreateHash(PVOID hProv, DWORD Algid, HANDLE hKey, DWORD dwFlags, PDWORD phHash)
{
    return TRUE;
}

enum HashParameters
{
    HP_ALGID = 0x0001,   // Hash algorithm
    HP_HASHVAL = 0x0002, // Hash value
    HP_HASHSIZE = 0x0004 // Hash value size
};

static BOOL WINAPI CryptGetHashParam(PVOID hHash, DWORD dwParam, PDWORD pbData, PDWORD pdwDataLen, DWORD dwFlags)
{
    DebugLog("%p, %u, %p, %p, %#x", hHash, dwParam, pbData, pdwDataLen, dwFlags);

    switch (dwParam) {
        case HP_HASHSIZE:
            *pdwDataLen = sizeof(DWORD);
            *pbData = 20;
            break;
    }

    return TRUE;
}

static BOOL WINAPI CryptSetHashParam(PVOID hHash, DWORD dwParam, PVOID pbData, DWORD dwFlags)
{
    return TRUE;
}

static BOOL WINAPI CryptImportPublicKeyInfo(HANDLE hCryptProv, DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pInfo, HANDLE *phKey)
{
    return TRUE;
}

static BOOL WINAPI CryptVerifySignatureW(HANDLE hHash, PVOID pbSignature, DWORD dwSigLen, HANDLE hPubKey, PVOID sDescription, DWORD dwFlags)
{
    DebugLog("Signature verification is not implemented #YOLO");
    return TRUE;
}

static BOOL WINAPI CertVerifyCertificateChainPolicy(PVOID pszPolicyOID, PVOID pChainContext, PVOID pPolicyPara, PVOID pPolicyStatus)
{
    DebugLog("Certificate policy verification is not implemented #YOLO");
    return TRUE;
}

DECLARE_CRT_EXPORT("CertCloseStore", CertCloseStore);
DECLARE_CRT_EXPORT("CertFindCertificateInStore", CertFindCertificateInStore);
DECLARE_CRT_EXPORT("CertFreeCertificateContext", CertFreeCertificateContext);
DECLARE_CRT_EXPORT("CertOpenStore", CertOpenStore);
DECLARE_CRT_EXPORT("CertStrToNameW", CertStrToNameW);
DECLARE_CRT_EXPORT("CertVerifyCertificateChainPolicy", CertVerifyCertificateChainPolicy);
DECLARE_CRT_EXPORT("CryptImportPublicKeyInfo", CryptImportPublicKeyInfo);
DECLARE_CRT_EXPORT("CryptCreateHash", CryptCreateHash);
DECLARE_CRT_EXPORT("BCryptOpenAlgorithmProvider", BCryptOpenAlgorithmProvider);
DECLARE_CRT_EXPORT("BCryptCloseAlgorithmProvider", BCryptCloseAlgorithmProvider);
DECLARE_CRT_EXPORT("BCryptGenRandom", BCryptGenRandom);
DECLARE_CRT_EXPORT("CryptAcquireContextW", CryptAcquireContextW);
DECLARE_CRT_EXPORT("CryptGetHashParam", CryptGetHashParam);
DECLARE_CRT_EXPORT("CryptSetHashParam", CryptSetHashParam);
DECLARE_CRT_EXPORT("CryptVerifySignatureW", CryptVerifySignatureW);

