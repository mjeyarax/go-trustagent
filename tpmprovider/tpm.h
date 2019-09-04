
typedef struct tpm tpm;

typedef enum TPM_VERSION
{
	TPM_VERSION_UNKNOWN,
    TPM_VERSION_LINUX_20,
    TPM_VERSION_WINDOWS_20
} TPM_VERSION;

tpm* TpmCreate();
void TpmDelete(tpm* tpm);

TPM_VERSION Version(tpm* tpm);
//int CreateCertifiedKey(char* keyAuth, char* aikAuth);
//int Unbind(ck *CertifiedKey, char* keyAuth, char* encData); // result buffer go allocated byte array passed in as reference, filled in by 'C' ([]byte, error)
//int Sign(ck *CertifiedKey, char* keyAuth []byte, alg crypto.Hash, hashed []byte) ([]byte, error)
int TakeOwnership(tpm* tpm, char* newOwnerAuth, int len);
int IsOwnedWithAuth(tpm* tpm, char* ownerAuth, int len);
//int SetCredential(authHandle uint, ownerAuth []byte, /*credentialType constants.CredentialType,*/ credentialBlob []byte) error
//int GetCredential(authHandle uint, /*credentialType constants.CredentialType*/) ([]byte, error)
//int GetAssetTag(authHandle uint) ([]byte, error)
//int GetAssetTagIndex() (uint, error)