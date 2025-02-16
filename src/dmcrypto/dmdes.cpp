#include "dmdes.h"
#include "dmcryptodes.h"

void CDMDes::DESGenKey(DMDESBlock* pIV)
{
    DESRandomKey(pIV);
}

void CDMDes::DES3GenKey(DMDES3Block* pIV)
{
    GenDES3Key(pIV);
}

void CDMDes::DESGenEncKeySche(DMDESContext *pCtx, DMDESBlock& oKey)
{
    DESSetEncKey(pCtx, oKey.acBlock);
}

void CDMDes::DES3GenEncKeySche(DMDES3Context *pCtx, DMDES3Block& oKey)
{
    DES3SetEncKey(pCtx, &oKey);
}


void CDMDes::DESGenDecKeySche(DMDESContext *pCtx, DMDESBlock& oKey)
{
    DESSetDecKey(pCtx, oKey.acBlock);
}

void CDMDes::DES3GenDecKeySche(DMDES3Context *pCtx, DMDES3Block& oKey)
{
    DES3SetDecKey(pCtx, &oKey);
}

void CDMDes::DESEncryptNCBC(DMDESContext    *pCtx,
    DMDESBlock		 *pIV,
    int32_t		 nLength,
    unsigned char *pInput,
    unsigned char *pOutput)
{
    DMDESBlock IVBak;
    memcpy(&IVBak, (const void*)pIV, sizeof(DMDESBlock));
    DESCryptCBC(pCtx, DES_ENCRYPT, nLength, pIV, pInput, pOutput);
    memcpy(pIV, (const void*)&IVBak, sizeof(DMDESBlock));
}

void CDMDes::DESEncryptNCBC(DMDES3Context   *pCtx,
    DMDES3Block	 *pIV,
    int32_t		 nLength,
    unsigned char *pInput,
    unsigned char *pOutput)
{
    DMDES3Block IVBak;
    memcpy(&IVBak, (const void*)pIV, sizeof(DMDES3Block));
    DES3CryptCBC(pCtx, DES_ENCRYPT, nLength, pIV, pInput, pOutput);
    memcpy(pIV, (const void*)&IVBak, sizeof(DMDES3Block));
}

void CDMDes::DESDecryptNCBC(DMDESContext	 *pCtx,
    DMDESBlock		 *pIV,
    int32_t		 nLength,
    unsigned char *pInput,
    unsigned char *pOutput)
{
    DMDESBlock IVBak;
    memcpy(&IVBak, (const void*)pIV, sizeof(DMDESBlock));
    DESCryptCBC(pCtx, DES_DECRYPT, nLength, pIV, pInput, pOutput);
    memcpy(pIV, (const void*)&IVBak, sizeof(DMDESBlock));
}

void CDMDes::DESDecryptNCBC(DMDES3Context	 *pCtx,
    DMDES3Block	 *pIV,
    int32_t		 nLength,
    unsigned char *pInput,
    unsigned char *pOutput)
{
    DMDES3Block IVBak;
    memcpy(&IVBak, (const void*)pIV, sizeof(DMDES3Block));
    DES3CryptCBC(pCtx, DES_DECRYPT, nLength, pIV, pInput, pOutput);
    memcpy(pIV, (const void*)&IVBak, sizeof(DMDES3Block));
}

std::string CDMDes::Encode(DMDES3Context *pCtx, DMDES3Block *pIV, const std::string& strInput)
{
    DMDES3Block IVBak;
    memcpy(&IVBak, (const void*)pIV, sizeof(DMDES3Block));
    std::string strOutput;
    int nSize = (strInput.size() % 8) ? ((strInput.size() / 8) + 1) * 8 : (strInput.size());
    strOutput.resize(nSize);
    DES3CryptCBC(pCtx, DES_ENCRYPT, strInput.size(), pIV, (uint8_t *)strInput.data(), (uint8_t *)strOutput.data());
    memcpy(pIV, (const void*)&IVBak, sizeof(DMDES3Block));

    return strOutput;
}

std::string CDMDes::Decode(DMDES3Context *pCtx, DMDES3Block *pIV, const std::string& strInput)
{
    DMDES3Block IVBak;
    memcpy(&IVBak, (const void*)pIV, sizeof(DMDES3Block));
    std::string strOutput;
    strOutput.resize(strInput.size());
    DES3CryptCBC(pCtx, DES_DECRYPT, strInput.size(), pIV, (uint8_t *)strInput.data(), (uint8_t *)strOutput.data());
    memcpy(pIV, (const void*)&IVBak, sizeof(DMDES3Block));
    strOutput.resize(strlen(strOutput.data()));
    return strOutput;
}

std::string CDMDes::Encode(DMDESContext* pCtx, DMDESBlock* pIV, const std::string& strInput)
{
	DMDESBlock IVBak;
	memcpy(&IVBak, (const void*)pIV, sizeof(DMDESBlock));
	std::string strOutput;
	int nSize = (strInput.size() % 8) ? ((strInput.size() / 8) + 1) * 8 : (strInput.size());
	strOutput.resize(nSize);
	DESCryptCBC(pCtx, DES_ENCRYPT, strInput.size(), pIV, (uint8_t*)strInput.data(), (uint8_t*)strOutput.data());
	memcpy(pIV, (const void*)&IVBak, sizeof(DMDESBlock));

	return strOutput;
}

std::string CDMDes::Decode(DMDESContext* pCtx, DMDESBlock* pIV, const std::string& strInput)
{
	DMDESBlock IVBak;
	memcpy(&IVBak, (const void*)pIV, sizeof(DMDESBlock));
	std::string strOutput;
	strOutput.resize(strInput.size());
	DESCryptCBC(pCtx, DES_DECRYPT, strInput.size(), pIV, (uint8_t*)strInput.data(), (uint8_t*)strOutput.data());
	memcpy(pIV, (const void*)&IVBak, sizeof(DMDESBlock));
	strOutput.resize(strlen(strOutput.data()));
	return strOutput;
}
