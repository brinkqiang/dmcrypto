
#include "dmcrypto.h"
#include "gtest.h"

TEST(DMCrypto, DMCrypto_MD5) {
    CDMMD5 md5;
    std::string input = "hello world";
    std::string expected = "5EB63BBBE01EEED093CB22BB8F5ACDC3";
    std::string result = md5.GetMD5(input);
    EXPECT_EQ(result, expected);
}

TEST(DMCrypto, DMCrypto_RC4) {
    CDMRC rc_client;
    rc_client.SetKey("hello world");
    std::string input = "hello world";
    std::string encrypted = rc_client.Encrypt(input);

	CDMRC rc_server;
    rc_server.SetKey("hello world");

    std::string decrypted = rc_server.Decrypt(encrypted);
    EXPECT_EQ(decrypted, input);
}

TEST(DMCrypto, DMCrypto_CRC) {
    CDMCRC crc;
    std::string input = "hello world";
    uint32_t result = crc.GetCRC(input);
    EXPECT_NE(result, 0); // CRC should not be zero
}

TEST(DMCrypto, DMCrypto_Base64) {
    CDMBase64 base64;
    std::string input = "hello world";
    std::string encoded = base64.Base64Encode(input);
    std::string decoded = base64.Base64Decode(encoded);
    EXPECT_EQ(decoded, input);
}

TEST(DMCrypto, DMCrypto_DES) {
    CDMDes des;
    DMDES3Block block;
    DMDES3Context encCtx, decCtx;
    
    des.DES3GenKey(&block);
    des.DES3GenEncKeySche(&encCtx, block);
    des.DES3GenDecKeySche(&decCtx, block);
    
    std::string input = "hello world";
    std::string encrypted = des.Encode(&encCtx, &block, input);
    std::string decrypted = des.Decode(&decCtx, &block, encrypted);
    EXPECT_EQ(decrypted, input);
}

TEST(DMCrypto, DMCrypto_AES) {
    CDMAES aes;
    std::string plain = "hello world12345"; // 16 bytes
    std::string iv = "hello world";
    std::string key = "hello world";
    
    // Test ECB mode
    std::string ecbEncrypted = aes.EncryptECB(plain, key);
    std::string ecbDecrypted = aes.DecryptECB(ecbEncrypted, key);
    EXPECT_EQ(ecbDecrypted, plain);
    
    // Test CFB mode
    std::string cfbEncrypted = aes.EncryptCFB(plain, key, iv);
    std::string cfbDecrypted = aes.DecryptCFB(cfbEncrypted, key, iv);
    EXPECT_EQ(cfbDecrypted, plain);
}
