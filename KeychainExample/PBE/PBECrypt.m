//
//  PBECrypt.m
//  KeychainExample
//
//  Created by 임정운 on 2021/06/11.
//

#import "PBECrypt.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>

@implementation PBECrypt
+ (NSData *)encodePBEWithMD5AndDESData:(NSData *)inData password:(NSString *)password direction:(int)direction
{
    static const char gSalt[] =
    {
        (unsigned char)0xa8, (unsigned char)0x7b, (unsigned char)0xc3, (unsigned char)0x37,
        (unsigned char)0x53, (unsigned char)0x22, (unsigned char)0xe2, (unsigned char)0x05
    };
    
    unsigned char *salt = (unsigned char *)gSalt;
    int saltLen = sizeof(gSalt);
    int iterations = 17;
    
    if (saltLen != 8) {
        NSLog(@"salt length should be 8!");
        return nil;
    }
    
    EVP_CIPHER_CTX cipherCtx;
    
    
    unsigned char *mResults;         // allocated storage of results
    int mResultsLen = 0;
    
    const char *cPassword = [password UTF8String];
    
    unsigned char *mData = (unsigned char *)[inData bytes];
    int mDataLen = [inData length];
    
    SSLeay_add_all_algorithms();
    X509_ALGOR *algorithm = PKCS5_pbe_set(NID_pbeWithMD5AndDES_CBC,
                                          iterations, salt, saltLen);
    
    
    memset(&cipherCtx, 0, sizeof(cipherCtx));
    
    if (algorithm != NULL)
    {
        EVP_CIPHER_CTX_init(&(cipherCtx));
        
        if (EVP_PBE_CipherInit(algorithm->algorithm, cPassword, strlen(cPassword),
                               algorithm->parameter, &(cipherCtx), direction))
        {
            
            EVP_CIPHER_CTX_set_padding(&cipherCtx, 1);
            
            int blockSize = EVP_CIPHER_CTX_block_size(&cipherCtx);
            int allocLen = mDataLen + blockSize + 1; // plus 1 for null terminator on decrypt
            mResults = (unsigned char *)OPENSSL_malloc(allocLen);
            
            unsigned char *in_bytes = mData;
            int inLen = mDataLen;
            unsigned char *out_bytes = mResults;
            int outLen = 0;
            
            
            
            int outLenPart1 = 0;
            if (EVP_CipherUpdate(&(cipherCtx), out_bytes, &outLenPart1, in_bytes, inLen))
            {
                out_bytes += outLenPart1;
                int outLenPart2 = 0;
                if (EVP_CipherFinal(&(cipherCtx), out_bytes, &outLenPart2))
                {
                    outLen += outLenPart1 + outLenPart2;
                    mResults[outLen] = 0;
                    mResultsLen = outLen;
                }
            } else {
                unsigned long err = ERR_get_error();
                ERR_load_crypto_strings();
                ERR_load_ERR_strings();
                char errbuff[256];
                errbuff[0] = 0;
                ERR_error_string_n(err, errbuff, sizeof(errbuff));
                NSLog(@"OpenSLL ERROR:\n\tlib:%s\n\tfunction:%s\n\treason:%s\n",
                      ERR_lib_error_string(err),
                      ERR_func_error_string(err),
                      ERR_reason_error_string(err));
                ERR_free_strings();
            }
            
            
            NSData *encryptedData = [NSData dataWithBytes:mResults length:mResultsLen];
            
            //NSLog(@"encryption result: %@\n", [encryptedData base64EncodedString]);
            
            return encryptedData;
        }
    }
    return nil;
    
}

@end
