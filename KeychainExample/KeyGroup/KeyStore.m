//
//  KeyStore.m
//  KeychainExample
//
//  Created by 임정운 on 2021/06/15.
//

#import "KeyStore.h"

#import <openssl/x509.h>
#import <openssl/pem.h>

@implementation KeyStore

#pragma mark - Keychain Modules

/**
@method createRandomKeyPairWithTag
    tag값을 식별자로 랜덤한 keyPair을 생성합니다. 현재는 레거시가 된 SecKeyGeneratePair 대신 SecKeyCreateRandomKey 함수를 사용합니다.
 */
+(void)createRandomKeyPairWithTag:(NSString *)tag
{
    NSData *privateTag = [tag dataUsingEncoding:NSUTF8StringEncoding];
    CFErrorRef error = NULL;
    
    NSDictionary *keyPairAttr = @{
        (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeySizeInBits : @2048,
        (__bridge id)kSecPrivateKeyAttrs : @{
                (__bridge id)kSecAttrIsPermanent : @YES,
                (__bridge id)kSecAttrApplicationTag : privateTag
        }
    };
    
    SecKeyRef privateKeyRef = SecKeyCreateRandomKey((__bridge CFDictionaryRef)keyPairAttr, &error);
    
    if(error != NULL) {
        NSLog(@"Error_Ocurred__%@",error);
        CFRelease(error);
    }
    
    NSLog(@"Create_Key_Succese, PrivateKey_Info__%@", privateKeyRef);
}

/**
 @method generateSecKeyWithTag
    레거시가 된 방식입니다. public과 private에 대한 tag를 각기 설정하여 keyPair을 생성합니다.
 */
+(SecKeyRef)createKeyPairWithTag:(NSString *)publicTagString inPrivateTag:(NSString *)privateTagString
{
    NSData *privateTag = [privateTagString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *publicTag = [publicTagString dataUsingEncoding:NSUTF8StringEncoding];
    
    SecKeyRef privateKeyRef = NULL;
    SecKeyRef publicKeyRef = NULL;
    
    NSDictionary *keyPairAttr = @{
        (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeySizeInBits : @2048,
        (__bridge id)kSecPrivateKeyAttrs : @{
                (__bridge id)kSecAttrIsPermanent : @YES,
                (__bridge id)kSecAttrApplicationTag : privateTag
        },
        (__bridge id)kSecPublicKeyAttrs : @{
                (__bridge id)kSecAttrIsPermanent : @YES,
                (__bridge id)kSecAttrApplicationTag : publicTag
        }
    };
    
    OSStatus error = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKeyRef, &privateKeyRef);
    
    if (error == noErr && privateKeyRef != NULL && publicKeyRef != NULL) {
        NSLog(@"Key_Generate_Successful");
        
        NSData *publicKeyRefData = [[NSData alloc] initWithBytes:publicKeyRef length:sizeof(publicKeyRef)];
        NSLog(@"PublicKey_Bits__%@", publicKeyRefData);
        
        return publicKeyRef;
    } else {
        NSLog(@"Error_Ocurred__During generate Key, Error_Code__%d", (int)error);
        return nil;
    }
    
    return nil;
}

/**
 @method getKeychainWithTag
    tag를 식별자로 하여 key를 찾아냅니다.
 */
+(void)getKeychainWithTag:(NSString *)tagString
{
    OSStatus sanityCheck = noErr;
    CFTypeRef result = NULL;
    NSData *tag = [tagString dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *publicKeyBits = nil;
    
    NSDictionary *query = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrApplicationTag : tag,
        (__bridge id)kSecAttrKeySizeInBits : @2048,
        (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecReturnData : @YES /* [NSNumber numberWithBool:YES] */
    };
    
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (sanityCheck != noErr) {
        NSLog(@"Error_Ocurred__Not matching SecItem.");
    } else {
        publicKeyBits = (__bridge NSData *)result;
        NSLog(@"Find_Key!__%@", publicKeyBits);
        
        CFRelease(result);
        publicKeyBits = nil;
    }
}

/**
 @method checkAllKeychainItems
    모든 클래스의 키체인을 확인합니다.
 */
+(void)checkAllKeychainItems
{
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnAttributes];
    [query setObject:(__bridge id)kSecMatchLimitAll forKey:(__bridge id)kSecMatchLimit];
    
    NSArray *secItemClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassIdentity,
        (__bridge id)kSecClassKey
    ];
    
    for (id secItemClass in secItemClasses) {
        [query setObject:secItemClass forKey:(__bridge id)kSecClass];
        
        CFTypeRef result = NULL;
        SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        
        void (^secItemClassCase)(void) = @{
            @"genp" : ^{NSLog(@"kSecClassGenericPassword__%@", result);},
            @"inet" : ^{NSLog(@"kSecClassInternetPassword__%@", result);},
            @"cert" : ^{NSLog(@"kSecClassCertificate__%@", result);},
            @"idnt" : ^{NSLog(@"kSecClassIdentity__%@", result);},
            @"keys" : ^{NSLog(@"kSecClassKey__%@", result);}
        }[secItemClass];
        
        secItemClassCase();
        if(result != NULL) CFRelease(result);
    }
}

/**
 @method deleteAllKeychainItems
    모든 키체인의 아이템들을 삭제합니다.
 */
+(void)deleteAllKeychainItems
{
    NSArray *secItemClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassIdentity,
        (__bridge id)kSecClassKey
    ];
    
    for (id secItemClass in secItemClasses) {
        NSDictionary *query = @{(__bridge id)kSecClass : secItemClass};
        SecItemDelete((__bridge CFDictionaryRef)query);
    }
    
    NSLog(@"Delete_ALL_Keychain_arguements...");
}


#pragma mark - Encrypt RSA

/**
 @method encryptData
    레거시 함수입니다. publicKeyRef를 인자로 plainData를 RSA/PKCS1 암호화합니다.
 */
+(NSData *)encryptData:(NSData *)plainData inPublicRef:(SecKeyRef)publicKeyRef
{
    const uint8_t *srcBuffer = (const uint8_t *)[plainData bytes];
    size_t srcLength = (size_t)plainData.length;
    
    size_t blockSize = SecKeyGetBlockSize(publicKeyRef) * sizeof(uint8_t);
    void *outBuffer = malloc(blockSize);
    
    NSLog(@"publicKeySize__%zu, uint8_tSize__%lu Block_Size__%zu",SecKeyGetBlockSize(publicKeyRef), sizeof(uint8_t), blockSize);
    //block 사이즈 할당.
    
    size_t srcBlockSize = blockSize - 11;
    NSLog(@"SRC_Block_Size__%zu", srcBlockSize);
    
    NSMutableData *result = [[NSMutableData alloc] init];
    for (int idx = 0; idx < srcLength; idx += srcBlockSize) {
        size_t dataLength = srcLength - idx;
        
        if (dataLength > srcBlockSize) {
            dataLength = srcBlockSize;
        }
        
        size_t outLength = blockSize;
        OSStatus status = noErr;
        
        if (plainData == nil || publicKeyRef == nil) {
            NSLog(@"Error_Ocurred__plainData or publicKeyRef is nil");
            return nil;
        } else {
            status = SecKeyEncrypt(publicKeyRef, kSecPaddingPKCS1,
                                   srcBuffer + idx, dataLength,
                                   outBuffer, &outLength);
            
            if (status != noErr) {
                NSLog(@"Error_Ocurred__SecEncrypt fail, Error_Code__%d", status);
                result = nil;
                break;
            } else {
                [result appendBytes:outBuffer length:outLength];
            }
        }
    }
    
    free(outBuffer);
    CFRelease(publicKeyRef);
    
    return result;
}

+(SecKeyRef)getPrivateKey:(NSString *)tag
{
    OSStatus sanityCheck = noErr;
    SecKeyRef privateKeyRef = NULL;
    
    NSDictionary *query = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrApplicationTag : tag,
        (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecReturnRef : @YES
    };
    
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKeyRef);
    
    if (sanityCheck == noErr) {
        NSLog(@"Get_PrivateKey_Success.");
        return privateKeyRef;
    }
    
    NSLog(@"Error_Ocurred__Get_PrivateKey__Failure.");
    return nil;
}

+(CFDataRef)encryptWithTag:(NSString *)tag inPlainText:(NSString *)plainText
{
    SecKeyRef privateKeyRef = [KeyStore getPrivateKey:tag];
    SecKeyRef publicKeyRef = SecKeyCopyPublicKey(privateKeyRef);

    CFErrorRef error = NULL;
    CFDataRef plainData = (__bridge CFDataRef)([plainText dataUsingEncoding:NSUTF8StringEncoding]);
    
    CFDataRef encryptionResult = SecKeyCreateEncryptedData(
                                                            publicKeyRef,
                                                            kSecKeyAlgorithmRSAEncryptionPKCS1,
                                                            plainData, &error);
    
    if (error != NULL) {
        NSLog(@"Error_Ocurred__%@", error);
        
        CFRelease(error);
        return nil;
    }
    
    NSLog(@"Encrypt_Success.");
    return encryptionResult;
}

+(NSString *)decryptWithTag:(NSString *)tag inCipher:(CFDataRef)cipher
{
    SecKeyRef privateKey = [KeyStore getPrivateKey:tag];
    CFErrorRef error = NULL;
    
    CFDataRef decryptionResult = SecKeyCreateDecryptedData(
                                                           privateKey,
                                                           kSecKeyAlgorithmRSAEncryptionPKCS1,
                                                           cipher, &error);
    
    if (error != NULL) {
        NSLog(@"Error_Ocurred__%@", error);
        
        CFRelease(error);
        return nil;
    }
    
    NSString *decryptionString = [[NSString alloc] initWithData:(__bridge NSData *)decryptionResult encoding:NSUTF8StringEncoding];
    
    return decryptionString;
}


#pragma mark - Test function

+(NSString *)testWithTag:(NSString *)tag inData:(NSData *)data
{
    SecKeyRef keyRef = [KeyStore createKeyPairWithTag:@"aa" inPrivateTag:@"bb"];
    
    NSData *resultData = [KeyStore encryptData:data inPublicRef:keyRef];
    NSString *resultWithBase64 = [resultData base64EncodedStringWithOptions:0];
    
    return resultWithBase64;
}

int aaa(int a, int b)
{
    bbb(10, 20);
    
    int result = a + b;
    return result;
}

//c++는 매개변수명을 지정해줄 수 없다.
NSString *bbb(int a, int b)
{
    return [NSString string];
}

@end
