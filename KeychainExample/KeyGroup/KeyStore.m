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
 @method generateRSAKeyWithTag
    SecKeyGeneratePair을 이용해서 키를 생성함과 동시에, 자동적으로 keychain에 저장된다.
 
 */

+(SecKeyRef)generateRSAKeyWithTag:(NSString *)publicTagString inPrivateTag:(NSString *)privateTagString
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
    
    NSString *aa = @"aa";
    
    void (^secItemClassCase)() = @{
        (__bridge id)kSecClassGenericPassword : ^{
            
        },
        
        (__bridge id)kSecClassInternetPassword : ^{
            
        },
        
        (__bridge id)kSecClassCertificate : ^{
            
        },
        
        (__bridge id)kSecClassIdentity : ^{
            
        },
        
        (__bridge id)kSecClassKey : ^{
            
        }
    }[aa];
    
    for (id secItemClass in secItemClasses) {
        [query setObject:secItemClass forKey:(__bridge id)kSecClass];
        
        CFTypeRef result = NULL;
        SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        
        NSString *secItemClassString = (__bridge NSString *)((__bridge CFStringRef)secItemClass);
        
        
        
        if(result != NULL) CFRelease(result);
    }
}

-(void)deleteAllKeychainItems
{
    
}

#pragma mark - Encrypt RSA

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

#pragma mark - Test function

+(NSString *)testWithTag:(NSString *)tag inData:(NSData *)data
{
    SecKeyRef keyRef = [KeyStore generateRSAKeyWithTag:tag inPrivateTag:tag];
    
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
