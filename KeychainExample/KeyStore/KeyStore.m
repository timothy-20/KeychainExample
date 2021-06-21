//
//  KeyStore.m
//  KeychainExample
//
//  Created by 임정운 on 2021/06/15.
//

#import <UIKit/UIKit.h>
#import "KeyStore.h"

@import Security;
@import LocalAuthentication;

@implementation KeyStore

#pragma mark - Keychain Modules

+(void)pincodeAlertWithView:(UIViewController *)view completionHandler:(void(^)(NSString *pincode))completion
{
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Retry" message:@"Access your password on the keychain" preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Enter pincode";
        textField.secureTextEntry = YES;
    }];
    
    UIAlertAction *pincodeAction = [UIAlertAction actionWithTitle:@"입력" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        completion(alert.textFields[0].text);
        [alert dismissViewControllerAnimated:YES completion:nil];
    }];
    
    UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:@"취소" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        [alert dismissViewControllerAnimated:YES completion:nil];
        return;
    }];
    
    [alert addAction:pincodeAction];
    [alert addAction:cancelAction];
    
    [view presentViewController:alert animated:YES completion:nil];
}

/**
@method createRandomKeyPairWithTag
    tag값을 식별자로 랜덤한 keyPair을 생성합니다. 현재는 레거시가 된 SecKeyGeneratePair 대신 SecKeyCreateRandomKey 함수를 사용합니다.
 */
+(void)keychainWithAlertView:(UIViewController *)view
{
    LAContext *context = [[LAContext alloc] init];
    NSError *contextError = nil;
    
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&contextError] == NO) {
        NSLog(@"Error_Ocurred__%@", contextError);
        return;
    }
    
    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:@"Access your password on the keychain" reply:^(BOOL success, NSError *error) {
        if (success) {
            dispatch_async(dispatch_get_main_queue(), ^{
                NSLog(@"Success__Biometry Authentification.");
                [self createRSAKeyPairWithBiometry:context withPincode:nil];
            });
            
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                switch (error.code) {
                    case LAErrorUserFallback:
                    {
                        NSLog(@"Fallback__Pincode Insert.");
                        [self pincodeAlertWithView:view completionHandler:^(NSString *pincode) {
                            NSLog(@"Receive_pincode__%@", pincode);
                            [self createRSAKeyPairWithBiometry:nil withPincode:pincode];
                        }];
                    }
                        break;
                        
                    case LAErrorUserCancel:
                    {
                        NSLog(@"Cancel__Pincode Insert.");
                        
                        [self pincodeAlertWithView:view completionHandler:^(NSString *pincode) {
                            NSLog(@"Receive_pincode__%@", pincode);
                            [self createRSAKeyPairWithBiometry:nil withPincode:pincode];
                        }];
                    }
                        break;
                        
                    default:
                        NSLog(@"Error_Ocurred__%@",error.description);
                        break;
                }
            });
        }
    }];
    
    return;
}

+(void)createRSAKeyPairWithBiometry:(LAContext *)context withPincode:(NSString *)pincode
{
    CFErrorRef attrError = NULL;
    CFErrorRef accessControlError = NULL;
    
    SecAccessControlRef pincodeACR = SecAccessControlCreateWithFlags(
                                                                     kCFAllocatorDefault,
                                                                     kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                                     kSecAccessControlApplicationPassword,
                                                                     &accessControlError);
    
    SecAccessControlRef biometryACR = SecAccessControlCreateWithFlags(
                                                                     kCFAllocatorDefault,
                                                                     kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                                     kSecAccessControlUserPresence,
                                                                     &accessControlError);
    
    if (pincodeACR == NULL || accessControlError != NULL) {
        NSLog(@"Error_Ocurred__%@", accessControlError);
        CFRelease(accessControlError);
        return;
    } else if (biometryACR == NULL || accessControlError != NULL) {
        NSLog(@"Error_Ocurred__%@", accessControlError);
        CFRelease(accessControlError);
        return;
    }
    
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    [query setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [query setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [query setObject:@2048 forKey:(__bridge id)kSecAttrKeySizeInBits];
    //여기까지는 기본적인 RSAKeyPair 생성 형태.
    
    if (context != nil && pincode == nil) {
        NSLog(@"Save with biometry in Keychain.");
        
//        [query setObject:(__bridge id)biometryACR forKey:(__bridge id)kSecAttrAccessControl];
        [query setObject:@{
            (__bridge id)kSecAttrIsPermanent : @YES,
            (__bridge id)kSecUseAuthenticationContext : context,
            (__bridge id)kSecAttrAccessControl : (__bridge id)biometryACR
        } forKey:(__bridge id)kSecPrivateKeyAttrs];
        
    } else if (context == nil && pincode != nil) {
        NSLog(@"Save with pincode in Keychain");
        
        NSData *tagData = [pincode dataUsingEncoding:NSUTF8StringEncoding];
//        [query setObject:(__bridge id)pincodeACR forKey:(__bridge id)kSecAttrAccessControl];
        [query setObject:@{
            (__bridge id)kSecAttrIsPermanent : @YES,
            (__bridge id)kSecAttrApplicationTag : tagData,
            (__bridge id)kSecAttrAccessControl : (__bridge id)pincodeACR
        } forKey:(__bridge id)kSecPrivateKeyAttrs];
    } else {
        NSLog(@"Error_Ocurred__Can't Receive Data.");
        return;
    }
    
    SecKeyRef privateKeyRef = SecKeyCreateRandomKey((__bridge CFDictionaryRef)query, &attrError);
    if (attrError != NULL) {
        NSLog(@"Error_Ocurred__%@", attrError);
        
        CFRelease(attrError);
        return;
    }
    
    NSLog(@"Create_Key_Succese, PrivateKey_Info__%@", privateKeyRef);
    return;
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

+(SecKeyRef)getPrivateKey
{
    OSStatus sanityCheck = noErr;
    SecKeyRef privateKeyRef = NULL;
    
    NSMutableDictionary *mutableQuery = [NSMutableDictionary dictionary];
    [mutableQuery setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [mutableQuery setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];

    
    NSDictionary *query = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
        (__bridge id)kSecUseOperationPrompt : @"Access you private key in keychain",
        (__bridge id)kSecReturnRef : @YES
    };
    
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKeyRef);
    
    if (sanityCheck == noErr) {
        NSLog(@"Get_PrivateKey_Success__%@", privateKeyRef);
        return privateKeyRef;
    }
    
    NSError *error = [[NSError alloc] initWithDomain:NSOSStatusErrorDomain code:sanityCheck userInfo:nil];
    NSLog(@"Error_Ocurred__%@", error.localizedDescription);
    
    return nil;
}

+(CFDataRef)encryptWithTag:(NSString *)tag inPlainText:(NSString *)plainText
{
    SecKeyRef privateKeyRef = [KeyStore getPrivateKey];
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
    SecKeyRef privateKey = [KeyStore getPrivateKey];
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


#pragma mark - Biometry Keychain

+(void)setKeychainForTouchId:(NSString *)plainText
{
    LAContext *context = [[LAContext alloc] init];
    NSError *error = nil;
    
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error] == NO) {
        NSLog(@"Error_Ocurred__%@", error);
        return;
    }
    
    NSData *pwData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    CFErrorRef accessControlError = NULL;
    
    SecAccessControlRef accessControlRef = SecAccessControlCreateWithFlags(
                                                                           kCFAllocatorDefault,
                                                                           kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                                           kSecAccessControlUserPresence,
                                                                           &accessControlError);
//    만일 AccessControl 옵션에서, biometry만 받게 한다면 생체인증 실패 시 pincode를 받는 등의 부차적인 작업을 할 수 없게된다.
    
    if (accessControlRef == NULL || accessControlError != NULL) {
        NSLog(@"Error_Ocurred__%@", accessControlError);
        return;
    }
    
    NSDictionary *attributes = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
//        (__bridge id)kSecAttrAccount : <#keychainItemIdenfier#>,
//        (__bridge id)kSecAttrService : <#serviceName#>,
        (__bridge id)kSecAttrAccessControl : (__bridge id)accessControlRef,
//        (__bridge id)kSecUseAuthenticationUI : @NO,
        (__bridge id)kSecUseAuthenticationContext : context,
        (__bridge id)kSecValueData : pwData
    };
    
    CFTypeRef result;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, &result);
    
    if (status != noErr) {
        NSError *error = [[NSError alloc] initWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        NSLog(@"Error_Ocurred__%@", error);
        return;
    }
    
    NSLog(@"Biometry_Authentification_Success");
}

+(void)verifyKeychainForTouchId
{
    LAContext *context = [[LAContext alloc] init];
    NSError *error = nil;
    
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error] == NO) {
        NSLog(@"Error_Ocurred__%@", error);
        return;
    }
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSDictionary *query = @{
            (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
//            (__bridge id)kSecAttrAccount : <#keychainItemIdentifier#>,
//            (__bridge id)kSecAttrService : <#serviceName#>,
            (__bridge id)kSecUseOperationPrompt : @"Access your password on the keychain",
            (__bridge id)kSecReturnData : @YES
        };
        
        CFTypeRef result = nil;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        if (status != noErr) {
            NSError *error = [[NSError alloc] initWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
            NSLog(@"Error_Ocurred__%@", error);
            return;
        }
        
        NSString *resultString = [[NSString alloc] initWithData:(__bridge NSData *)result encoding:NSUTF8StringEncoding];
        NSLog(@"Biometry_Authentification_Success__%@", resultString);
    });
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
