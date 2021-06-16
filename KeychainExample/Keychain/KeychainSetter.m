//
//  KeychainSetter.m
//  KeychainExample
//
//  Created by 임정운 on 2021/06/09.
//

#import "KeychainSetter.h"

@import Security;

@implementation KeychainSetter

+(void)addKeyWithKeychain:(NSString *)key inValue:(NSString *)value
{
    NSData *genericPassword = [value dataUsingEncoding:NSUTF8StringEncoding];
//    저장할 genericPassword 값에 대해 다른 방식의 암호화가 필요하겠다.
    
    NSMutableDictionary *attributes = [NSMutableDictionary dictionary];
    [attributes setObject:(__bridge id)kSecClassGenericPassword forKeyedSubscript:(__bridge id)kSecClass];
//    [attributes setObject:serviceName forKeyedSubscript:(__bridge id)kSecAttrService];
//    [attributes setObject:accountStr forKeyedSubscript:(__bridge id)kSecAttrAccount];
    [attributes setObject:key forKeyedSubscript:(__bridge id)kSecAttrGeneric];
    [attributes setObject:genericPassword forKey:(__bridge id)kSecValueData];
//    kSecValueData_key에 들어가는 Object가 keychain에 실질적으로 저장될 object이다.
    
    CFTypeRef result;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, &result);
    
//    SecAccessControlRef accessControl =
//    SecAccessControlCreateWithFlags(CFAllocatorRef  _Nullable allocator,
//                                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
//                                    SecAccessControlCreateFlags flags,
//                                    CFErrorRef  _Nullable * _Nullable error);
    
    if (status != noErr) {
        NSLog(@"Error_Ocurred__osStatus_%d", (int)status);
        return;
    }
    
    NSLog(@"Success_validate_data");
//    NSLog(@"return_result??__%@",(__bridge NSString *)result);
}

+(void)readUserWithUsername:(NSString *)key
{
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    [query setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
//    [query setObject:serviceName forKey:(__bridge id)kSecAttrService];
//    [query setObject:accountStr forKey:(__bridge id)kSecAttrAccount];
    [query setObject:key forKey:(__bridge id)kSecAttrGeneric];
//    [query setObject:[NSNumber numberWithBool:false] forKey:(__bridge id)kSecReturnAttributes];
    [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData]; //true numberWithBool에 대한 축약형으로 사용할 수 있음.
    
    CFTypeRef result;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    
    if (status != noErr) {
        NSLog(@"Error_Ocurred__diffrent identifier data.");
        return;
    }
    
    CFDataRef existingItem = result;
//    CFDictionaryRef existingItem = result;
//    NSData *resultData = [(__bridge NSDictionary *)existingItem objectForKey:(__bridge id)kSecAttrGeneric];
    NSString *resultStr = [[NSString alloc] initWithData:(__bridge NSData *)existingItem encoding:NSUTF8StringEncoding];
    
    NSLog(@"get_result??_%@", resultStr);
}




+(void)keychainWithPW:(NSString *)pwString inKeychainItemIndetifier:(NSString *)keychainItemIdentifier inKeychainItemServiceName:(NSString *)keychainItemServiceName
{
    NSData *pwData = [pwString dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableDictionary *attributes = [[NSMutableDictionary alloc] init];
    [attributes setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    [attributes setObject:keychainItemIdentifier forKey:(__bridge id)kSecAttrAccount];
    [attributes setObject:keychainItemServiceName forKey:(__bridge id)kSecAttrService];
    
//    NSDictionary *query = @{
//        (__bridge id)(CFStringRef)kSecClass:(__bridge id)(kSecClassGenericPassword),
//        (__bridge id)(CFStringRef)kSecAttrAccount:keychainItemIdentifier,
//        (__bridge id)(CFStringRef)kSecAttrServer:keychainItemServiceName,
//        (__bridge id)(CFStringRef)kSecAttrAccessControl:(__bridge id)(SecAccessControlRef)accessControl
//    };
 
    CFErrorRef accessControlError = NULL;
    SecAccessControlRef accessControl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, kSecAccessControlUserPresence, &accessControlError);
    
    if(accessControlError != nil || accessControl == NULL) {
        NSLog(@"Error_Ocurred__%@...With keychainIdentifier__%@", accessControlError, keychainItemIdentifier);
        return;
    }
    
    attributes[(__bridge id)kSecAttrAccessControl] = (__bridge id)accessControl;
    attributes[(__bridge id)kSecUseAuthenticationUI] = 0; //@NO
    attributes[(__bridge id)kSecValueData] = pwData;
    
    CFTypeRef result;
    OSStatus osStatus = SecItemAdd((__bridge CFDictionaryRef)attributes, &result);
    
    if(osStatus != noErr) {
        NSError *error = [[NSError alloc] initWithDomain:NSOSStatusErrorDomain code:osStatus userInfo:nil];
        NSLog(@"Error_Ocurred__%@...With osStatus__%d", error, (int)osStatus);
    }
    
    NSString *secUseOperationPrompt = @"webAuthn request";
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSMutableDictionary *query = [NSMutableDictionary dictionary];
        [query setObject:(__bridge id)(kSecClassGenericPassword) forKey:(__bridge id)kSecClass];
        [query setObject:keychainItemIdentifier forKey:(__bridge id)kSecAttrAccount];
        [query setObject:keychainItemServiceName forKey:(__bridge id)kSecAttrService];
        [query setObject:secUseOperationPrompt forKey:(__bridge id)kSecUseAuthenticationContext];
        
        CFTypeRef result = nil;
        OSStatus userPresenceStatus = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        
        if(userPresenceStatus == noErr)
            NSLog(@"Fingerprint or device passcode vaildated.");
        else
            NSLog(@"Error_Ocurred__Status_%d", (int)userPresenceStatus);
    });
    
}

@end
