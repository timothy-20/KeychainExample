//
//  KeyStore.h
//  KeychainExample
//
//  Created by 임정운 on 2021/06/15.
//

#import <Foundation/Foundation.h>

@interface KeyStore : NSObject

+(void)keychainWithAlertView:(UIViewController *)view;

+(void)checkAllKeychainItems;
+(void)deleteAllKeychainItems;

+(SecKeyRef)getPrivateKey;
+(CFDataRef)encryptWithTag:(NSString *)tag inPlainText:(NSString *)plainText;
+(NSString *)decryptWithTag:(NSString *)tag inCipher:(CFDataRef)cipher;

+(void)setKeychainForTouchId:(NSString *)plainText;
+(void)verifyKeychainForTouchId;

@end
