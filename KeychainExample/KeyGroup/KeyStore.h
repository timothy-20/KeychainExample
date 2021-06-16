//
//  KeyStore.h
//  KeychainExample
//
//  Created by 임정운 on 2021/06/15.
//

#import <Foundation/Foundation.h>

@interface KeyStore : NSObject

+(SecKeyRef)generateRSAKeyWithTag:(NSString *)publicTagString inPrivateTag:(NSString *)privateTagString;
+(void)getKeychainWithTag:(NSString *)tagString;

+(void)checkAllKeychainItems;

@end
