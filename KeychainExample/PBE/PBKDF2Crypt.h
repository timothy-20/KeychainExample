//
//  PBKDF2Crypt.h
//  KeychainExample
//
//  Created by 임정운 on 2021/06/14.
//

#import <Foundation/Foundation.h>

@interface PBKDF2Crypt : NSObject

+(NSData *)secRandom8BytesSalt;
+(NSData *)encryptPBKDF2:(NSString *)inPassword inSalt:(NSData *)salt;
+(NSData *)encryptAES128:(NSString *)plainText inKey:(NSData *)key;

@end
