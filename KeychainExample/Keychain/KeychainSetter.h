//
//  KeychainSetter.h
//  KeychainExample
//
//  Created by 임정운 on 2021/06/09.
//

#import <Foundation/Foundation.h>

@interface KeychainSetter : NSObject
+(void)addKeyWithKeychain:(NSString *)key inValue:(NSString *)value;
+(void)readUserWithUsername:(NSString *)key;

@end
