//
//  KeyGenerateExample.m
//  KeychainExample
//
//  Created by 임정운 on 2021/06/16.
//

#import "KeyGenerateExample.h"

@implementation KeyGenerateExample

- (void) generateKeyPairWithKeySizeInBits:(int)bits withPublicIdentifier:(NSString *)publicIdentifier andPrivateIdentifier:(NSString *)privateIdentifier
{

    NSLog(@"begin generating key...");
    OSStatus status = noErr;

    NSMutableDictionary* privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary* publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary* keyPairAttr = [[NSMutableDictionary alloc] init];

    NSData* publicTag = [publicIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    NSData* privateTag = [privateIdentifier dataUsingEncoding:NSUTF8StringEncoding];

    SecKeyRef publicKey = NULL;
    SecKeyRef privateKey = NULL;

    [keyPairAttr setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id) kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithInt:bits] forKey:(__bridge id) kSecAttrKeySizeInBits];

    [privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id) kSecAttrIsPermanent];
    [privateKeyAttr setObject:privateTag forKey:(__bridge id) kSecAttrApplicationTag];

    [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];

    [keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];

    SecItemDelete((__bridge CFDictionaryRef)keyPairAttr);

    status = SecKeyGeneratePair((__bridge CFDictionaryRef) keyPairAttr, &publicKey, &privateKey);

    if(status != noErr){
        NSLog(@"status = %d", (int)status);
    }
    if(publicKey){
        NSLog(@"public key %@",publicKey);
    }

    if(privateKey){
        NSLog(@"private key %@",privateKey);
    }

    [self getPublicKeyBits:publicIdentifier];
}


- (NSData *)getPublicKeyBits: (NSString*) publicKeyIdentifier {

    OSStatus sanityCheck = noErr;
    NSData * publicKeyBits = nil;
    CFTypeRef pk;
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];

    NSData* publicTag = [publicKeyIdentifier dataUsingEncoding:NSUTF8StringEncoding];

    // Set the public key query dictionary.
    [queryPublicKey setObject:(__bridge_transfer id)kSecClassKey forKey:(__bridge_transfer id)kSecClass];

    [queryPublicKey setObject:publicTag forKey:(__bridge_transfer id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge_transfer id)kSecAttrKeyTypeRSA forKey:(__bridge_transfer id)kSecAttrKeyType];
    [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge_transfer id)kSecReturnData];

    // Get the key bits.
    sanityCheck = SecItemCopyMatching((__bridge_retained CFDictionaryRef)queryPublicKey, &pk);
    if (sanityCheck != noErr)
    {
        publicKeyBits = nil;
    }
    publicKeyBits = (__bridge_transfer NSData*)pk;
    NSLog(@"public bits %@",publicKeyBits);

    return publicKeyBits;
}


@end
