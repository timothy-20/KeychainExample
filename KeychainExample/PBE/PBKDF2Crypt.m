//
//  PBKDF2Crypt.m
//  KeychainExample
//
//  Created by 임정운 on 2021/06/14.
//

#import "PBKDF2Crypt.h"

@import CommonCrypto;

@implementation PBKDF2Crypt

#pragma mark - Encrypt Modules

+(NSString *)dataToHexString:(NSData *)inData
{
    const unsigned char *dataBuffer = (const unsigned char *)[inData bytes];
    
    if(!dataBuffer) {
        NSLog(@"Error_Ocurred__Not_exist_inData");
        return [NSString string];
    }
    
    NSUInteger dataLength = [inData length];
    NSMutableString *hexString = [NSMutableString stringWithCapacity:(dataLength * 2)];
    
    for (int i = 0; i < dataLength; ++i) {
        [hexString appendString:[NSString stringWithFormat:@"%02lx", (unsigned long)dataBuffer[i]]];
    }
    
    return [NSString stringWithString:hexString];
}

+(NSData *)arc4random8bytesSalt
{
    unsigned char saltBuffer[8];
    for (int i = 0; i < 8; i++) {
        saltBuffer[i] = (unsigned char)arc4random();
    }
    
    return [NSData dataWithBytes:saltBuffer length:sizeof(saltBuffer)];
}

+(NSData *)secRandom8BytesSalt
{
    uint8_t saltBytes[8];
    int saltResult = SecRandomCopyBytes(kSecRandomDefault, 8, saltBytes);
    
    if (saltResult == 0) {
//        NSMutableString *uuidStringReplacement = [[NSMutableString alloc] initWithCapacity:16];
//        for (NSInteger index = 0; index < 8; index++) {
//            [uuidStringReplacement appendFormat:@"%02x", saltBytes[index]];
//        }
        
        NSData *saltData = [[NSData alloc] initWithBytes:saltBytes length:sizeof(saltBytes)];
        return saltData;
    }
    
    NSLog(@"Error_Ocurred__Fail_Generate_SaltBytes");
    return [NSData data];
}

#pragma mark - Generate PBKDF2Key

+(NSData *)encryptPBKDF2:(NSString *)inPassword inSalt:(NSData *)salt
{
    NSData *pwData = [inPassword dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"SecRandom_Salt__%@", salt);
    
    NSMutableData *derivedKey = [NSMutableData dataWithLength:kCCKeySizeAES128];
    uint defineRound = 1000;
    
//    int round = CCCalibratePBKDF(kCCPBKDF2, pwData.length, salt.length, kCCPRFHmacAlgSHA256, 32, 100);
//    NSLog(@"Round_Count__%d", round);
//    NSAssert((round == 0), @"Error_Ocurred__round value is zero...");
    
    int resultInt = CCKeyDerivationPBKDF(kCCPBKDF2, pwData.bytes, pwData.length,
                         salt.bytes, salt.length,
                         kCCPRFHmacAlgSHA1,
                         defineRound, derivedKey.mutableBytes, derivedKey.length);
//    PBF는 난수생성을 위한 알고리즘을 의미한다.
    
    if (resultInt != 0) {
        NSLog(@"Error Ocurred__Fail generate DerivedKey...");
        return [NSData data];
    }
//    NSAssert((resultInt == 0), @"Error Ocurred__Fail generate DerivedKey...");
    
    return derivedKey;
}

+(NSString *)encryptBase64Url:(NSData *)inData
{
    NSString *base64UrlString = [inData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    base64UrlString = [base64UrlString stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    base64UrlString = [base64UrlString stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    
    return base64UrlString;
}

#pragma mark - Encrypt AES128-CBC

+(NSData *)encryptAES128:(NSString *)plainText inKey:(NSData *)key
{
    const unsigned int keySize = kCCKeySizeAES128;
    
    if (key == nil) {
        NSLog(@"Errror_Ocurred__Cant recieve keyValue");
        return [NSData data];
    }
    
    char keyPtr[keySize + 1];
    bzero(keyPtr, sizeof(keyPtr)); //Array를 전부 0으로 채워 초기화
    
//    NSData *makeshift = [NSData data];
//    [makeshift getBytes:(nonnull void *) length:(NSUInteger)];
    
//    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    [key getBytes:keyPtr length:sizeof(keyPtr)];
    size_t numByteEncypted = 0x00;
    
    NSData *plainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
//    const char *aaa = plainText.UTF8String; //NSString to 'const char'.
    
    NSUInteger dataLength = [plainData length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize); //plainData 길이에 aes128Block만큼 length를 더한 값만큼 메모리를 할당받는다.
    
    NSMutableData *makeshiftIV = [NSMutableData dataWithLength:16];
    makeshiftIV = (NSMutableData *)[@"testIV" dataUsingEncoding:NSUTF8StringEncoding];
    
    NSLog(@"IV_DATA__%@", makeshiftIV);
    NSLog(@"IV_HEX__%@", [self dataToHexString:makeshiftIV]);
//    cbc encode?
    
    CCCryptorStatus result = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding | kCCModeCBC,
                                     keyPtr, keySize, makeshiftIV.bytes,
                                     plainData.bytes, plainData.length,
                                     buffer, bufferSize, &numByteEncypted);
    
    if (result == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numByteEncypted];
    } else {
        NSLog(@"Error_Ocurred__AES128 Encrypt was fail...");
    }
    
    free(buffer);
    return [NSData data];
}


#pragma mark - Test function

+(void)testWitharc4AndSecRandom
{
    static const char gSalt[] =
    {
        (unsigned char)0xa8, (unsigned char)0x7b, (unsigned char)0xc3, (unsigned char)0x37,
        (unsigned char)0x53, (unsigned char)0x22, (unsigned char)0xe2, (unsigned char)0x05
    };
    
    NSData *saltData = [NSData dataWithBytes:(const void *)gSalt length:sizeof(gSalt)];
    NSLog(@"Print_Const_Char_Salt__%@", saltData);
    NSLog(@"Print_Const_Char_HexString__%@", [self dataToHexString:saltData]);
    
    int bytesLength = 8;
    NSMutableData *randomData = [NSMutableData dataWithCapacity:bytesLength];
    for (unsigned int i = 0; i < bytesLength; ++i) {
        u_int32_t randomBits = arc4random();
        [randomData appendBytes:(void *)&randomBits length:1];
    }
    NSLog(@"Print_arc4random_Salt__%@", randomData);
    NSLog(@"Print_arc4rnadom_HexString__%@", [self dataToHexString:randomData]);
    
    uint8_t randomBytes[8];
    int randomResult = SecRandomCopyBytes(kSecRandomDefault, 8, randomBytes);
    if(randomResult == 0) {
        NSMutableString *uuidStringReplacement = [[NSMutableString alloc] initWithCapacity:8*2];
        
        NSData *testString = [[NSData alloc] initWithBytes:randomBytes length:sizeof(randomBytes)];
        NSLog(@"aaaaaaa_______%@", [self dataToHexString:testString]);
        
        for (NSInteger index = 0; index < 8; index++) {
            [uuidStringReplacement appendFormat:@"%02x", randomBytes[index]];
        }
        
        NSLog(@"Print_SecRandomCopyBytes_Salt__%@", uuidStringReplacement);
    } else {
        NSLog(@"Error_Ocurred_With_SecRandomBytes_Salt!");
    }
    
//    u_int32_t value = acr4random() % 1000;
//    NSData *value2 = [NSData dataWithBytes:value length:(value)];
}

+(void)dancingWithBytes
{
    NSData *aa = [@"aa" dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"aaaaaaaaaaaaaa______%@", [self dataToHexString:aa]);
    
    NSString *bb = @"bb";
    char cc[10];
    bzero(cc, sizeof(cc));

    [bb getCString:cc maxLength:sizeof(cc) encoding:NSUTF8StringEncoding];
    NSLog(@"bb__%@, cc__%s", bb, cc);
}

@end
