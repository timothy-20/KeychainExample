//
//  ViewController.m
//  KeychainExample
//
//  Created by 임정운 on 2021/06/09.
//

#import "ViewController.h"

#import "KeychainSetter.h"
#import "PBKDF2Crypt.h"

#import "KeyStore.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    NSString *pinCode = [NSString stringWithFormat:@"000000"];
    //int, NSNumber과 같은 기본 포맷으로 받는다면 접근제어자로 변환하면 된다.
    NSString *masterKey = [NSString stringWithFormat:@"This_is_Master_Key"];
    
    NSData *saltData = [PBKDF2Crypt secRandom8BytesSalt];
    NSString *saltWithBase64 = [saltData base64EncodedStringWithOptions:0];
    
    NSData *derivedKey = [PBKDF2Crypt encryptPBKDF2:pinCode inSalt:saltData];
    //pin을 이용해 암호화 할 key를 생성.
    
    NSData *masterKeyCipher = [PBKDF2Crypt encryptAES128:masterKey inKey:derivedKey];
    NSString *masterKeyWithBase64 = [masterKeyCipher base64EncodedStringWithOptions:0];
    
    NSString *saltAndMasterKey = [[NSString alloc] initWithFormat:@"%@%@",saltWithBase64 ,masterKeyWithBase64];
//    이런식으로 데이터를 합쳐두는지는 모르겠다.
    
    NSLog(@"saltAndAsterKey_Cipher__%@", saltAndMasterKey);
     
    
    [KeyStore createRandomKeyPairWithTag:@"a"];
    
    CFDataRef keychainCipher = [KeyStore encryptWithTag:@"a" inPlainText:saltAndMasterKey];
    NSLog(@"Encryption_Result__%@", keychainCipher);
    
    NSString *keychainDecryption = [KeyStore decryptWithTag:@"a" inCipher:keychainCipher];
    NSLog(@"Decryption_Result__%@", keychainDecryption);
    
    [KeyStore deleteAllKeychainItems];
}

@end
