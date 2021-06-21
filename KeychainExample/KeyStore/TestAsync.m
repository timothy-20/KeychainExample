//
//  TestAsync.m
//  KeychainExample
//
//  Created by 임정운 on 2021/06/21.
//

#import "TestAsync.h"

@implementation TestAsync

-(void)sendToError:(NSString **)error
{
    *error = @"love YA!";
}

-(void)receiveError
{
    NSString *errorMessage = nil;
    [self sendToError:&errorMessage];
    
    NSLog(@"Error_Ocurred__%@", errorMessage);
}

@end
