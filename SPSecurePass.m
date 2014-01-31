// Copyright (c) 2014 Loop - Engenharia da Computação LTDA

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//  SPSecurePass.m
//  Created by Daniel Sandoval on 1/28/14.

#import "SPSecurePass.h"
#import <CommonCrypto/CommonKeyDerivation.h>
#import <Security/Security.h>

NSUInteger const kLKSaltLength = 14;
NSUInteger const kLKDerivedKeyLength = 50;

@implementation SPSecurePass

+ (NSData*)storingPasswordData:(NSString*)password iterationsAndSaltData:(NSData*)iterSaltData {
    NSData* salt;
    uint32_t iterations;
    
    if ([iterSaltData length] != kLKSaltLength + sizeof(uint32_t))
        return nil;
    
    iterations = *(uint32_t*)[iterSaltData bytes];
    salt = [iterSaltData subdataWithRange:NSMakeRange(1, kLKSaltLength)];
    return [SPSecurePass storingPasswordData:password salt:salt iterations:iterations];
}

+ (NSData*)storingPasswordData:(NSString*)password salt:(NSData*)salt iterations:(uint32_t)iter {
    NSData* passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t derivedKey[kLKDerivedKeyLength];
    NSMutableData* result = [[NSMutableData alloc] init];
    int errorCheck;
    
    errorCheck = CCKeyDerivationPBKDF(kCCPBKDF2, [passwordData bytes], [passwordData length],
                         [salt bytes], [salt length], kCCPRFHmacAlgSHA256, iter, derivedKey, sizeof(derivedKey));
    
    if (errorCheck != 0) {
        NSLog(@"CCKeyDerivation error: %d", errorCheck);
        return nil;
    }
    
    [result appendBytes:&iter length:sizeof(iter)];
    [result appendData:salt];
    [result appendBytes:derivedKey length:sizeof(derivedKey)];
    
    return [result copy];
}

+ (NSData*)storingPasswordData:(NSString*)password {
    uint8_t salt[kLKSaltLength];
    uint32_t iterations = CCCalibratePBKDF(kCCPBKDF2, [[password dataUsingEncoding:NSUTF8StringEncoding] length],
                                       sizeof(salt), kCCPRFHmacAlgSHA256, kLKDerivedKeyLength, 200);
    
    SecRandomCopyBytes(kSecRandomDefault, kLKSaltLength, salt);
    
    return [SPSecurePass storingPasswordData:password salt:[NSData dataWithBytes:salt length:sizeof(salt)] iterations:iterations];
}

@end
