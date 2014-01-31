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

//  SPSecurePass.h
//  Created by Daniel Sandoval on 1/28/14.

#import <Foundation/Foundation.h>

@interface SPSecurePass : NSObject

//The functions storingPasswordData: provide easy functionality for transforming a clear text password
//into the string stored into the database. The key derivation algorithm PBKDF2 is used.
//The algorithm requires as input the password, a salt, and the number of iterations it should execute.
//All functions return a NSData blob in the format:
// <little endian 4 bytes number of iterations> || <14 bytes salt data> || <50 bytes derived key>

//Generates salt randomly and uses a number of iterations that yields 200 miliseconds of processing.
+ (NSData*)storingPasswordData:(NSString*)password;

//Expects iterations and salt data in the format:
// <little endian 4 bytes number of iterations> || <14 bytes salt data>
+ (NSData*)storingPasswordData:(NSString*)password iterationsAndSaltData:(NSData*)iterSaltData;

+ (NSData*)storingPasswordData:(NSString*)password salt:(NSData*)salt iterations:(uint32_t)iter;


@end
