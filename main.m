//
//  main.m
//  KapiTest7P
//
//  Created by kapi on 3/28/19.
//  Copyright © 2019 kapi. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"
#import <Foundation/Foundation.h>
#import "AesGcm/Classes/IAGAesGcm.h"
#import <CommonCrypto/CommonCrypto.h>

@interface NSDataHelper:NSObject

/* method declaration */
- (NSData *)hexStringToNSData:(NSString *)hexString;

@end

@implementation NSDataHelper
- (NSData *)hexStringToNSData:(NSString *)hexString{
    hexString = [hexString stringByReplacingOccurrencesOfString:@" " withString:@""];
    NSMutableData *mutaData= [[NSMutableData alloc] init];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    int i;
    for (i=0; i < [hexString length]/2; i++) {
        byte_chars[0] = [hexString characterAtIndex:i*2];
        byte_chars[1] = [hexString characterAtIndex:i*2+1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [mutaData appendBytes:&whole_byte length:1];
    }
    
    NSData* cipherData = mutaData;
    return cipherData;
}
@end

int main(int argc, char * argv[]) {
    
    @autoreleasepool {
        // Define an Encryption Key
        u_char keyBytes[kCCKeySizeAES128] = {0x7a,0x4b,0x7a,0x78,0x47,0x6d,0x58,0x51,0x37,0x66,0x33,0x37,0x30,0x62,0x64,0x64};
        NSData *key = [NSData dataWithBytes:keyBytes length:sizeof(keyBytes)];
        
        // Define an Initialization Vector
        // GCM recommends a IV size of 96 bits (12 bytes), but you are free to use other sizes
        u_char ivBytes[12] = {0x36,0x62,0x38,0x65,0x34,0x66,0x36,0x38,0x51,0x55,0x50,0x34};
        NSData *iv = [NSData dataWithBytes:ivBytes length:sizeof(ivBytes)];
        
        // Define an Additional Authenticated Data
        NSData *aad = [@"ABCDEFGHIJKL" dataUsingEncoding:NSUTF8StringEncoding];
        
        // Now, we are ready to encrypt some plain data
        NSString *plainText = @"this is the test text";
        NSLog(@"Plain Text: %@", plainText);
        NSData *expectedPlainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
        
        // The returned ciphered data is a simple class with 2 properties: the actual encrypted data and the authentication tag.
        // The authentication tag can have multiple sizes and it is up to you to set one, in this case the size is 128 bits
        // (16 bytes)
        IAGCipheredData *cipheredData = [IAGAesGcm cipheredDataByAuthenticatedEncryptingPlainData:expectedPlainData
                                                                  withAdditionalAuthenticatedData:aad
                                                                          authenticationTagLength:IAGAuthenticationTagLength128
                                                                             initializationVector:iv
                                                                                              key:key
                                                                                            error:nil];
        
        
        
        // Decrypt the encrypted message using hex string of cipher and its tag
        NSDataHelper *helper = [[NSDataHelper alloc]init];
        NSData* cipherNSDataFromHexString = [helper hexStringToNSData:[cipheredData getCipheredData]];
        NSData* tagDataFromHexString = [helper hexStringToNSData:[cipheredData getTag]];
        
        // And now, de-cypher the encrypted data to see if the returned plain data is as expected
        IAGCipheredData *ciepherDataFromHexString = [[IAGCipheredData alloc] initWithCipheredData:cipherNSDataFromHexString
                                                                                authenticationTag:tagDataFromHexString];
        
        
        // And now, de-cypher the encrypted data to see if the returned plain data is as expected
        NSData *plainData = [IAGAesGcm plainDataByAuthenticatedDecryptingCipheredData:ciepherDataFromHexString
                                                      withAdditionalAuthenticatedData:aad
                                                                 initializationVector:iv
                                                                                  key:key
                                                                                error:nil];
        
        NSString* decryptedText = [[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding];
        NSLog(@"Cipher Text (Hex): %@", [cipheredData getCipheredData]);
        NSLog(@"Tag (Hex): %@", [cipheredData getTag]);
        NSLog(@"Decrypted Text: %@", decryptedText);
        
        // Plain Text: this is the test text
        // Cipher Text (Hex): 382E86E8756828D1DE17B5BA885B34F9E0A8F94EA6
        // Tag (Hex): 56C77699EA6182D3C227DBE0DFF3B19B
        // Decrypted Text: this is the test text

        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}





