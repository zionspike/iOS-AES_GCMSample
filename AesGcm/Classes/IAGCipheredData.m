//
//  IAGCipheredData.m
//  Pods
//
//  Created by Enrique de la Torre (dev) on 17/09/2016.
//
//

#import "IAGCipheredData.h"

static NSString *const kCoderKeyAuthenticationTagData = @"authenticationTagData";
static NSString *const kCoderKeyCipheredData = @"cipheredData";

@interface IAGCipheredData ()

@property (nonatomic) NSData *cipheredData;
@property (nonatomic) NSData *authenticationTagData;

@end

@implementation IAGCipheredData

#pragma mark - Synthesize properties

- (const void *)cipheredBuffer
{
    return self.cipheredData.bytes;
}

- (NSUInteger)cipheredBufferLength
{
    return self.cipheredData.length;
}

- (const void *)authenticationTag
{
    return self.authenticationTagData.bytes;
}

- (IAGAuthenticationTagLength)authenticationTagLength
{
    return self.authenticationTagData.length;
}

#pragma mark - NSSecureCoding class synthesize properties

+ (BOOL)supportsSecureCoding
{
    return YES;
}



- (NSString *)getCipheredData
{
//    return [NSString stringWithFormat:@"%@", self.cipheredData];
    
    NSData *data = self.cipheredData;
    // get the length of the hexstring
    // data.lenght returns the lenght in bytes, so we *2 to get as hexstring
    NSUInteger capacity = data.length * 2;
    // Create a new NSMutableString with the correct lenght
    NSMutableString *mutableString = [NSMutableString stringWithCapacity:capacity];
    // get the bytes of data to be able to loop through it
    const unsigned char *buf = (const unsigned char*) [data bytes];
    
    NSInteger t;
    for (t=0; t<data.length; ++t) {
        [mutableString appendFormat:@"%02X", (NSUInteger)buf[t]];
    }
    // save as NSString
    NSString * hexstring = mutableString;
    return hexstring;
}
    

- (NSString *)getTag
{
//    return [NSString stringWithFormat:@"%@", self.authenticationTagData];
    
    NSData *data = self.authenticationTagData;
    // get the length of the hexstring
    // data.lenght returns the lenght in bytes, so we *2 to get as hexstring
    NSUInteger capacity = data.length * 2;
    // Create a new NSMutableString with the correct lenght
    NSMutableString *mutableString = [NSMutableString stringWithCapacity:capacity];
    // get the bytes of data to be able to loop through it
    const unsigned char *buf = (const unsigned char*) [data bytes];
    
    NSInteger t;
    for (t=0; t<data.length; ++t) {
        [mutableString appendFormat:@"%02X", (NSUInteger)buf[t]];
    }
    // save as NSString
    NSString * hexstring = mutableString;
    return hexstring;
}


#pragma mark - NSObject methods

- (NSString *)description
{
    return [NSString stringWithFormat:@"Ciphertext: %@. Auth tag: %@",
            self.cipheredData, self.authenticationTagData];
}

#pragma mark - Init object

- (instancetype)initWithCipheredData:(NSData *)cipheredData
                   authenticationTag:(NSData *)authenticationTag {
    BOOL isAuthenticationTagLengthValid = ((IAGAuthenticationTagLength96 == authenticationTag.length) ||
                                           (IAGAuthenticationTagLength104 == authenticationTag.length) ||
                                           (IAGAuthenticationTagLength112 == authenticationTag.length) ||
                                           (IAGAuthenticationTagLength120 == authenticationTag.length) ||
                                           (IAGAuthenticationTagLength128 == authenticationTag.length));
    if (!isAuthenticationTagLengthValid)
    {
        return nil;
    }

    return [self initWithCipheredBuffer:cipheredData.bytes
                   cipheredBufferLength:cipheredData.length
                      authenticationTag:authenticationTag.bytes
                authenticationTagLength:(IAGAuthenticationTagLength)authenticationTag.length];
}

- (instancetype)initWithCipheredBuffer:(const void *)cipheredBuffer
                  cipheredBufferLength:(NSUInteger)cipheredBufferLength
                     authenticationTag:(const void *)authenticationTag
               authenticationTagLength:(IAGAuthenticationTagLength)authenticationTagLength
{
    self = [super init];

    if (self)
    {
        _cipheredData = [NSData dataWithBytes:cipheredBuffer length:cipheredBufferLength];
        _authenticationTagData = [NSData dataWithBytes:authenticationTag
                                                length:authenticationTagLength];
    }

    return self;
}

#pragma mark - NSCoding init methods

- (instancetype)initWithCoder:(NSCoder *)aDecoder {
    NSData *cipheredData = [aDecoder decodeObjectOfClass:[NSData class]
                                                  forKey:kCoderKeyCipheredData];
    NSData *authenticationTag = [aDecoder decodeObjectOfClass:[NSData class]
                                                       forKey:kCoderKeyAuthenticationTagData];
    if (!cipheredData || !authenticationTag)
    {
        return nil;
    }

    return [self initWithCipheredData:cipheredData authenticationTag:authenticationTag];
}

#pragma mark - Equality

- (NSUInteger)hash
{
    return self.cipheredData.hash;
}

- (BOOL)isEqual:(id)object
{
    if ([self class] == [object class])
    {
        return [self isEqualToCipheredData:object];
    }

    return [super isEqual:object];
}

- (BOOL)isEqualToCipheredData:(IAGCipheredData *)object
{
    if (self == object)
    {
        return YES;
    }

    return ([self.cipheredData isEqualToData:object.cipheredData] &&
            [self.authenticationTagData isEqualToData:object.authenticationTagData]);
}

#pragma mark - NSCoding methods

- (void)encodeWithCoder:(NSCoder *)aCoder {
    [aCoder encodeObject:self.cipheredData forKey:kCoderKeyCipheredData];
    [aCoder encodeObject:self.authenticationTagData forKey:kCoderKeyAuthenticationTagData];
}

@end
