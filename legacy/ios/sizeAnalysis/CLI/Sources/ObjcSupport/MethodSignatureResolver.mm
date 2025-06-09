//
//  MethodSignatureResolver.m
//  AssetAnalyzer
//
//  Created by Noah Martin on 1/11/21.
//  Copyright © 2021 Tom Doron. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "MethodSignatureResolver.h"

@implementation MethodSignatureResolver

+ (BOOL)checkMethodSignature:(NSString *)input {
  if ([input containsString:@"\n"]) {
    return false;
  }

  @try {
    NSMethodSignature *sig = [NSMethodSignature signatureWithObjCTypes:[input cStringUsingEncoding:NSASCIIStringEncoding]];
    return sig != nil;
  } @catch (NSException *exception) {
    return false;
  }
  return false;
}

@end
