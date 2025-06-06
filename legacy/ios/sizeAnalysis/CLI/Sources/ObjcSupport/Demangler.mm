//
//  Demangler.m
//  AssetAnalyzer
//
//  Created by Noah Martin on 7/19/21.
//  Copyright © 2021 Tom Doron. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Demangler.h"

@implementation Demangler

+ (NSString*)demangle:(NSString *)input {
  std::shared_ptr<char> result = cppDemangle(input.UTF8String);
  if (result != NULL) {
    return [NSString stringWithUTF8String:result.get()];
  } else {
    return @"";
  }
}

@end
