//
//  safeValueForKey.m
//  AppSizeAnalyzer
//
//  Created by Itay Brenner on 29/4/25.
//

#import <Foundation/Foundation.h>
#import "SafeValueForKey.h"

// Helper to call `valueForKey` without swift crashing
id safeValueForKey(id object, NSString *key) {
  @try {
    return [object valueForKey:key];
  } @catch (NSException *exception) {
    return nil;
  }
}
