//
//  Demangler.h
//  MyApp
//
//  Created by Noah Martin on 7/19/21.
//  Copyright © 2021 Tom Doron. All rights reserved.
//

#import <Foundation/Foundation.h>

#ifndef Demangler_h
#define Demangler_h

#ifdef __cplusplus
extern "C++" {
  #include <memory>
  std::shared_ptr<char> cppDemangle(const char *abiName);
}
#endif

@interface Demangler : NSObject
+ (NSString*)demangle:(NSString*)input;
@end

#endif /* Demangler_h */
