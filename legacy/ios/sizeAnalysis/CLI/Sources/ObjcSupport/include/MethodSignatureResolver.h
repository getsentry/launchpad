//
//  MethodSignatureResolver.h
//  MyApp
//
//  Created by Noah Martin on 1/11/21.
//  Copyright © 2021 Tom Doron. All rights reserved.
//

#import <Foundation/Foundation.h>

#ifndef MethodSignatureResolver_h
#define MethodSignatureResolver_h

@interface MethodSignatureResolver : NSObject

+ (BOOL)checkMethodSignature:(NSString* _Nonnull)input;

@end

#endif /* MethodSignatureResolver_h */
