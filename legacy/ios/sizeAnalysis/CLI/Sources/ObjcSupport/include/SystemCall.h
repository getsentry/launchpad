//
//  System.c.h
//  
//
//  Created by Noah Martin on 2/7/23.
//

#ifndef System_c_h
#define System_c_h

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// system(3) isn't allowed in Swift, so use this shim to call it anyways, rather than Apple's terrible process APIs
int nonRestrictedSystem(const char *);

#ifdef __cplusplus
}
#endif

#endif /* System_c_h */
