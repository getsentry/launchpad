//
//  System.c.c
//  
//
//  Created by Noah Martin on 2/7/23.
//

#include <stdlib.h>
#include "SystemCall.h"

int nonRestrictedSystem(const char *cmd) {
  return system(cmd);
}
