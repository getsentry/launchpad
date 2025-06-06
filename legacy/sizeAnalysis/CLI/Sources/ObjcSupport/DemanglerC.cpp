//
//  DemanglerC.cpp
//  AssetAnalyzer
//
//  Created by Noah Martin on 7/19/21.
//  Copyright © 2021 Tom Doron. All rights reserved.
//

#include <cxxabi.h>  // needed for abi::__cxa_demangle
#include <memory>

std::shared_ptr<char> cppDemangle(const char *abiName)
{
  int status;
  char *ret = abi::__cxa_demangle(abiName, 0, 0, &status);

  /* NOTE: must free() the returned char when done with it! */
  std::shared_ptr<char> retval;
  retval.reset( (char *)ret, [](char *mem) { if (mem) free((void*)mem); } );
  return retval;
}