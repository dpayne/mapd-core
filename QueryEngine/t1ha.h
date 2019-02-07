#ifndef QUERYENGINE_T1HA_H
#define QUERYENGINE_T1HA_H

#include <stdlib.h>
#include "../Shared/funcannotations.h"

extern "C" NEVER_INLINE DEVICE  uint64_t t1ha(const void *data, size_t len, uint64_t seed);

#endif
