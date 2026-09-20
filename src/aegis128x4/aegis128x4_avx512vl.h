#ifndef aegis128x4_avx512vl_H
#define aegis128x4_avx512vl_H

#include "../common/common.h"
#include "implementations.h"

#ifdef HAVE_VAESINTRIN_H
extern struct aegis128x4_implementation aegis128x4_avx512vl_implementation;
#endif

#endif