#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include "../AvnApi/AvnApi.h"

static AVN_API AvnApi = {};

AVN_EXPORT PAVN_API Stub = &AvnApi;

