#pragma once

#ifdef FEATURE_APC_FILTER
namespace ApcFilter {
    BOOL EnableApcFilter();
    VOID DisableApcFilter();
}
#endif