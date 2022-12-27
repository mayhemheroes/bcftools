#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
extern "C" {
    #include "vcmp.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    char* ref1 = strdup(provider.ConsumeRandomLengthString(1000).c_str());
    char* ref2 = strdup(provider.ConsumeRemainingBytesAsString().c_str());
    vcmp_t* vcmp = vcmp_init();

    vcmp_set_ref(vcmp, ref1, ref2);

    vcmp_destroy(vcmp);
    free(ref1);
    free(ref2);
    return 0;
}
