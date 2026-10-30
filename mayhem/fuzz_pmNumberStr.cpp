#include <stdint.h>
#include <stdio.h>
#include <limits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" const char * pmNumberStr(double value);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    double value = provider.ConsumeFloatingPoint<double>();

    pmNumberStr(value);

    return 0;
}