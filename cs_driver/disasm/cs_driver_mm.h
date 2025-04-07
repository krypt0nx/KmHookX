#ifndef CAPSTONE_CS_DRIVER_MM_H_
#define CAPSTONE_CS_DRIVER_MM_H_
#define NTDDI_VERSION NTDDI_WIN10
#define _WIN32_WINNT _WIN32_WINNT_WIN10

#ifdef __cplusplus
extern "C" {
	int __isa_inverted = 0;
	int __avx10_version = 0;
#endif

#include <capstone.h>

	/*
	 Initializes Capstone dynamic memory management for Windows drivers

	 @return: CS_ERR_OK on success, or other value on failure.
	 Refer to cs_err enum for detailed error.

	 NOTE: cs_driver_init() can be called at IRQL <= DISPATCH_LEVEL.
	*/
	cs_err CAPSTONE_API cs_driver_mm_init();

#ifdef __cplusplus
}
#endif

#endif  // CAPSTONE_CS_DRIVER_MM_H_
