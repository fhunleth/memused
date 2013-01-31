# memused

This program scans /proc/\*/maps to account for all virtual memory mappings. The goal is to help determine
the worst case physical memory that could be used by not double counting shared text and data
areas. It also can help identify processes that map unexpectantly large amounts of virtual
memory. However, the stats should be taken with a grain of salt. While I've found this more
useful than ps, it certainly has its flaws
