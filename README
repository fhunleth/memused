# memused

This program scans /proc/\*/maps to account for all virtual memory mappings. The
goal is to help determine the worst case physical memory that could be used by
not double counting shared text and data areas. It also can help identify
processes that map unexpectantly large amounts of virtual memory. However, the
stats should be taken with a grain of salt. While I've found this more useful than
ps, it certainly has its flaws too.

# Example output

    Processes sorted by total amount of mapped memory:
    
                    Name    PID  Unique text  Shared text  Unique data  Shared data        Total
           /usr/bin/stim    440      1003520     14786560     47759360       266240     63815680
            /usr/bin/rim    439      2363392     15900672      4730880       339968     23334912
              supervisor    422       180224     15880192      6074368       286720     22421504
           /sbin/syslogd    385            0      2527232       315392        16384      2859008
                     -sh    457        45056      2535424       253952        20480      2854912
                watchdog    391            0      2527232       249856        16384      2793472
             /sbin/klogd    387            0      2527232       249856        16384      2793472
                    init      1            0      2527232       249856        16384      2793472
    
    Mapped files sorted by size privately or uniquely mapped:
    
                    Name  Unique text  Shared text  Unique data  Shared data        Total
               /dev/cmem            0            0     46166016            0     46166016
           /usr/bin/stim       937984            0         4096         4096       946176
            /usr/bin/rim       741376            0         8192            0       749568
    /lib/libqwt.so.6.0.2       671744            0            0        16384       688128
    b/libasound.so.2.0.0       585728            0            0        16384       602112
     /usr/bin/supervisor       180224            0         4096            0       184320
    /lib/liblua.so.5.1.5       147456            0            0         4096       151552
    tMultimedia.so.4.8.1       147456            0            0         4096       151552
    ibrimscript.so.1.0.0       131072            0            0         4096       135168
    lib/libdmtx.so.0.0.0        94208            0            0         4096        98304
    libnss_files-2.13.so        69632         4096            0         4096        77824
    lib/libstub.so.1.0.0        69632            0            0         4096        73728
           /SYSV414e4547            0            0        65536            0        65536
    ibrffcharts.so.1.0.0        45056            0            0         4096        49152
           /SYSV4956444a            0            0         4096            0         4096
           /SYSV50434958            0            0         4096            0         4096
           /SYSV50434959            0            0         4096            0         4096
           /SYSV4d43544f            0            0         4096            0         4096
           /SYSV4d435450            0            0         4096            0         4096
    ib/libQtGui.so.4.8.1            0      7135232            0       126976      7262208
    b/libQtCore.so.4.8.1            0      2920448            0        36864      2957312
       /lib/libc-2.13.so            0      1327104            0         4096      1331200
                /dev/fb0            0            0            0       921600       921600
    /libstdc++.so.6.0.16            0       823296            0         8192       831488
       /lib/libm-2.13.so            0       667648            0         4096       671744
    /libQxtCore.so.0.6.2            0       532480            0        20480       552960
    ibQtNetwork.so.4.8.1            0       528384            0        12288       540672
            /bin/busybox            0       434176            0         4096       438272
    geformats/libqmng.so            0       335872            0         8192       344064
           /SYSV00000000            0            0            0       307200       307200
    /lib/librff.so.1.0.0            0       237568            0        12288       249856
    lib/libjpeg.so.8.4.0            0       208896            0         4096       212992
    s/DroidSans-Bold.ttf            0       196608            0            0       196608
    /fonts/DroidSans.ttf            0       192512            0            0       192512
      /lib/libgcc_s.so.1            0       155648            0         4096       159744
    /libpng14.so.14.11.0            0       143360            0         4096       147456
         /lib/ld-2.13.so            0       131072            0         4096       135168
    b/libpthread-2.13.so            0       110592            0         4096       114688
    ibrim-utils.so.1.0.0            0        98304            0         4096       102400
    sr/lib/libz.so.1.2.6            0        98304            0         4096       102400
      /lib/librt-2.13.so            0        53248            0         4096        57344
    eformats/libqjpeg.so            0        49152            0         4096        53248
      /lib/libdl-2.13.so            0        40960            0         4096        45056
           /SYSV00000000            0            0            0         4096         4096
                /dev/mem            0            0            0         4096         4096

    Summary
    Total amount of unique read-only/text data: 3592192 bytes
    Total amount of shared read-only/text data: 16633856 bytes
    Total amount of private or singly mapped writable data: 59883520 bytes
    Total amount of shared writable data: 1593344 bytes
    Sum total of mapped memory: 81702912 bytes


