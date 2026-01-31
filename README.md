# siftr2_reader.py  
A lightweight Python 3 script that mirrors the core behavior of review_siftr2_log.c.  
  
run examples:  
  
% du -h siftr2.log  
766M    siftr2.log  
  
% ./siftr2_reader.py -f siftr2.log     
input file name: siftr2.log  
siftr version: 2.5  
flow id list:  
 id:947fbda1 IPv4 (10.1.1.1:54321<->10.1.1.2:5201) stack:freebsd tcp_cc:cubic mss:1448 SACK:1 snd/rcv_scal:8/8 cnt:7773063/7773063  
  
starting_time: 2026-01-22 12:25:26.132319 (1769102726.132319)  
ending_time:   2026-01-22 12:27:06.170838 (1769102826.170838)  
log duration: 100.04 seconds  
  
this program execution time: 0.006 seconds  
  
% ./siftr2_reader.py -f siftr2.log -s 947fbda1  
input file name: siftr2.log  
siftr version: 2.5  
flow id list:  
 id:947fbda1 IPv4 (10.1.1.1:54321<->10.1.1.2:5201) stack:freebsd tcp_cc:cubic mss:1448 SACK:1 snd/rcv_scal:8/8 cnt:7773063/7773063  
  
starting_time: 2026-01-22 12:25:26.132319 (1769102726.132319)  
ending_time:   2026-01-22 12:27:06.170838 (1769102826.170838)  
log duration: 100.04 seconds  
input flow id is: 947fbda1  
input file has total lines: 7773065  
plot_file_name: plot_947fbda1.data  
++++++++++++++++++++++++++++++ summary ++++++++++++++++++++++++++++  
  10.1.1.1:54321->10.1.1.2:5201 flowid: 947fbda1  
input flow data_pkt_cnt: 3708579, fragment_cnt: 2, fragment_ratio: 0.000  
           avg_payload: 3173, min_payload: 37, max_payload: 13032 bytes  
           avg_srtt: 14423, min_srtt: 218, max_srtt: 16000 µs  
           avg_cwnd: 1683218, min_cwnd: 14480, max_cwnd: 1684053 bytes  
           has 7773063 useful records (3708582 outputs, 4064481 inputs)  
  
this program execution time: 42.540 seconds  
%  
  
% du -h plot_947fbda1.data   
320M    plot_947fbda1.data  
  
Above example shows the program can process 7.7 million records in 42.54 seconds,  
which is around 183K records per-second.  
  
% pypy3 siftr2_reader.py -f siftr2.100s.log -s 947fbda1  
siftr version: 2.5  
flow id list:  
 id:947fbda1 IPv4 (10.1.1.1:54321<->10.1.1.2:5201) stack:freebsd tcp_cc:cubic mss:1448 SACK:1 snd/rcv_scal:8/8 cnt:7773063/7773063  
  
starting_time: 2026-01-22 12:25:26.132319 (1769102726.132319)  
ending_time:   2026-01-22 12:27:06.170838 (1769102826.170838)  
log duration: 100.04 seconds  
input flow id is: 947fbda1  
input file has total lines: 7773065  
plot_file_name: plot_947fbda1.data  
++++++++++++++++++++++++++++++ summary ++++++++++++++++++++++++++++  
  10.1.1.1:54321->10.1.1.2:5201 flowid: 947fbda1  
input flow data_pkt_cnt: 3708579, fragment_cnt: 2, fragment_ratio: 0.000  
           avg_payload: 3173, min_payload: 37, max_payload: 13032 bytes  
           avg_srtt: 14423, min_srtt: 218, max_srtt: 16000 µs  
           avg_cwnd: 1683218, min_cwnd: 14480, max_cwnd: 1684053 bytes  
           has 7773063 useful records (3708582 outputs, 4064481 inputs)  
  
this program execution time: 13.367 seconds  
%  
  
Use PyPy3, the execution time is further reduced, and handles data around 580K  
records per-second.  
  