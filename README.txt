Foundations of Computer Networks (CSCI 651)
Project 1 : Packet Analyzer
Author    : Pavan Prabhakar Bhat (pxb8715@rit.edu)
----------------------------------------------------------------------------------

Files in this directory:

pktanalyzer.java      :  The file to modify for the assignment.
new_tcp_packet1.bin   :  Binary file defining the captured packets containing an ethernet frame with an IP datagram and a TCP packet.
new_udp_packet1.bin   :  Binary file defining the captured packets containing an ethernet frame with an IP datagram and an UDP packet.
new_icmp_packet2.bin  :  Binary file defining the captured packets containing an ethernet frame with an IP datagram and an ICMP packet.
pktanalyzer           :  Automated test script. Runs pktanalyzer.java with defined arguments.
                 

You should modify the argument on the command line when testing your program.

Making 'pktanalyzer' executable on the CS computers (i.e. in Unix/Linux):

  1. Go to the directory containing the code for Project 1.
  2. Issue the following command:

        chmod u+x pktanalyzer
     
     This will make 'pktanalyzer' executable for you, the 'user'. 
	 
     Running this command tells Linux to look for the "#!/bin/bash" command at
     the top of the file, which runs 'bash' shell and then treats the rest of
     the file as input to the shell, and then exits when this ‘shell script’ ends.
    
Example command: (Make sure that the required bin file is in the same directory as the pktanalyzer.java file and the bash file)

    ./pktanalyzer new_tcp_packet1.bin
    
This script would automatically compile the pktanalyzer.java file and run the pktanalyzer program.

