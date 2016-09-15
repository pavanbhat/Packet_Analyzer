/***
 * Project 1: Develop a packet analyzer
 * Due date: Wed., Sep. 14th, 11:59pm
 * 
 * Project Description: 
 * 
 * Analyzing the Captured Packets
 * Write an application that reads a set of packets and produces a detailed summary of those packets. 
 * Your packet analyzer should run as a shell command. The syntax of the command is the following: % pktanalyzer datafile
 * The pktanalyzer program will extract and display the different headers of the captured packets in the file datafile. 
 * First, it displays the Ethernet header fields of the captured frames. 
 * Second, if the Ethernet frame contains an IP Datagram, it prints the IP header. 
 * Third, it prints the packets encapsulated in the IP Datagram. TCP, UDP, or ICMP packets can be encapsulated in the IP packet.
 * 
 * Author: Pavan Prabhakar Bhat (pxb8715@rit.edu)
 * 
 */
// All imports here
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class pktanalyzer {

	// Contains the Hex version of the Ethernet packet
	String ethernet[] = new String[7];
	// Contains the Hex version of the IP packet
	String ip[];
	// Contains the entire data in Hex
	String hexPacket[];
	// Total length of the packet
	int totalPacketLength = 0;

	/**
	 * Main method that begins the program with initializing all the inputs,
	 * analyzing all the packets and displaying them.
	 * 
	 * @param args
	 *            args[0] is the path of the binary file which contains
	 *            information on the packets
	 * 
	 */
	public static void main(String[] args) {
		// Object of the class
		pktanalyzer pkt = new pktanalyzer();
		// Reads the binary file as input
		int count = pkt.getInput(args[0]);

		// Reads, analyzes and displays the Ethernet packet
		String nextPacket = pkt.displayEthernetPacket();

		// Reads, analyzes and displays the IP packet
		if (nextPacket.equalsIgnoreCase("0800")) {
			pkt.displayIpPacket(count);
		} else {
			System.out.println("Protocol not listed!");
		}

	}

	/**
	 * Takes the command line argument (binary file) and stores it as a Hex
	 * string array
	 * 
	 * @param file
	 *            Command line argument - Binary input file
	 * @return Returns the next index of the hex packet
	 */
	private int getInput(String file) {

		// Takes the file path as the input
		File name = new File(file);
		FileInputStream in;
		int read;
		int i = 0, counter = 0;
		// Reads the length of the file and assigns it to the totalPacketLength
		totalPacketLength = (int) (name.length());
		hexPacket = new String[totalPacketLength];
		// Stores the hex bytes in a String array named hexPacket
		try {
			in = new FileInputStream(name);

			while ((read = in.read()) != -1) {
				if (counter == 0) {
					hexPacket[i] = "";
				}
				if (Integer.toHexString(read).length() == 2) {
					hexPacket[i] += Integer.toHexString(read);
				} else {
					hexPacket[i] += "0" + Integer.toHexString(read);
				}

				counter++;
				if (counter == 2) {
					counter = 0;
					i++;
				}
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		// Stores the Ethernet packet from the hexPacket
		int count = 0;
		while (count < 7) {
			ethernet[count] = hexPacket[count];
			count++;
		}
		return count;

	}

	/**
	 * Analyzes and displays the Ethernet packet header
	 * 
	 * @return Returns the protocol string to the main program to continue with
	 *         the next header
	 */
	private String displayEthernetPacket() {
		// Displays the information from the Ethernet header byte by byte
		System.out.println("ETHER:  ----- Ether Header -----");
		System.out.println("ETHER: ");
		System.out.println("ETHER:  Packet size = " + (totalPacketLength) + " bytes");
		System.out.println("ETHER:  Destination = " + ethernet[0].substring(0, 2) + ":" + ethernet[0].substring(2) + ":"
				+ ethernet[1].substring(0, 2) + ":" + ethernet[1].substring(2) + ":" + ethernet[2].substring(0, 2) + ":"
				+ ethernet[2].substring(2));
		System.out.println("ETHER:  Source      = " + ethernet[3].substring(0, 2) + ":" + ethernet[3].substring(2) + ":"
				+ ethernet[4].substring(0, 2) + ":" + ethernet[4].substring(2) + ":" + ethernet[5].substring(0, 2) + ":"
				+ ethernet[5].substring(2));
		System.out.println("ETHER:  Ethertype   = " + ethernet[6] + " (IP)");
		System.out.println("ETHER:");
		return ethernet[6];
	}

	/**
	 * Reads, Analyzes and Displays the IP header
	 * 
	 * @param nextIndex
	 *            Takes the Starting index of the IP header as a parameter
	 */
	private void displayIpPacket(int nextIndex) {

		// Displays the information from the IP header byte by byte
		System.out.println("IP:   ----- IP Header ----- ");
		System.out.println("IP: ");
		String first = hexPacket[nextIndex];
		int firstDecimal = Integer.parseInt(first, 16);
		String firstBinary = Integer.toBinaryString(firstDecimal);
		// Pads the firstBinary bits with zeros as it is lost during binary to integer conversion
		if (firstBinary.length() < 16) {
			int firstBinaryLength = firstBinary.length();
			for (int i = 0; i < (16 - firstBinaryLength); i++) {
				firstBinary = "0" + firstBinary;
			}
		}
		// Version of the IP header
		int version = Integer.parseInt(firstBinary.substring(0, 4), 2);
		System.out.println("IP:   Version = " + version);

		// IP header Length
		int ipHeaderLength = Integer.parseInt(firstBinary.substring(4, 8), 2);
		ipHeaderLength = (4 * ipHeaderLength);
		System.out.println("IP:   Header length   = " + ipHeaderLength + " bytes");

		String type = firstBinary.substring(8, 16);
		String typeOfService = String.format("%02x", Integer.parseInt(type, 16));

		// Type of Service of the IP Header
		System.out.println("IP:   Type of service = " + "0x" + typeOfService);

		// Categorizes the precedence of the type of service
		switch (type.substring(0, 3)) {
		case "000":
			System.out.println("IP:         000. .... = " + Integer.parseInt(type.substring(0, 3), 2)
					+ " (Best Effort or Routine precedence)");
			break;
		case "001":
			System.out.println(
					"IP:         001. .... = " + Integer.parseInt(type.substring(0, 3), 2) + " (Priority precedence)");
			break;
		case "010":
			System.out.println(
					"IP:         010. .... = " + Integer.parseInt(type.substring(0, 3), 2) + " (Immediate precedence)");
			break;
		case "011":
			System.out.println(
					"IP:         011. .... = " + Integer.parseInt(type.substring(0, 3), 2) + " (Flash precedence)");
			break;
		case "100":
			System.out.println("IP:         100. .... = " + Integer.parseInt(type.substring(0, 3), 2)
					+ " (Flash Override precedence)");
			break;
		case "101":
			System.out.println(
					"IP:         101. .... = " + Integer.parseInt(type.substring(0, 3), 2) + " (Critical precedence)");
			break;
		case "110":
			System.out.println("IP:         110. .... = " + Integer.parseInt(type.substring(0, 3), 2)
					+ " (Internetwork control precedence)");
			break;
		case "111":
			System.out.println("IP:         111. .... = " + Integer.parseInt(type.substring(0, 3), 2)
					+ " (Network control precedence)");
			break;
		default:
			// Displayed if no precedence is listed
			System.out.println("IP:         xxx. .... = " + " (IP precedence not listed!)");
			break;
		}
		// Analyzes different information from the type of service 
		if (type.charAt(3) == '0') {
			System.out.println("IP:         ...0 .... = " + "normal delay");
		} else {
			System.out.println("IP:         ...1 .... = " + "low delay");
		}
		if (type.charAt(4) == '0') {
			System.out.println("IP:         .... 0... = " + "normal throughput");
		} else {
			System.out.println("IP:         .... 1... = " + "high throughput");
		}
		if (type.charAt(5) == '0') {
			System.out.println("IP:         .... .0.. = " + "normal reliability");
		} else {
			System.out.println("IP:         .... .1.. = " + "high reliability");
		}

		// Total length of the remaining packet
		int totalLength = Integer.parseInt(hexPacket[nextIndex + 1], 16);
		System.out.println("IP:   Total length = " + totalLength + " bytes");
		int count = 0;

		// Rest of the IP packet
		ip = new String[8];
		while (count < 8) {
			ip[count] = hexPacket[(nextIndex + 2) + count];
			count++;
		}
		// Next index of hexPacket to be passed to the next protocol
		nextIndex = (nextIndex + 2) + count;

		int identification = Integer.parseInt(ip[0], 16);
		System.out.println("IP:   Identification = " + identification);

		String secondBinary = Integer.toBinaryString(Integer.parseInt(ip[1], 16));
		// Pads the secondBinary bits with zeros as it is lost during binary to integer conversion
		if (secondBinary.length() < 16) {
			int secondBinaryLength = secondBinary.length();
			for (int i = 0; i < (16 - secondBinaryLength); i++) {
				secondBinary = "0" + secondBinary;
			}
		}

		String flags = secondBinary.substring(0, 3);
		// Fragmentation options of the flags from the IP header
		System.out.println("IP:   Flags = " + "0x" + Integer.parseInt(flags, 2));
		if (flags.charAt(1) == '0') {
			System.out.println("IP:         .0.. .... = " + "may fragment");
		} else {
			System.out.println("IP:         .1.. .... = " + "do not fragment");
		}
		if (flags.charAt(2) == '0') {
			System.out.println("IP:         ..0. .... = " + "last fragment");
		} else {
			System.out.println("IP:         ..1. .... = " + "More fragments");
		}

		String fragmentOffset = secondBinary.substring(3);
		// Fragmentation offset of the IP header
		if (flags.charAt(1) == '1') {
			System.out.println("IP:   Fragment offset = 0 bytes");
		} else {
			System.out.println("IP:   Fragment offset = " + Integer.parseInt(fragmentOffset, 2) + " bytes");
		}
		// Time to live
		int ttl = Integer.parseInt(ip[2].substring(0, 2), 16);
		System.out.println("IP:   Time to live = " + ttl + " seconds/hops");

		// Check to find the protocol of the remaining packet
		int protocol = 0;
		if (ip[2].substring(2).equalsIgnoreCase("01")) {
			System.out.println("IP:   Protocol = " + 1 + " (ICMP)");
			protocol = 1;
		} else if (ip[2].substring(2).equalsIgnoreCase("06")) {
			System.out.println("IP:   Protocol = " + 6 + " (TCP)");
			protocol = 6;
		} else if (ip[2].substring(2).equalsIgnoreCase("11")) {
			System.out.println("IP:   Protocol = " + 17 + " (UDP)");
			protocol = 17;
		} else {
			System.out.println("IP:   Protocol not listed!");
		}

		// Header Checksum
		System.out.println("IP:   Header checksum = 0x" + ip[3]);

		// Source and Destination IP addresses with their host names
		String sourceIP = Integer.parseInt(ip[4].substring(0, 2), 16) + "." + Integer.parseInt(ip[4].substring(2), 16)
				+ "." + Integer.parseInt(ip[5].substring(0, 2), 16) + "." + Integer.parseInt(ip[5].substring(2), 16);
		;

		String destinationIP = Integer.parseInt(ip[6].substring(0, 2), 16) + "."
				+ Integer.parseInt(ip[6].substring(2), 16) + "." + Integer.parseInt(ip[7].substring(0, 2), 16) + "."
				+ Integer.parseInt(ip[7].substring(2), 16);

		try {
			InetAddress source = InetAddress.getByName(sourceIP);
			System.setProperty("java.net.preferIPv4Stack", "true");

			System.out.print("IP:   Source address      = " + sourceIP + ", " + source.getHostName());
			System.out.println();
		} catch (UnknownHostException e) {
			// Catches the Unknown Host Exception
			System.out.println("IP:   Source address      = " + sourceIP + ", " + " (hostname unknown)");
		}
		try {
			InetAddress destination = InetAddress.getByName(destinationIP);
			System.out.print("IP:   Destination address = " + destinationIP + ", " + destination.getHostName());
			System.out.println();
		} catch (UnknownHostException e) {
			// Catches the Unknown Host Exception
			System.out.println("IP:   Destination address = " + destinationIP + ", " + " (hostname unknown)");
		}

		// Displays whether the IP header has any Options else calls on the next
		// protocol attached
		if (ipHeaderLength == 20) {
			System.out.println("IP:   No options");
			System.out.println("IP:");

			switch (protocol) {
			case 1:
				displayIcmpPacket(nextIndex);
				break;
			case 6:
				displayTcpPacket(nextIndex);
				break;
			case 17:
				displayUdpPacket(nextIndex);
				break;
			default:
				//Displayed if the protocol is neither TCP, UDP or ICMP
				System.out.println("Protocol not listed!");
				break;
			}

		} else if (ipHeaderLength > 20) {
			// If Options exist then will compute the new index and forward it
			// to the next incoming protocol
			System.out.println("IP:   Options (" + (ipHeaderLength - 20) + " bytes)");
			System.out.println("IP:");
			try {
				switch (protocol) {
				case 1:
					displayIcmpPacket(nextIndex + ((ipHeaderLength - 20) / 2));
					break;
				case 6:
					displayTcpPacket(nextIndex + ((ipHeaderLength - 20) / 2));
					break;
				case 17:
					displayUdpPacket(nextIndex + ((ipHeaderLength - 20) / 2));
					break;
				default:
					System.out.println("IP:   Protocol not listed!");
					break;
				}
			} catch (Exception e) {
				// Throws an error if the options packet length prescribed is
				// odd
				System.err.println("The length of the options packet is odd");
			}

		}

	}

	/**
	 * Analyzes and displays the UDP packet
	 * 
	 * @param nextindex
	 *            Takes the Starting index of the UDP header as a parameter
	 */
	private void displayUdpPacket(int nextindex) {
		// Displays the information from the UDP header byte by byte
		System.out.println("UDP:  ----- UDP Header -----");
		System.out.println("UDP:");
		// Source port of the UDP Header
		int sourcePort = Integer.parseInt(hexPacket[nextindex], 16);
		System.out.println("UDP:  Source port = " + sourcePort);
		// Destination port of the UDP header with several options
		int destinationPort = Integer.parseInt(hexPacket[nextindex + 1], 16);
		switch (destinationPort) {
		case 20:
			System.out.println("UDP:  Destination port = " + destinationPort + " (FTP)");
			break;
		case 22:
			System.out.println("UDP:  Destination port = " + destinationPort + " (SSH)");
			break;
		case 53:
			System.out.println("UDP:  Destination port = " + destinationPort + " (DNS)");
			break;
		case 67:
			System.out.println("UDP:  Destination port = " + destinationPort + " (DHCP)");
			break;
		case 80:
			System.out.println("UDP:  Destination port = " + destinationPort + " (HTTP)");
			break;
		case 110:
			System.out.println("UDP:  Destination port = " + destinationPort + " (POP3)");
			break;
		case 143:
			System.out.println("UDP:  Destination port = " + destinationPort + " (IMAP)");
			break;
		case 443:
			System.out.println("UDP:  Destination port = " + destinationPort + " (HTTPS)");
			break;
		case 992:
			System.out.println("UDP:  Destination port = " + destinationPort + " (Telnet)");
			break;
		case 2049:
			System.out.println("UDP:  Destination port = " + destinationPort + " (NFS)");
			break;
		default:
			// if can't find the destination ports listed in above will display
			// that the destination port is not listed
			System.out.println("UDP:  Type of destination port not listed!");
			break;
		}

		// Length of the UDP header
		int length = Integer.parseInt(hexPacket[nextindex + 2], 16);
		System.out.println("UDP:  Length = " + length);

		// Calculates the checksum in Hex
		String checksum = hexPacket[nextindex + 3];
		System.out.println("UDP:  Checksum = 0x" + checksum);
		System.out.println("UDP:");

		// Calculates and analyzes the data and decodes the bytes of data
		// attached to the UDP packet
		int i = 0, counter = 1;
		String[] tempData = new String[(int) Math.ceil((length - 8) / 8)];
		String[] tempDecodedData = new String[(int) Math.ceil((length - 8) / 8)];
		tempData[0] = "";
		tempDecodedData[0] = "";
		// Limited to a decimal range of [33, 126] to consider numbers,
		// alphabets and special characters to the decoding rest all will be
		// replaced with "."
		while (((counter * 2) < length - 8) && hexPacket[nextindex + 3 + counter] != null) {
			if (Integer.parseInt(hexPacket[nextindex + 3 + counter].substring(0, 2), 16) >= 33
					&& Integer.parseInt(hexPacket[nextindex + 3 + counter].substring(0, 2), 16) <= 126) {
				tempDecodedData[i] += Character
						.toString((char) Integer.parseInt(hexPacket[nextindex + 3 + counter].substring(0, 2), 16));
			} else {
				tempDecodedData[i] += ".";
			}
			if (Integer.parseInt(hexPacket[nextindex + 3 + counter].substring(2), 16) >= 33
					&& Integer.parseInt(hexPacket[nextindex + 3 + counter].substring(2), 16) <= 126) {
				tempDecodedData[i] += Character
						.toString((char) Integer.parseInt(hexPacket[nextindex + 3 + counter].substring(2), 16));
			} else {
				tempDecodedData[i] += ".";
			}
			tempData[i] += hexPacket[nextindex + 3 + counter] + " ";

			// Makes sure that there are only 16 bytes printed on a line
			if (counter % 8 == 0) {
				i++;
				tempData[i] = "";
				tempDecodedData[i] = "";
			}
			counter++;
		}
		// Prints the UDP Data
		System.out.println("UDP:  Data: (first " + ((counter - 1) * 2) + " bytes)");
		int j = 0;
		while (tempData[j] != "") {
			System.out.println("UDP:  " + tempData[j] + "    " + "\"" + tempDecodedData[j] + "\"");
			j++;
		}
	}

	/**
	 * Analyzes and displays the TCP packet
	 * 
	 * @param nextIndex
	 *            Takes the Starting index of the TCP header as a parameter
	 */
	private void displayTcpPacket(int nextIndex) {
		System.out.println("TCP:  ----- TCP Header ----- ");
		System.out.println("TCP:");
		int sourcePort = Integer.parseInt(hexPacket[nextIndex], 16);
		// Source port of the TCP header
		System.out.println("TCP:  Source port = " + sourcePort);
		int destinationPort = Integer.parseInt(hexPacket[nextIndex + 1], 16);
		// Displays the destination port to be forwarded to from the TCP header
		switch (destinationPort) {
		case 20:
			System.out.println("TCP:  Destination port = " + destinationPort + " (FTP)");
			break;
		case 22:
			System.out.println("TCP:  Destination port = " + destinationPort + " (SSH)");
			break;
		case 53:
			System.out.println("TCP:  Destination port = " + destinationPort + " (DNS)");
			break;
		case 67:
			System.out.println("TCP:  Destination port = " + destinationPort + " (DHCP)");
			break;
		case 80:
			System.out.println("TCP:  Destination port = " + destinationPort + " (HTTP)");
			break;
		case 110:
			System.out.println("TCP:  Destination port = " + destinationPort + " (POP3)");
			break;
		case 143:
			System.out.println("TCP:  Destination port = " + destinationPort + " (IMAP)");
			break;
		case 443:
			System.out.println("TCP:  Destination port = " + destinationPort + " (HTTPS)");
			break;
		case 992:
			System.out.println("TCP:  Destination port = " + destinationPort + " (Telnet)");
			break;
		case 2049:
			System.out.println("TCP:  Destination port = " + destinationPort + " (NFS)");
			break;
		default:
			// Displayed if the destination port is not listed above.
			System.out.println("TCP:  Type of destination port not listed!");
			break;
		}
		
		// Sequence Number
		long sequenceNumber = Long.parseLong(hexPacket[nextIndex + 2] + hexPacket[nextIndex + 3], 16);
		System.out.println("TCP:  Sequence number = " + sequenceNumber);
		
		// Acknowledgement Number
		long acknowledgementNumber = Long.parseLong(hexPacket[nextIndex + 4] + hexPacket[nextIndex + 5], 16);
		System.out.println("TCP:  Acknowledgement number = " + acknowledgementNumber);
		
		// Data offset which gives the information regarding the options for the header
		int dataOffset = Integer.parseInt("" + hexPacket[nextIndex + 6].charAt(0), 16);
		System.out.println("TCP:  Data offset = " + dataOffset + " bytes");
		String flags = hexPacket[nextIndex + 6].substring(1);
		System.out.println("TCP:  Flags = 0x" + flags);
		flags = Integer.toBinaryString(Integer.parseInt(flags, 16));
		// Pads the flag bits with zeros as it is lost during binary to integer conversion
		if (flags.length() < 9) {
			int flagsLength = flags.length();
			for (int i = 0; i < (9 - flagsLength); i++) {
				flags = "0" + flags;
			}
		}

		// Urgent Pointer bit
		if (flags.charAt(3) == '0') {
			System.out.println("TCP:        ..0. .... = No urgent pointer");
		} else {
			System.out.println("TCP:        ..1. .... = urgent pointer");
		}

		// Acknowledgement bit
		if (flags.charAt(4) == '0') {
			System.out.println("TCP:        ...0 .... = No Acknowledgement");
		} else {
			System.out.println("TCP:        ...1 .... = Acknowledgement");
		}

		// Push Function
		if (flags.charAt(5) == '0') {
			System.out.println("TCP:        .... 0... = No Push");
		} else {
			System.out.println("TCP:        .... 1... = Push");
		}

		// Reset the connection
		if (flags.charAt(6) == '0') {
			System.out.println("TCP:        .... .0.. = No reset");
		} else {
			System.out.println("TCP:        .... .1.. = reset");
		}

		// Synchronize sequence numbers
		if (flags.charAt(7) == '0') {
			System.out.println("TCP:        .... ..0. = No Syn");
		} else {
			System.out.println("TCP:        .... ..1. = Syn");
		}

		// Finish flag - tells us whether there is any data incoming from the
		// sender
		if (flags.charAt(8) == '0') {
			System.out.println("TCP:        .... ...0 = No Fin");
		} else {
			System.out.println("TCP:        .... ...1 = Fin");
		}

		int windowSize = Integer.parseInt(hexPacket[nextIndex + 7], 16);
		System.out.println("TCP:  Window = " + windowSize);
		System.out.println("TCP:  Checksum = 0x" + hexPacket[nextIndex + 8]);
		int urgentPointer = Integer.parseInt(hexPacket[nextIndex + 9], 16);
		System.out.println("TCP:  Urgent pointer = " + urgentPointer);
		int optionLength = (dataOffset * 4) - 20;
		// Integer.parseInt(hexPacket[nextCount+10].substring(2), 16);

		if (optionLength == 0) {
			System.out.println("TCP:  No options ");
		} else {
			System.out.println("TCP:  No options (" + optionLength + " bytes)");
		}

		System.out.println("TCP: ");
		System.out.println("TCP:  Data: (first " + 64 + " bytes)");

		String[] tempData = new String[4];
		String[] tempDecodedData = new String[4];
		tempData[0] = "";
		tempDecodedData[0] = "";
		int i = 0, counter = 1;
		int index = nextIndex + 10 + (optionLength / 2);
		while (i < 4 && (hexPacket[index + counter - 1] != null)) {
			// Stores the encoding in a temporary string array which is limited
			// to a decimal range of [33, 126] to consider numbers, alphabets
			// and special characters to the decoding rest all will be replaced
			// with "."
			if (Integer.parseInt(hexPacket[index + counter - 1].substring(0, 2), 16) >= 33
					&& Integer.parseInt(hexPacket[index + counter - 1].substring(0, 2), 16) <= 126) {
				tempDecodedData[i] += Character
						.toString((char) Integer.parseInt(hexPacket[index + counter - 1].substring(0, 2), 16));
			} else {
				tempDecodedData[i] += ".";
			}
			if (Integer.parseInt(hexPacket[index + counter - 1].substring(2), 16) >= 33
					&& Integer.parseInt(hexPacket[index + counter - 1].substring(2), 16) <= 126) {
				tempDecodedData[i] += Character
						.toString((char) Integer.parseInt(hexPacket[index + counter - 1].substring(2), 16));
			} else {
				tempDecodedData[i] += ".";
			}

			// Adds the hex data values to a temporary string array to display
			// TCP data
			tempData[i] += hexPacket[index + counter - 1] + " ";
			// Makes sure that there are only 16 bytes printed on a single line
			if (counter % 8 == 0) {
				i++;
				if (i < 4) {
					tempData[i] = "";
					tempDecodedData[i] = "";
				}
			}
			counter++;

		}
		// Prints the TCP Data
		int j = 0;
		while (j < 4 && tempData[j] != "") {
			System.out.println("TCP:  " + tempData[j] + "    " + "\"" + tempDecodedData[j]+ "\"");
			j++;
		}
	}

	/**
	 * Analyzes and displays the ICMP packet
	 * 
	 * @param nextCount
	 * 				Takes the Starting index of the ICMP header as a parameter
	 */
	private void displayIcmpPacket(int nextCount) {
		// Displays the information from the UDP header byte by byte
		System.out.println("ICMP:  ----- ICMP Header ----- ");
		System.out.println("ICMP:");
		// Type of packet
		int type = Integer.parseInt(hexPacket[nextCount].substring(0, 2), 16);
		// The following categorizes types into different sub-types
		switch (type) {
		case 0:
			System.out.println("ICMP:  Type = " + type + " (Echo Reply)");
			break;
		case 3:
			System.out.println("ICMP:  Type = " + type + " (Destination Unreachable)");
			break;
		case 8:
			System.out.println("ICMP:  Type = " + type + " (Echo request)");
			break;
		case 9:
			System.out.println("ICMP:  Type = " + type + " (Router Advertisement)");
			break;
		case 11:
			System.out.println("ICMP:  Type = " + type + " (Time Exceeded)");
			break;
		case 13:
			System.out.println("ICMP:  Type = " + type + " (Timestamp)");
			break;
		case 30:
			System.out.println("ICMP:  Type = " + type + " (Traceroute)");
			break;
		default:
			System.out.println("ICMP:  Type not listed!");
			break;
		}

		int code = Integer.parseInt(hexPacket[nextCount].substring(2));
		
		// ICMP sub-type
		System.out.println("ICMP:  Code = " + code);
		
		// Calculates and displays the checksum
		System.out.println("ICMP:  Checksum = 0x" + hexPacket[nextCount + 1]);
		System.out.println("ICMP:");

	}

}
