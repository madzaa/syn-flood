# Pcap Parser
This Go program reads packet capture savefiles and performs operations to parse packet headers and retrieve header information.
## Prerequisites
To run this program, you need to have Go installed on your machine.
## Usage
1. Clone this repository to your local machine.
2. Navigate to the project directory.
3. Place the "synflood.pcap" file in the same directory as the Go code.
4. Open a terminal and run the following command:
   go run main.go
5. The program will read the "synflood.pcap" file, parse the packet headers, and display the number of packets.
## Code Explanation
The program consists of the following main components:
-  check  function: Checks if an error occurred and panics if it did.
-  PacketHeader  struct: Defines the structure of a packet header.
-  main  function: Entry point of the program. Reads the "synflood.pcap" file, calls functions to retrieve header information and parse packet headers, and logs the number of packets.
-  parsePacketHeaders  function: Parses the packet headers in the data and returns the number of packets.
-  getHeader  function: Retrieves the magic number, major version, and minor version from the data.
-  getUint32  function: Extracts a 4-byte slice from the data starting from the given position.
-  le  function: Converts a byte slice to a little-endian unsigned 32-bit integer.
-  be  function: Converts a byte slice to a big-endian integer.
   Please note that the program assumes the presence of the "synflood.pcap" file in the same directory. Make sure to place the file accordingly before running the program.
   Feel free to modify the code or adapt it to suit your needs.
