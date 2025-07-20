# INFIL - An Integrated CLI Offensive Security Tool

## Project Overview
The main motivation behind this project is to combine some simple functionality offered by commonly used security and networking tools such as Nmap, MSFvenom, and Netcat. Functionalities include port scanning and service enumeration (Nmap), payload and command generation (MSFvenom), and remote shell connections (Netcat).

## Build Dependencies
- **Compiler**: g++ (Homebrew GCC 13.2.0)

- **C++ Standard**: C++17

- **Compiler Flags**:
  - `-std=c++17`
  - `-I/opt/homebrew/include`

- **Linker Flags**:

  - `-L/opt/homebrew/lib`
  - `-ltins`

- **System Libraries**:
  - libtins (>= 4.4)
  - libpcap (automatically used by libtins)

- **Platform**:
  - macOS/Linux

## Repository Overview
- `infil.cpp` contains the main *Infil* class that takes in user input and initialises the specified tool.

- `listener.cpp` contains the method of the *Listener* class that opens a port on the user's machine and allows for remote shell connections with a target machine.

- `listener.hpp` is the header file for `listener.cpp`.

- `payload.cpp` contains the *LinuxX86ReverseShell* and *LinuxX86BindShell* classes that support simple Linux x86 (32-bit) reverse shell and bind shell payloads, as well as the equivalent shell commands that can be run on Unix-like machines.

- `payload.hpp` is the header file for `payload.cpp`.

- `scanner.cpp` contains the methods of the *Scanner* class that allow for port scanning and service enumeration. Supported scan types include TCP connect, UDP, and SYN/stealth scans.

- `scanner.hpp` is the header file for `scanner.cpp`.

- `makefile` is the Makefile for the project.

## Usage
### 1. Compilation
Ensure the current working directory can access the Makefile and run the following command:
```sh
make infil
```
This will produce an executable file *infil*.

### 2. Running the Program
<mark style="background-color: turquoise">a. To start the **listener**, run the following command:</mark>
```sh
./infil listener <lport> <protocol>
```
- Replace `lport` with the port number to listen on
- Replace `protocol` with any of the following protocol options:
  - **-T** (TCP Connection)
  - **-U** (UDP Connection)

<mark style="background-color: turquoise">b. To generate **payloads**, run the following command:</mark>
```sh
./infil payload <type> <format> [lhost] <lport>
```
- Replace `type` with any of the following payload options:
  - **-R** (Reverse Shell)
  - **-B** (Bind Shell)
- Replace `format` with any of the following formatting options:
  - **-C** (Shell Command)
  - **-P** (Hex Payload)
- Replace `lhost` with the IP address of the listening host machine **if reverse shell payload is selected**
- Replace `lport` with the port number of the listening host machine

<mark style="background-color: turquoise">c. To start the **port scanner**, run the following command:</mark>
```sh
./infil scanner <ip> <port> <type> [options ...]
```
- Replace `ip` with the target machine's IP address
- Replace `port` with the target machine's port number/range in the corresponding format:
  - **-p-** (Scan all ports)
  - **-p**`<portnum>` (Scan a specific port)
  - **-p**`<portStart>`**-**`<portEnd>` (Scan a range of ports)
- Replace `type` with any of the following scan options:
  - **-T** (TCP Connect Scan)
  - **-S** (Stealth/SYN Scan)
  - **-U** (UDP Scan)

**Important:** Running SYN (-S) and UDP (-U) scans requires elevated privileges. Use `sudo` to execute these scan types.

- The following global option can be included but is not required:
  - **-v** (Verbose Mode)

You may also wish to test the scanner's functionality on [Nmap's official test machine](http://scanme.nmap.org/). The public IP address for this machine is **45.33.32.156**.



