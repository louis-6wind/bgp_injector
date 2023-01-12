#!/usr/bin/env python3

"""
    BGP prefix injection tool
    
*****************************************************************************************
Copyright (c) 2018 Jorge Borreicho
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*****************************************************************************************
"""

import socket
import sys
import time
from datetime import datetime
import struct
import threading
import json
import os


AFI_IPV4 = 1
SAFI_UNICAST = 1


def keepalive_thread(conn, interval):

    # infinite loop so that function do not terminate and thread do not end.
    while True:
        time.sleep(interval)
        keepalive_bgp(conn)


def receive_thread(conn):

    # infinite loop so that function do not terminate and thread do not end.
    while True:

        # Receiving from client
        r = conn.recv(1500)
        while True:
            start_ptr = (
                r.find(
                    b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                )
                + 16
            )
            end_ptr = (
                r[16:].find(
                    b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                )
                + 16
            )
            if (
                start_ptr >= end_ptr
            ):  # a single message was sent in the BGP packet OR it is the last message of the BGP packet
                decode_bgp(r[start_ptr:])
                break
            else:  # more messages left to decode
                decode_bgp(r[start_ptr:end_ptr])
                r = r[end_ptr:]


def decode_bgp(msg):

    msg_length, msg_type = struct.unpack("!HB", msg[0:3])
    if msg_type == 4:
        # print(timestamp + " - " + "Received KEEPALIVE") #uncomment to debug
        pass
    elif msg_type == 2:
        timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print(timestamp + " - " + "Received UPDATE")
    elif msg_type == 1:
        version, remote_as, holdtime, i1, i2, i3, i4, opt_length = struct.unpack(
            "!BHHBBBBB", msg[3:13]
        )
        timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print(timestamp + " - " + "Received OPEN")
        print()
        print(
            "--> Version:"
            + str(version)
            + ", Remote AS: "
            + str(remote_as)
            + ", Hold Time:"
            + str(holdtime)
            + ", Remote ID: "
            + str(i1)
            + "."
            + str(i2)
            + "."
            + str(i3)
            + "."
            + str(i4)
        )
        print()
    elif msg_type == 3:
        timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print(timestamp + " - " + "Received NOTIFICATION")


def multiprotocol_capability(afi, safi):
    hexstream = bytes.fromhex("02060104")
    hexstream += struct.pack("!H", afi)
    hexstream += struct.pack("!B", 0)
    hexstream += struct.pack("!B", safi)

    return hexstream


def open_bgp(conn, config):

    # Build the BGP Message
    bgp_version = b"\x04"
    bgp_as = struct.pack("!H", config["my_as"])
    bgp_hold_time = struct.pack("!H", config["hold_time"])

    octet = config["bgp_identifier"].split(".")
    bgp_identifier = struct.pack(
        "!BBBB", int(octet[0]), int(octet[1]), int(octet[2]), int(octet[3])
    )

    bgp_opt = b""
    bgp_opt += multiprotocol_capability(AFI_IPV4, SAFI_UNICAST)

    bgp_opt_lenght = struct.pack("!B", len(bgp_opt))

    bgp_message = (
        bgp_version + bgp_as + bgp_hold_time + bgp_identifier + bgp_opt_lenght + bgp_opt
    )

    # Build the BGP Header
    total_length = len(bgp_message) + 16 + 2 + 1
    bgp_marker = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    bgp_length = struct.pack("!H", total_length)
    bgp_type = b"\x01"
    bgp_header = bgp_marker + bgp_length + bgp_type

    bgp_packet = bgp_header + bgp_message

    conn.send(bgp_packet)
    return 0


def keepalive_bgp(conn):

    # Build the BGP Header
    total_length = 16 + 2 + 1
    bgp_marker = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    bgp_length = struct.pack("!H", total_length)
    bgp_type = b"\x04"
    bgp_header = bgp_marker + bgp_length + bgp_type

    bgp_packet = bgp_header

    conn.send(bgp_packet)
    return 0


def encode_ipv4_prefix(address, netmask):

    octet = address.split(".")
    length = struct.pack("!B", int(netmask))

    if int(netmask) <= 8:
        prefix = struct.pack("!B", int(octet[0]))
    elif int(netmask) <= 16:
        prefix = struct.pack("!BB", int(octet[0]), int(octet[1]))
    elif int(netmask) <= 24:
        prefix = struct.pack("!BBB", int(octet[0]), int(octet[1]), int(octet[2]))
    else:
        prefix = struct.pack(
            "!BBBB", int(octet[0]), int(octet[1]), int(octet[2]), int(octet[3])
        )

    return length + prefix


def encode_path_attribute(type, value):

    path_attributes = {
        "origin": [b"\x40", 1],
        "as-path": [b"\x40", 2],
        "next-hop": [b"\x40", 3],
        "med": [b"\x80", 4],
        "local_pref": [b"\x40", 5],
        "communities": [b"\xc0", 8],
    }

    attribute_flag = path_attributes[type][0]
    attribute_type_code = struct.pack("!B", int(path_attributes[type][1]))

    if type == "origin":
        attribute_value = struct.pack("!B", 1)
    elif type == "as-path":
        as_number_list = value.split(" ")
        attribute_value = struct.pack("!BB", 2, len(as_number_list))
        for as_number in as_number_list:
            attribute_value += struct.pack("!H", int(as_number))
    elif type == "next-hop":
        octet = value.split(".")
        attribute_value = struct.pack(
            "!BBBB", int(octet[0]), int(octet[1]), int(octet[2]), int(octet[3])
        )
    elif type == "med":
        attribute_value = struct.pack("!I", value)
    elif type == "local_pref":
        attribute_value = struct.pack("!I", value)
    elif type == "communities":
        communities_list = value.split(" ")
        attribute_value = b""
        for community in communities_list:
            aux = community.split(":")
            attribute_value += struct.pack("!HH", int(aux[0]), int(aux[1]))

    attribute_length = struct.pack("!B", len(attribute_value))

    return attribute_flag + attribute_type_code + attribute_length + attribute_value


def update_bgp(conn, bgp_mss, withdrawn_routes, path_attributes, nlri):

    # Build the BGP Message

    # Expired Routes
    # 1 - Withdrawn Routes

    bgp_withdrawn_routes = b""
    max_length_reached = False

    while len(withdrawn_routes) > 0 and not max_length_reached:
        route = withdrawn_routes.pop(0)
        addr, mask = route.split("/")
        bgp_withdrawn_routes += encode_ipv4_prefix(addr, mask)
        if (
            len(bgp_withdrawn_routes) + 16 + 2 + 1 + 2 + 2 + 100 >= bgp_mss
        ):  # + header + withdrawn_routes_length + total_path_attributes_length + 100 bytes margin for attributes
            max_length_reached = True

    bgp_withdrawn_routes_length = struct.pack("!H", len(bgp_withdrawn_routes))
    bgp_withdrawn_routes = bgp_withdrawn_routes_length + bgp_withdrawn_routes

    # New Routes
    # 2 - Path Attributes

    bgp_total_path_attributes = b""

    if not max_length_reached:
        try:
            bgp_total_path_attributes += encode_path_attribute(
                "origin", path_attributes["origin"]
            )
        except KeyError:
            pass
        try:
            bgp_total_path_attributes += encode_path_attribute(
                "as-path", path_attributes["as-path"]
            )
        except KeyError:
            pass
        try:
            bgp_total_path_attributes += encode_path_attribute(
                "next-hop", path_attributes["next-hop"]
            )
        except KeyError:
            pass
        try:
            bgp_total_path_attributes += encode_path_attribute(
                "med", path_attributes["med"]
            )
        except KeyError:
            pass
        try:
            bgp_total_path_attributes += encode_path_attribute(
                "local_pref", path_attributes["local_pref"]
            )
        except KeyError:
            pass
        try:
            bgp_total_path_attributes += encode_path_attribute(
                "communities", path_attributes["communities"]
            )
        except KeyError:
            pass

    bgp_total_path_attributes_length = struct.pack("!H", len(bgp_total_path_attributes))
    bgp_total_path_attributes = (
        bgp_total_path_attributes_length + bgp_total_path_attributes
    )

    # 3- Network Layer Reachability Information (NLRI)

    bgp_new_routes = b""
    while len(nlri) > 0 and not max_length_reached:
        route = nlri.pop(0)
        addr, mask = route.split("/")
        bgp_new_routes += encode_ipv4_prefix(addr, mask)
        if (
            len(bgp_withdrawn_routes) + len(bgp_new_routes) + 16 + 2 + 1 + 2 + 2 + 100
            >= bgp_mss
        ):  # + header + withdrawn_routes_length + total_path_attributes_length + 100 bytes margin for attributes
            max_length_reached = True

    bgp_message = bgp_withdrawn_routes + bgp_total_path_attributes + bgp_new_routes

    # Build the BGP Header
    total_length = len(bgp_message) + 16 + 2 + 1
    bgp_marker = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    bgp_length = struct.pack("!H", total_length)
    bgp_type = b"\x02"
    bgp_header = bgp_marker + bgp_length + bgp_type

    bgp_packet = bgp_header + bgp_message

    conn.send(bgp_packet)

    timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print(timestamp + " - " + "Sent UPDATE.")

    if (
        len(withdrawn_routes) > 0 or len(nlri) > 0
    ):  # there are still BGP info to be updated that didn't fit this last Update message
        update_bgp(conn, bgp_mss, withdrawn_routes, path_attributes, nlri)

    return 0


def ip2str(ip_bytes):
    ip_addr = struct.unpack("!BBBB", ip_bytes)
    return (
        str(int(ip_addr[0]))
        + "."
        + str(int(ip_addr[1]))
        + "."
        + str(int(ip_addr[2]))
        + "."
        + str(int(ip_addr[3]))
    )


def str2ip(ip_str):
    s_octet = ip_str.split(".")
    ip_addr = struct.pack(
        "!BBBB", int(s_octet[0]), int(s_octet[1]), int(s_octet[2]), int(s_octet[3])
    )
    return ip_addr


def prefix_generator(start_address, netmask):
    addr = str2ip(start_address)
    i = 0
    while True:
        yield ip2str(
            struct.pack("!I", struct.unpack("!I", addr)[0] + i * (2 ** (32 - netmask)))
        )
        i += 1


if __name__ == "__main__":
    CONFIG_FILENAME = os.path.join(sys.path[0], "bgp_injector.cfg")

    input_file = open(CONFIG_FILENAME, "r")

    config = json.loads(input_file.read())

    bgp_peer = config["peer_address"]
    bgp_local = config["local_address"]
    bgp_mss = config["mss"]
    bgp_port = config["port"]
    rib = dict()
    timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print(timestamp + " - " + "Starting BGP... (peer: " + str(bgp_peer) + ")")

    try:
        bgp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bgp_socket.bind((bgp_local, 0))
        bgp_socket.connect((bgp_peer, bgp_port))
        open_bgp(bgp_socket, config)

    except TimeoutError:
        timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print(timestamp + " - " + "Error: Cannot connect to peer.")
        exit()

    receive_worker = threading.Thread(
        target=receive_thread, args=(bgp_socket,)
    )  # wait from BGP msg from peer and process them
    receive_worker.setDaemon(True)
    receive_worker.start()

    keepalive_worker = threading.Thread(
        target=keepalive_thread,
        args=(
            bgp_socket,
            (config["hold_time"]) / 3,
        ),
    )  # send keep alives every 10s by default
    keepalive_worker.setDaemon(True)
    keepalive_worker.start()

    # send a first keepalive packet before sending the initial UPDATE packet
    keepalive_bgp(bgp_socket)

    timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print(timestamp + " - " + "BGP is up.")

    prefixes_to_withdraw = []
    prefixes_to_advertise = []
    path_attributes = config["path_attributes"]

    prefix_gen = prefix_generator(config["start_address"], config["netmask"])

    for i in range(config["number_of_prefixes_to_inject"]):
        prefix = next(prefix_gen)
        prefixes_to_advertise.append(prefix + "/" + str(config["netmask"]))

    time.sleep(3)
    update_bgp(
        bgp_socket,
        bgp_mss,
        prefixes_to_withdraw,
        path_attributes,
        prefixes_to_advertise,
    )

    try:
        while True:
            time.sleep(60)

    except KeyboardInterrupt:
        timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print(timestamp + " - " + "^C received, shutting down.")
        bgp_socket.close()
        exit()
