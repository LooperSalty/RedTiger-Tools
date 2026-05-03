# Copyright (c) RedTiger by Loxy0devlp
# Licensed under the MIT License.
# See LICENSE file in the project root for full license text.

from Config.Utils import *
from Program.Utils.NetworkScanningUtils import *

def PortScanner(target=None, mode=None, protocol_scan=None, port=None, output=None, socket_timeout=None, socket_proxy=None):
    Title("Port Scanner")

    if isinstance(port, list): port = "".join(port)
    if not target: target = Input("Target [-t] -> ")
    detect_target = DetectTarget(target)

    if not detect_target in ["ip"]: ErrorIp()
    elif any(bad in target for bad in blacklists): ErrorTarget()

    if not has_cli_args: 
        socket_timeout = Input(f"Max socket timeout [-ST] (default: {str(default_socket_timeout)}) -> ")
        socket_proxy   = Input(f"Socket proxy [-SP] (default: {str(default_socket_proxy)}) -> ")

        print(f"""
  {BEFORE}01{AFTER + white} TCP
  {BEFORE}02{AFTER + white} UDP
  {BEFORE}03{AFTER + white} TCP & UDP
        """)
        protocol_scan = Input(f"Protocol scan [-PS] (default: {default_protocol}) -> ").strip()

    if not socket_proxy: socket_proxy = default_socket_proxy

    try:
        if not socket_timeout: socket_timeout = default_socket_timeout
        else: socket_timeout = float(socket_timeout)
        Info(f"Max socket timeout: {white}{str(socket_timeout)}s")
    except (ValueError, TypeError): ErrorTimeout()

    EnableSocketProxy(socket_proxy=socket_proxy, socket_timeout=socket_timeout)

    try:
        if not protocol_scan: protocol_scan = default_protocol
        else: protocol_scan = "".join(protocol_scan.split())
        if protocol_scan in ("1", "01", "TCP"):       protocol_scan = "TCP"
        elif protocol_scan in ("2", "02", "UDP"):     protocol_scan = "UDP"
        elif protocol_scan in ("3", "03", "TCP,UDP"): protocol_scan = "TCP,UDP"
        Info(f"Protocol: {white}{protocol_scan}")
    except (ValueError, TypeError): ErrorTimeout()

    json_data = {
        "Parameters": {
            "Socket timeout": socket_timeout if socket_timeout else None,
            "Socket proxy": socket_proxy if socket_proxy else None,
            "Protocol scan": protocol_scan if protocol_scan else None,
        }
    }

    ip, port_default, json_format = TargetGetIp(target, detect_target)
    if not ip: ErrorTarget()
    MergeJson(json_data, json_format)
    ip_type, json_format = IpType(ip)
    MergeJson(json_data, json_format)

    if not mode:
        print(f"""
  {BEFORE}01{AFTER + white} Single port
  {BEFORE}02{AFTER + white} Multiple ports
  {BEFORE}03{AFTER + white} Port range
  {BEFORE}04{AFTER + white} Default port
  {BEFORE}05{AFTER + white} All ports
        """)
        mode = Input("Scan mode [-m] -> ").strip()

    if mode in ("1", "01", "single"):
        if not port: port = Input("Port [-p] -> ")
        port = "".join(port.split())
        if not port.isdigit(): ErrorPort()
        else:
            port = int(port)
            if 1 <= port <= max_port:
                json_data["Parameters"]["Mode"] = "single"
                json_data["Parameters"]["Port"] = port
                Wait(f"Port scanning: {white + str(port)}")
                tcp_port_stats, udp_port_stats, json_format = IpGetPort(ip, socket_timeout=socket_timeout, port=port, mass_scan=False, port_default=port_default, stats_pressed=True, protocol_scan=protocol_scan)
            else: ErrorPort()

    elif mode in ("2", "02", "multiple"):
        if not port: port = Input("Ports [-p] (ex: 22,80,443) -> ")
        port = "".join(port.split())
        try:
            ports_list = [int(x) for x in port.split(",")]
            if not ports_list: ErrorPort()
            elif all(1 <= x <= max_port for x in ports_list):
                json_data["Parameters"]["Mode"] = "multiple"
                json_data["Parameters"]["Ports"] = port
                Wait(f"Port scanning: {white + str(port)}")
                tcp_port_stats, udp_port_stats, json_format = IpGetPort(ip, socket_timeout=socket_timeout, port=port, mass_scan=False, port_default=port_default, stats_pressed=True, protocol_scan=protocol_scan)
            else: ErrorPort()
        except ValueError: ErrorFormat()

    elif mode in ("3", "03", "range"):
        if not port: port = Input("Port range [-p] (ex: 1-100) -> ")
        port = "".join(port.split())
        if "-" not in port: ErrorFormat()
        else:
            try:
                start, end = map(int, port.split("-"))
                if 1 <= start <= end <= max_port:
                    json_data["Parameters"]["Mode"] = "range"
                    json_data["Parameters"]["Ports"] = port
                    Wait(f"Port scanning: {white + str(port)}")
                    tcp_port_stats, udp_port_stats, json_format = IpGetPort(ip, socket_timeout=socket_timeout, port=port, mass_scan=True, port_default=port_default, stats_pressed=True, protocol_scan=protocol_scan)
                else: ErrorPort()
            except ValueError: ErrorFormat()
    
    elif mode in ("4", "04", "default"):
        json_data["Parameters"]["Mode"] = "default"
        tcp_port_stats, udp_port_stats, json_format = IpGetPort(ip, socket_timeout=socket_timeout, all=False, mass_scan=True, port_default=port_default, stats_pressed=True, protocol_scan=protocol_scan)
    
    elif mode in ("5", "05", "all"):
        json_data["Parameters"]["Mode"] = "all"
        Wait(f"Port scanning..")
        tcp_port_stats, udp_port_stats, json_format = IpGetPort(ip, socket_timeout=socket_timeout, all=True, mass_scan=True, port_default=port_default, stats_pressed=True, protocol_scan=protocol_scan)

    else: ErrorMode()

    MergeJson(json_data, json_format)
    banners, json_format = IpGetServiceBanner(ip, tcp_port_stats["Open"], socket_timeout, log=True)
    MergeJson(json_data, json_format)

    if output in (True, None): SaveJsonToFile(json_data, f"Result_PortScanner_{target}", json_output=output)
    Continue()
    Reset()