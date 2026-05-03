# Copyright (c) RedTiger by Loxy0devlp
# Licensed under the MIT License.
# See LICENSE file in the project root for full license text.

from Config.Utils import *
from Program.Utils.NetworkScanningUtils import *

def ClassifyIp(lock, ip, port, ip_width, protocol_width, up_hosts, counters, tcp_icmp_timeout):
    methods = []
    latencies = []

    ping_icmp_status, ping_icmp_latency, json_format = IpGetPingAndLatency(ip, status="ICMP", icmp_timeout=tcp_icmp_timeout, log=False)
    if ping_icmp_status:
        methods.append("ICMP")
        latencies.append(ping_icmp_latency)

    ping_tcp_status, ping_tcp_latency, json_format = IpGetPingAndLatency(ip, status="TCP", port=port, socket_timeout=tcp_icmp_timeout, log=False)
    if ping_tcp_status:
        methods.append(f"TCP:{port}")
        latencies.append(ping_tcp_latency)

    with lock:
        if methods:
            latency = min(latencies, key=lambda x: float("inf") if x == "timeout" else x)
            protocol = " / ".join(methods)
            up_hosts.append({"IP": ip, "Status": "Up", "Protocol": protocol, "Latency": latency})
            Add(f"{white}{ip:<{ip_width}} {protocol:<{protocol_width}} {"Up":<8} {latency}")
        else: counters["Filtered or down"] += 1
    state["completed"] += 1

def ScanNetwork(lock, network, port, ip_width, protocol_width, tcp_icmp_timeout):
    up_hosts = []
    counters = {"Filtered or down": 0}
    threads  = []

    for ip in network.hosts():
        ip = str(ip)
        thread = StartThread(ClassifyIp, lock, ip, port, ip_width, protocol_width, up_hosts, counters, tcp_icmp_timeout)
        threads.append(thread)

    for thread in threads: thread.join()
    
    return up_hosts, counters

def HostDiscovery(target=None, output=None, port=None, tcp_icmp_timeout=None, socket_proxy=None):
    Title("Host Discovery")

    if not target: target = Input("Target [-t] (ex: 192.168.1.1/24) -> ")
    if "/" in target: ip, cidr_prefix = target.split("/")
    else: ErrorCidr()

    detect_target = DetectTarget(ip)
    if not detect_target in ["ip"]: ErrorIp()
    elif any(bad in target for bad in blacklists): ErrorTarget()
    elif not cidr_prefix.isdigit(): ErrorCidr()

    ip, port_default, json_format = TargetGetIp(ip, detect_target)
    if not ip: ErrorTarget()
    ip_type, json_format = IpType(ip)
    Info(f"CIDR prefix: {white}{cidr_prefix}")
    
    if not has_cli_args: 
        tcp_icmp_timeout    = Input(f"Max TCP/ICMP timeout [-TIT] (default: {str(default_tcp_icmp_timeout)}) -> ")
        socket_proxy        = Input(f"Socket proxy [-SP] (default: {str(default_socket_proxy)}) -> ")
        port                = Input(f"TCP port [-p] (default: {str(default_port)}) -> ")
    
    if not socket_proxy: socket_proxy = default_socket_proxy

    try:
        if not tcp_icmp_timeout: tcp_icmp_timeout = default_tcp_icmp_timeout
        else: tcp_icmp_timeout = float(tcp_icmp_timeout)
        Info(f"Max timeout: {white}{str(tcp_icmp_timeout)}s")
    except (ValueError, TypeError): ErrorTimeout()
    
    try:
        if not port: port = default_port
        elif int(port) > max_port: ErrorPort()
        Info(f"Port: {white}{str(port)}")
    except (ValueError, TypeError): ErrorPort()

    EnableSocketProxy(socket_proxy=socket_proxy, socket_timeout=tcp_icmp_timeout)
    network = ipaddress.ip_network(target, strict=False)

    total_hosts    = network.num_addresses - (2 if network.version == 4 else 0)
    ip_width       = len(network.network_address.compressed.rsplit("." if network.version == 4 else ":", 1)[0] + ("." if network.version == 4 else ":")) + 4
    protocol_width = 12 + len(str(port))
    lock           = threading.Lock()

    Wait(f"CIDR scanning: {white}{target}")
    global state
    state = {"stop": False, "completed": 0, "completed_total": total_hosts}
    StartThread(StatsPressed, state, time_start=time.time())
    print(f"{red}{"":<14} {'IP:':<{ip_width}} {'Protocol:':<{protocol_width}} {"Status:":<8} Latency:{reset}")
    up_hosts, counters = ScanNetwork(lock, network, port, ip_width, protocol_width, tcp_icmp_timeout)
    state["stop"] = True
    Info(f"Up: {white}{len(up_hosts)}{red} Filtered or down (no response): {white}{counters["Filtered or down"]}")

    json_data = {
        "Parameters": {
            "TCP/ICMP timeout": tcp_icmp_timeout if tcp_icmp_timeout else None,
            "Socket proxy": socket_proxy if socket_proxy else None,
            "TCP port": port if port else None
        },
        "IP": ip,
        "IP type": ip_type,
        "CIDR prefix": cidr_prefix,
        "Hosts": {
            "Up": up_hosts,
            "Filtered or down": counters["Filtered or down"]
        }
    }

    if output in (True, None): SaveJsonToFile(json_data, f"Result_HostDiscovery_{target}", json_output=output)
    Continue()
    Reset()
