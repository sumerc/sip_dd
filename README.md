# sip_dd
Sip DoS Defense Tool

Architecture : Melih Tas

Code: Sumer Cip

# Usage:
python3 sip_dd.py -d <dev_name> -t <inbound_traffic_limit_in_kbps> -v (VERBOSE logging on) -f <bpf_filter>

If no bpf filter given, default is 'udp port 5060'

# Test:
nping --udp <host> -p 5060 --data-length 10