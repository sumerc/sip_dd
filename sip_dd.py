import os
import time
import argparse
import calendar
import datetime
import threading
import pickle
from collections import defaultdict, Counter
from scapy.all import *

MAX_UDP_SIP_PACKET_SIZE = 64 # kb
RATE_CALCULATE_INTERVAL = 1 # sec - smaller is more accurate but slower

def _get_dump_file_names():
    """Calculate the filenames that the PCAP data to be written from the now(DateTime)
    hourly/13:00-14:00_28.Nov.2017.pcap
    daily/28.Nov.2017.pcap
    weekly/21-28_Nov.2017
    monthly/Nov.2017
    """
    now = datetime.datetime.now()

    abbr_month_name = calendar.month_name[now.month][:3]
    start_day_of_week = (now - datetime.timedelta(days=now.weekday())).day
    end_day_of_week = (now - datetime.timedelta(days=now.weekday()) + \
        datetime.timedelta(days=7)).day

    hfn = 'hourly/%d:00-%d:00_%d.%s.%d' % (now.hour, now.hour+1, now.day, 
        abbr_month_name, now.year)
    dfn = 'daily/%d.%s.%d' % (now.day, abbr_month_name, now.year)
    wfn = 'weekly/%d-%d_%s.%d' % (start_day_of_week, end_day_of_week, abbr_month_name, 
        now.year)
    mfn = 'monthly/%s.%d' % (abbr_month_name, now.year)

    return [hfn, dfn, wfn, mfn]

# TODO: Write a mock way to simulate traffic from a pcap file(for testing)

class SipDDSniffer(object):
    """ 
    XXX

    Note: I don't care too much about thread-safety since data intensive stuff happens
    on files, only simple conf./status is passed between threads.
    """
    ACTIVATE_ACTION_MODULE = True # TODO: used for debuggiing, remove after debug

    def __init__(self, args):
        self.args = args
        self.in_packet_rate_limit=self.args.inbound_traffic_rate_in_kbps/MAX_UDP_SIP_PACKET_SIZE
        
        self.total_len_in_bytes = 0
        self.current_rate = 0 # kbps
        self.suspect_rate_exceeded = True
        self.counters = {}

    def _load_counters(self):
        for file_name in _get_dump_file_names():
            try:
                with open(file_name + '.rates', 'rb') as f:
                    self.rates = pickle.load(f)
            except FileNotFoundError:
                self.rates = {'total_sum':0, 'sample_count': 0, 'max': 0}

    def _save_counters(self):
        for file_name in _get_dump_file_names():
            with open(file_name + '.rates', 'wb') as f:
                pickle.dump(self.rates, f)

    @property
    def current_edge(self):
        return self.current_rate

    @property
    def normal_edge(self):
        return self.rates['total_sum'] / self.rates['sample_count']

    @property
    def attack_edge(self):
        return self.rates['max']

    @property
    def suspect_edge(self):
        return (self.attack_edge + self.normal_edge) / 2

    @property
    def current_limit(self):
        return (self.current_edge / MAX_UDP_SIP_PACKET_SIZE)

    @property
    def normal_limit(self):
        return (self.normal_edge / MAX_UDP_SIP_PACKET_SIZE)
    
    @property
    def suspect_limit(self):
        return (self.suspect_edge / MAX_UDP_SIP_PACKET_SIZE)
    
    @property
    def attack_limit(self):
        return (self.attack_limit / MAX_UDP_SIP_PACKET_SIZE)
    
    def _calc_rate(self):
        prev_tot_len = self.total_len_in_bytes
        while(True):
            self.current_rate = \
                (self.total_len_in_bytes-prev_tot_len) / 1024 / RATE_CALCULATE_INTERVAL
            prev_tot_len = self.total_len_in_bytes
            
            self.rates['total_sum'] += self.current_rate
            self.rates['sample_count'] += 1
            self.rates['max'] = max(self.rates['max'], self.current_rate)

            self._save_counters()

            if self.args.verbose:
                print("Current Edge: %d\n Normal Edge:%d\n, Suspect Edge: %d\n, "
                    "Attack Edge: %d\n" % (self.current_edge, self.normal_edge, 
                    self.suspect_edge, self.attack_edge))

            # check and do suspect actions and reset fields
            if self.suspect_rate_exceeded or self.ACTIVATE_ACTION_MODULE:
                # TODO: Check if SLs reached and do some actions
                import pprint;
                pprint.pprint(self.counters)

            self.suspect_rate_exceeded = False
            self.counters = {'rule1': Counter(),
                             'rule2': Counter(),
                             'rule3_per_cseq': defaultdict(Counter),
                             'rule3': Counter(), 
                             'rule4_per_cseq': defaultdict(Counter),
                             'rule4': Counter(),}
            
            if self.current_edge > self.suspect_edge or \
                self.current_limit > self.suspect_limit:
                self.suspect_rate_exceeded = True

            time.sleep(RATE_CALCULATE_INTERVAL)

    def _on_pkt_recv(self, pkt):
        try:
            for file_name in _get_dump_file_names():
                wrpcap(file_name + '.pcap', pkt, append=True)
            
            self.total_len_in_bytes += pkt.len

            if self.suspect_rate_exceeded or self.ACTIVATE_ACTION_MODULE:
                try:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].src
                    sip_data = pkt[Raw].load.decode("ascii")
                    
                    # TODO: I am sure there is a better alternative to extract CSeq 
                    # value from a sip msg but this simply works.
                    cseq = None
                    sip_data_splitted = sip_data.split()
                    for i, a in enumerate(sip_data_splitted):
                        if a == 'CSeq:':
                            cseq = sip_data_splitted[i+1]
                            break
                    if cseq is None:
                        raise Exception("CSeq not found.")
                except IndexError:
                    return

                # TODO: For lab purpose we will use the IP address in From header in the Application Layer. 

                # Rule-1
                if any(x in sip_data for x in ['INVITE sip', 'REGISTER sip']):
                    self.counters['rule1'][src_ip] += 1

                # Rule-2
                if any(x in sip_data for x in ['INVITE sip', 'REGISTER sip']):
                    self.counters['rule2'][dst_ip] += 1
                
                # Rule-3
                if any(x in sip_data for x in ['INVITE sip', 'REGISTER sip']):
                    self.counters['rule3_per_cseq'][src_ip][cseq] += 1
                    self.counters['rule3'][src_ip] = \
                        min(2, (self.counters['rule3_per_cseq'][src_ip][cseq]//4)+1)
                    

                # Rule-4
                if any(x in sip_data for x in ['INVITE sip', 'REGISTER sip']):
                    self.counters['rule4_per_cseq'][dst_ip][cseq] += 1
                    self.counters['rule4'][dst_ip] = \
                        min(2, (self.counters['rule4_per_cseq'][dst_ip][cseq]//4)+1)

        except Exception as e:
            import traceback; traceback.print_exc()

    def _sniff(self):
        sniff(iface=self.args.dev_name, prn=self._on_pkt_recv, 
            filter=self.args.bpf_filter, store=0)

    def start(self):
        self._load_counters()

        self._rate_calculator_thread = threading.Thread(target=self._calc_rate, args=())
        self._rate_calculator_thread.start()

        self._sniffer_thread = threading.Thread(target=self._sniff, args=())
        self._sniffer_thread.start()

def main():
    parser = argparse.ArgumentParser(description='SIP DoS Defense Tool')
    parser.add_argument('--dev_name', '-d', type=str, required=True)
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--bpf_filter', '-f', type=str, default='udp port 5060')
    parser.add_argument('--inbound_traffic_rate_in_kbps', '-t', type=int, required=True)

    args = parser.parse_args()

    # ensure PCAP dirs are in place
    for d in ['daily', 'hourly', 'weekly', 'monthly']:
        if not os.path.exists(d):
            os.makedirs(d)

    # start our sniffer
    sniffer = SipDDSniffer(args)
    sniffer.start()

if __name__ == "__main__":
    main()

"""
a=rdpcap(_get_dump_file_names()[3]+'.pcap')
for p in a:
    if IP in p: # can be IPv6 
        print(p[IP].src)
        print(p[UDP])
        #if Raw in p:
        print(p[Raw].load)
    #p.show()    
    #print(dir(p))
    #print(p[IP].src)
    #print(p[UDP])
"""