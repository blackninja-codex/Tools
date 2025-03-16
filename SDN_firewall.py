from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp
import time

class DNSAmplificationMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DNSAmplificationMonitor, self).__init__(*args, **kwargs)
        self.dns_traffic = {}  # Tracks DNS request/response counts per source IP
        self.dns_threshold = 100  # Max DNS requests/responses per interval
        self.dns_interval = 1  # 1 second interval

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def dns_traffic_check(self, src_ip):
        now = time.time()
        if src_ip in self.dns_traffic:
            count, last_reset = self.dns_traffic[src_ip]
            if now - last_reset > self.dns_interval:
                # Reset counter if interval has passed
                self.dns_traffic[src_ip] = (1, now)
                return True
            elif count < self.dns_threshold:
                # Increment counter if within threshold
                self.dns_traffic[src_ip] = (count + 1, last_reset)
                return True
            else:
                # Drop packet if threshold is exceeded
                return False
        else:
            # Initialize counter for new IP
            self.dns_traffic[src_ip] = (1, now)
            return True

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if not eth:
            return

        eth_type = eth.ethertype
        if eth_type == 0x0800:  # IPv4
            ip = pkt.get_protocols(ipv4.ipv4)[0]
            src_ip = ip.src

            if ip.proto == 17:  # UDP
                udp_pkt = pkt.get_protocols(udp.udp)
                if udp_pkt and udp_pkt[0].dst_port == 53:  # DNS traffic (UDP port 53)
                    if not self.dns_traffic_check(src_ip):
                        # Drop DNS packet if threshold is exceeded
                        return

        # Forward the packet (allow all non-DNS traffic and DNS traffic within limits)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)
