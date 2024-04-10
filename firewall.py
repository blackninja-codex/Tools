from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp
import time

class HTTPFloodFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HTTPFloodFirewall, self).__init__(*args, **kwargs)
        self.ip_list = {}
        self.rate_limit = 2 * 10**(-3)  # 2 milliseconds
        self.rate_limit_counter = {}
        self.rate_limit_threshold = 100  # Allowed requests within rate_limit_interval
        self.rate_limit_interval = 1  # 1 second
        self.allowed_ports = {80, 443}  # Allowed destination ports

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

    def rate_limit_check(self, src_ip):
        now = time.time()
        if src_ip in self.rate_limit_counter:
            counter, last_reset = self.rate_limit_counter[src_ip]
            if now - last_reset > self.rate_limit_interval:
                self.rate_limit_counter[src_ip] = (1, now)
                return True
            elif counter < self.rate_limit_threshold:
                self.rate_limit_counter[src_ip] = (counter + 1, last_reset)
                return True
            else:
                return False
        else:
            self.rate_limit_counter[src_ip] = (1, now)
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

            if ip.proto == 6:  # TCP
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                if tcp_pkt.dst_port in self.allowed_ports:  # HTTP or HTTPS
                    now = time.time()
                    if src_ip in self.ip_list:
                        time_diff = now - self.ip_list[src_ip]
                        if time_diff < self.rate_limit:
                            return  # Drop packet

                    self.ip_list[src_ip] = now

                    if not self.rate_limit_check(src_ip):
                        return  # Drop packet due to rate limiting

        # Forward the packet
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

app_manager.require_app('ryu.controller.rest_conf_switch')
app_manager.require_app('ryu.controller.ofp_handler')
app_manager.require_app('ryu.controller.dpset')
app_manager.require_app('ryu.topology.switches')