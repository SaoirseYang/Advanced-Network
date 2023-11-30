from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto as inet
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp, udp, icmp

"""
CNSCC365 | Base L2 Learning Switch

This acts simply as a hub for now, but, if expanded, will function
as a L2 learning switch.
"""

class LearningSwitch(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] # Use OF v1_3 for this module!

    def __init__(self, *args, **kwargs):
        ''' Create instance of the controller '''
        super(LearningSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        ''' Handle Configuration Changes '''
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        print("EVENT: Switch added || dpid: 0x%09x"%(datapath.id))
        self.mac_to_port[datapath.id] = {}
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        ''' Handle Packet In OpenFlow Events '''
        self.logger.info("EVENT: PACKET IN")

        ## Collect EVENT data
        msg = ev.msg                                        # The message containing all the data needed from the openflow event
        datapath = msg.datapath                          # The switch (datapath) that the event came from
        ofproto = datapath.ofproto                          # OF Protocol lib to be used with the OF version on the switch
        parser = datapath.ofproto_parser                    # OF Protocol Parser that matches the OpenFlow version on the switch
        dpid = datapath.id                                  # ID of the switch (datapath) that the event came from

        ## Collect packet data
        pkt = packet.Packet(msg.data)                       # The packet relating to the event (including all of its headers)
        in_port = msg.match['in_port']                      # The port that the packet was received on the switch

        ######## !
        # This is where most learning functionality should be implemented
        ####### !

        #self.logger.info("PACKET OUT: Flooding")

        out_port = ofproto.OFPP_FLOOD                       # Specify Flood | Given we have 0 idea where tos end the packet...

        # Extract L4 header information
        self.extract_l4_info(pkt, datapath, in_port, ofproto, parser)

        # The action of sending a packet out converted to the correct OpenFlow format
        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        return

    def add_flow(self, datapath, priority, match, actions):
        ''' Write to the Datapath's flow-table '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        self.logger.info("FLOW MOD: Written")
        datapath.send_msg(mod)

    def extract_l4_info(self, pkt, datapath, in_port, ofproto, parser):
        ''' Extract L4 header information and call the appropriate handler '''
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("Received packet: %s %s %s %s", dpid, src, dst, in_port)
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPPacketOut(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:

            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto

                #if ICMP Portocol
                if protocol == in_proto.IPPROTO_ICMP:
                    self.handle_icmp(srcip, dstip, protocol, pkt, datapath, out_port)

                elif protocol == in_proto.IPPROTO_TCP:
                    self.handle_tcp(srcip, dstip, protocol, pkt, datapath, out_port)

                elif protocol == in_proto.IPPROTO_UDP:
                    self.handle_udp(srcip, dstip, protocol, pkt, datapath, out_port)
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def handle_tcp(self, srcip, dstip, protocol, pkt, datapath, out_port):
        ''' Handle TCP packet '''
        tcp_header = pkt.get_protocol(tcp.tcp)
        # 创建 TCP 数据包的匹配字段
        match = datapath.ofproto_parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,  # 指定 IP 协议
            ip_proto=protocol,  # 指定 TCP 协议
            ipv4_src=srcip,
            ipv4_dst=dstip,
            tcp_src=tcp_header.src_prot,  # 匹配源端口
            tcp_dst=tcp_header.dst_port  # 匹配目标端口
        )
        # 指定动作（在这里我们直接输出到源端口，你可以根据需要调整）
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        # 发送 Flow Mod 到 Datapath
        self.add_flow(datapath, 1, match, actions)
        return


    def handle_udp(self, srcip, dstip, protocol, pkt, datapath, out_port):
        ''' Handle UDP packet '''
        udp_header = pkt.get_protocol(udp.udp)

        # 创建 UDP 数据包的匹配字段
        match = datapath.ofproto_parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,  # 指定 IP 协议
            ip_proto=protocol,  # 指定 TCP 协议
            ipv4_src=srcip,
            ipv4_dst=dstip,
            tcp_src=udp_header.src_prot,  # 匹配源端口
            tcp_dst=udp_header.dst_port  # 匹配目标端口
        )
        # 指定动作（在这里我们直接输出到源端口，你可以根据需要调整）
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        # 发送 Flow Mod 到 Datapath
        self.add_flow(datapath, 1, match, actions)
        return

    def handle_icmp(self, srcip, dstip, protocol, pkt, datapath, out_port):
        ''' Handle ICMP packet '''
        icmp_header = pkt.get_protocol(icmp.icmp)
        # 创建 ICMP 数据包的匹配字段
        match = datapath.ofproto_parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,  # 指定 IP 协议
            ip_proto=protocol,  # 指定 TCP 协议
            ipv4_src=srcip,
            ipv4_dst=dstip,
            tcp_src=icmp_header.src_prot,  # 匹配源端口
            tcp_dst=icmp_header.dst_port  # 匹配目标端口
        )
        # 指定动作（在这里我们直接输出到源端口，你可以根据需要调整）
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        # 发送 Flow Mod 到 Datapath
        self.add_flow(datapath, 1, match, actions)
        return


