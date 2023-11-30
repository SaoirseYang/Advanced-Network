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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        ''' Handle Configuration Changes '''
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        print("EVENT: Switch added || dpid: 0x%09x"%(datapath.id))
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

        self.logger.info("PACKET OUT: Flooding")
        out_port = ofproto.OFPP_FLOOD                       # Specify Flood | Given we have 0 idea where tos end the packet...

        # Extract L4 header information
        self.extract_l4_info(pkt, datapath, in_port)

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

    def extract_l4_info(self, pkt, datapath, in_port):
        ''' Extract L4 header information and call the appropriate handler '''
        tcp_header = pkt.get_protocol(tcp.tcp)
        udp_header = pkt.get_protocol(udp.udp)

        if tcp_header:
            # TCP packet handling
            self.handle_tcp(pkt, datapath, in_port)
        elif udp_header:
            # UDP packet handling
            self.handle_udp(pkt, datapath, in_port)
        else:
            # Other L4 types (for now, we'll handle ICMP)
            self.handle_icmp(pkt, datapath, in_port)

    # 添加新的处理函数

    def handle_tcp(self, pkt, datapath, in_port):
        ''' Handle TCP packet '''
        tcp_header = pkt.get_protocol(tcp.tcp)

        # 获取源端口和目标端口
        src_port = tcp_header.src_port
        dst_port = tcp_header.dst_port

        self.logger.info(f"TCP Packet: Src Port - {src_port}, Dst Port - {dst_port}")

        # Add your TCP handling logic here

        # 创建 TCP 数据包的匹配字段
        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port,
            eth_type=ether_types.ETH_TYPE_IP,  # 指定 IP 协议
            ip_proto=inet.IPPROTO_TCP,  # 指定 TCP 协议
            tcp_src=src_port,  # 匹配源端口
            tcp_dst=dst_port  # 匹配目标端口
        )

        # 指定动作（在这里我们直接输出到源端口，你可以根据需要调整）
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]

        # 发送 Flow Mod 到 Datapath
        self.add_flow(datapath, 1, match, actions)


    def handle_udp(self, pkt, datapath, in_port):
        ''' Handle UDP packet '''
        udp_header = pkt.get_protocol(udp.udp)

        # 获取源端口和目标端口
        src_port = udp_header.src_port
        dst_port = udp_header.dst_port

        self.logger.info(f"UDP Packet: Src Port - {src_port}, Dst Port - {dst_port}")

        # Add your UDP handling logic here

        # 创建 UDP 数据包的匹配字段
        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port,
            eth_type=ether_types.ETH_TYPE_IP,  # 指定 IP 协议
            ip_proto=inet.IPPROTO_UDP,  # 指定 UDP 协议
            udp_src=src_port,  # 匹配源端口
            udp_dst=dst_port  # 匹配目标端口
        )

        # 指定动作（在这里我们直接输出到源端口，你可以根据需要调整）
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]

        # 发送 Flow Mod 到 Datapath
        self.add_flow(datapath, 1, match, actions)

    def handle_icmp(self, pkt, datapath, in_port):
        ''' Handle ICMP packet '''
        icmp_header = pkt.get_protocol(icmp.icmp)

        # 获取 ICMP 类型和代码
        icmp_type = icmp_header.type_
        icmp_code = icmp_header.code

        self.logger.info(f"ICMP Packet: Type - {icmp_type}, Code - {icmp_code}")

        # 创建 ICMP 数据包的匹配字段
        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port,
            eth_type=ether_types.ETH_TYPE_IP,  # 指定 IP 协议
            ip_proto=inet.IPPROTO_ICMP,  # 指定 ICMP 协议
            icmpv4_type=icmp_type,  # 匹配 ICMP 类型
            icmpv4_code=icmp_code  # 匹配 ICMP 代码
        )

        # 指定动作（在这里我们直接输出到源端口，你可以根据需要调整）
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]

        # 发送 Flow Mod 到 Datapath
        self.add_flow(datapath, 1, match, actions)


