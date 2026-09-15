from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import networkx as nx
import time

class SDNController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mac_to_dpid = {}
        self.net = nx.DiGraph()
        self.flood_history = {} # Upgraded to track ALL packets

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(event.EventSwitchEnter)
    @set_ev_cls(event.EventLinkAdd)
    @set_ev_cls(event.EventLinkDelete)
    def update_topology(self, ev):
        self.net.clear()
        switches = get_switch(self, None)
        for switch in switches:
            self.net.add_node(switch.dp.id)
            
        links = get_link(self, None)
        for link in links:
            self.net.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)
            self.net.add_edge(link.dst.dpid, link.src.dpid, port=link.dst.port_no)
        
        # --- CUSTOM PROGRESS LOGGING ---
        switch_count = len(self.net.nodes)
        link_count = int(len(self.net.edges) / 2) # Divide by 2 because links are two-way
        current_time = time.strftime("%H:%M:%S")
        
        print("\n" + "="*50)
        print("⏳ [" + current_time + "] TOPOLOGY DISCOVERY PROGRESS")
        print("Switches Mapped: " + str(switch_count))
        print("Links Discovered: " + str(link_count))
        print("Switch IDs Online: " + str(list(self.net.nodes)))
        print("="*50 + "\n")
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # 1. Ignore Controller Discovery Packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # 2. Drop IPv6 to prevent Mininet background storms
        if eth.ethertype == 0x86dd: 
            return

        # 3. Universal Loop Prevention (Rate-limits duplicate PacketIns from floods)
        packet_key = (dpid, eth.src, eth.dst)
        if packet_key in self.flood_history and (time.time() - self.flood_history[packet_key]) < 0.1:
            return
        self.flood_history[packet_key] = time.time()

        # 4. Smart MAC Learning
        is_edge_port = True
        if dpid in self.net:
            for neighbor in self.net[dpid]:
                if self.net[dpid][neighbor]['port'] == in_port:
                    is_edge_port = False 
                    break
        
        if is_edge_port:
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][eth.src] = in_port
            self.mac_to_dpid[eth.src] = dpid

        out_port = ofproto.OFPP_FLOOD

        # 5. Dijkstra's Shortest Path Routing
        if eth.dst in self.mac_to_dpid:
            dst_dpid = self.mac_to_dpid[eth.dst]
            if dpid == dst_dpid:
                out_port = self.mac_to_port[dpid][eth.dst]
            else:
                try:
                    path = nx.shortest_path(self.net, dpid, dst_dpid)
                    next_hop = path[1]
                    out_port = self.net[dpid][next_hop]['port']
                except nx.NetworkXNoPath:
                    return

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)