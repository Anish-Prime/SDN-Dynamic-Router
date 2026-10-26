from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import networkx as nx
import time
import os, sys

# --- DASHBOARD: make sdn_rest_api.py (same folder) importable under ryu-manager ---
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ryu.lib import hub
from ryu.lib.packet import arp, ipv4
from ryu.app.wsgi import WSGIApplication
from sdn_rest_api import DashboardMixin

class SDNController(DashboardMixin, app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}   # DASHBOARD: Ryu's built-in REST server (port 8080)

    def __init__(self, *args, **kwargs):
        super(SDNController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mac_to_dpid = {}
        self.net = nx.DiGraph()
        self.flood_history = {} 
        self.dead_ports = set() # NEW: Tracks dead ports so Ryu doesn't revive them

        # --- DASHBOARD additions ---
        self.host_ip = {}        # mac -> ip (learned from ARP/IPv4 on edge ports)
        self.flow_counts = {}    # (dpid, in_port, src, dst) -> last packet_count
        self.init_dashboard(kwargs['wsgi'])
        self.monitor_thread = hub.spawn(self._traffic_monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        # Default table-miss flow (priority 0)
        self.add_flow(datapath, 0, match, actions, cookie=0)

    def add_flow(self, datapath, priority, match, actions, cookie=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # Added cookie parameter to tag specific flows
        mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        port = msg.desc

        current_time = time.strftime("%H:%M:%S")

        # Check if the port state indicates the link went down
        if port.state & ofproto.OFPPS_LINK_DOWN:
            self.dead_ports.add((datapath.id, port.port_no))
            print(f"\n==================================================")
            print(f"⚠️  [{current_time}] LINK DOWN DETECTED")
            print(f"Switch DPID: {datapath.id} | Port: {port.port_no}")
            print(f"Flushing flow tables to force route recalculation...")
            print(f"==================================================\n")
        else:
            self.dead_ports.discard((datapath.id, port.port_no))
            print(f"\n==================================================")
            print(f"✅ [{current_time}] LINK UP DETECTED")
            print(f"Switch DPID: {datapath.id} | Port: {port.port_no}")
            print(f"==================================================\n")

        # Instantly update our graph without waiting for Ryu's slow LLDP timeouts
        self.rebuild_topology()

        # Fetch all active switches and flush their dynamic flows
        switches = get_switch(self, None)
        for switch in switches:
            self.remove_flows(switch.dp)
                        
    def remove_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.flow_counts.clear()   # DASHBOARD: counters restart after a flush
        # An empty match means it will match all flows
        empty_match = parser.OFPMatch()
        
        # Delete ONLY flows tagged with cookie=1 (our dynamic routes).
        # This protects Ryu's LLDP rules and your table-miss rule!
        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=1,
            cookie_mask=0xFFFFFFFFFFFFFFFF, # Match the cookie exactly
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=1,
            match=empty_match
        )
        datapath.send_msg(mod)

    def rebuild_topology(self):
        self.net.clear()
        switches = get_switch(self, None)
        for switch in switches:
            self.net.add_node(switch.dp.id)
            
        links = get_link(self, None)
        for link in links:
            # IMPORTANT: Ignore links that are connected to physically down ports
            if (link.src.dpid, link.src.port_no) in self.dead_ports or \
            (link.dst.dpid, link.dst.port_no) in self.dead_ports:
                continue
                
            self.net.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)
            self.net.add_edge(link.dst.dpid, link.src.dpid, port=link.dst.port_no)
        
        # --- CUSTOM PROGRESS LOGGING ---
        switch_count = len(self.net.nodes)
        link_count = int(len(self.net.edges) / 2)
        current_time = time.strftime("%H:%M:%S")
        
        print("\n" + "="*50)
        print(f"⏳ [{current_time}] TOPOLOGY DISCOVERY PROGRESS")
        print(f"Switches Mapped: {switch_count}")
        print(f"Links Discovered: {link_count}")
        print(f"Switch IDs Online: {list(self.net.nodes)}")
        print("="*50 + "\n")

    @set_ev_cls(event.EventSwitchEnter)
    @set_ev_cls(event.EventLinkAdd)
    @set_ev_cls(event.EventLinkDelete)
    def update_topology(self, ev):
        # Let Ryu's background events trigger our smart builder
        self.rebuild_topology()
        
            
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

        # 1. Drop LLDP and IPv6 to prevent Mininet background storms
        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.ethertype == 0x86dd:
            return
        
        # 2. Ignore multicast MACs from learning (starting with 01:00:5e or 33:33)
        if eth.dst.startswith('01:00:5e') or eth.dst.startswith('33:33'):
            return

        # 3. Universal Loop Prevention (Rate-limits duplicate PacketIns from floods)
        packet_key = (dpid, eth.src, eth.dst)
        if packet_key in self.flood_history and (time.time() - self.flood_history[packet_key]) < 1.5:
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
            # DASHBOARD: remember the host's IP so the UI can label it h1, h2...
            arp_pkt = pkt.get_protocol(arp.arp)
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if arp_pkt:
                self.host_ip[eth.src] = arp_pkt.src_ip
            elif ip_pkt:
                self.host_ip[eth.src] = ip_pkt.src

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
                    
                    # --- CUSTOM PATH LOGGING ---
                    print(f"📍 Switch {dpid} routing to {dst_dpid} via path: {path}")
                    # ---------------------------
                    
                except nx.NetworkXNoPath:
                    return
                    
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            # Tag specific routes with cookie=1 so they can be selectively flushed later
            self.add_flow(datapath, 1, match, actions, cookie=1)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    # ------------------------------------------------------------------
    # DASHBOARD: detect real traffic by polling the cookie=1 flow counters.
    # (Once a flow is installed, later pings never reach the controller, so
    #  PacketIn alone cannot animate repeated pings. Counters can.)
    # ------------------------------------------------------------------
    def _traffic_monitor(self):
        while True:
            try:
                for sw in get_switch(self, None):
                    dp = sw.dp
                    parser = dp.ofproto_parser
                    dp.send_msg(parser.OFPFlowStatsRequest(
                        dp, flags=0, cookie=1, cookie_mask=0xFFFFFFFFFFFFFFFF))
            except Exception as e:
                self.logger.warning("traffic monitor: %s", e)
            hub.sleep(0.5)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        for stat in ev.msg.body:
            if stat.cookie != 1:
                continue
            src, dst = stat.match.get('eth_src'), stat.match.get('eth_dst')
            in_port = stat.match.get('in_port')
            if src is None or dst is None:
                continue
            key = (dpid, in_port, src, dst)
            prev = self.flow_counts.get(key, 0)
            if stat.packet_count < prev:      # flow was reinstalled
                prev = 0
            self.flow_counts[key] = stat.packet_count
            # Only the INGRESS switch of the source host reports the full path
            is_ingress = (self.mac_to_dpid.get(src) == dpid and
                          self.mac_to_port.get(dpid, {}).get(src) == in_port)
            if stat.packet_count > prev and is_ingress and dst in self.mac_to_dpid:
                self._emit_path(src, dst)

    def _emit_path(self, src, dst):
        s, d = self.mac_to_dpid[src], self.mac_to_dpid[dst]
        try:
            path = [s] if s == d else nx.shortest_path(self.net, s, d)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return
        self.log_event('path', src=src, dst=dst, path=path)
