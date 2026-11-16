# -*- coding: utf-8 -*-
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub
from eventlet.green import socket
import re

class ControladorIDS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ControladorIDS, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.bloqueadas = set()
        
        self.port_to_vlan = {
            1: {2: 10, 3: 20, 4: 30, 5: 10, 1: 'trunk'},
            2: {3: 10, 4: 20, 5: 30, 6: 20, 1: 'trunk', 2: 'trunk'},
            3: {2: 10, 3: 20, 4: 30, 1: 'trunk'}
        }
        
        self.snort_thread = hub.spawn(self.escuchar_alertas_udp)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch s%s conectado al Controlador IDS", datapath.id)

    def escuchar_alertas_udp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 5140))
        self.logger.info("Escuchando alertas de Snort en tiempo real (UDP 127.0.0.1:5140)...")
        while True:
            data, _ = sock.recvfrom(4096)
            linea = data.decode('utf-8', errors='ignore')
            match = re.search(r'\{[A-Z]+\}\s+([0-9]+(?:\.[0-9]+){3})', linea)
            if match:
                ip_atacante = match.group(1)
                if ip_atacante not in self.bloqueadas:
                    self.bloqueadas.add(ip_atacante)
                    self.mitigar_ataque(ip_atacante)

    def mitigar_ataque(self, ip_atacante):
        for dp_id, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_atacante)
            self.add_flow(datapath, 200, match, [])
            self.logger.info("IDS Snort detecto anomalia. Bloqueando IP origen %s en switch s%s (priority=200)", ip_atacante, dp_id)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        vlan_origen = self.port_to_vlan.get(dpid, {}).get(in_port, None)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            vlan_destino = self.port_to_vlan.get(dpid, {}).get(out_port, None)
            if vlan_origen != 'trunk' and vlan_destino != 'trunk' and vlan_origen != vlan_destino:
                return
            actions = [parser.OFPActionOutput(out_port)]
        else:
            actions = []
            for p, v in self.port_to_vlan.get(dpid, {}).items():
                if p != in_port and (v == vlan_origen or v == 'trunk' or vlan_origen == 'trunk'):
                    actions.append(parser.OFPActionOutput(p))

        if actions:
            if dst != 'ff:ff:ff:ff:ff:ff':
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    return
            data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
