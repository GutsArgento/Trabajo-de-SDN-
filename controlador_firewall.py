# -*- coding: utf-8 -*-
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp

class ControladorFirewallSDN(app_manager.RyuApp):
    # BLOQUE 1: DEFINICION DE PROTOCOLO Y MATRICES BASE
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ControladorFirewallSDN, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
        # Matriz de segmentacion de VLAN por puerto fisico de cada switch
        self.port_to_vlan = {
            1: {2: 10, 3: 20, 4: 30, 5: 10, 1: 'trunk'}, # Switch 1
            2: {3: 10, 4: 20, 5: 30, 6: 20, 1: 'trunk', 2: 'trunk'}, # Switch 2
            3: {2: 10, 3: 20, 4: 30, 1: 'trunk'} # Switch 3
        }

    # BLOQUE 2: CONFIGURACION INICIAL DEL SWITCH (Table-Miss + Reglas Proactivas L3/L4)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 2.1 Regla Table-Miss (Prioridad 0): envia paquetes desconocidos a Ryu
        match_miss = parser.OFPMatch()
        actions_miss = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match_miss, actions_miss)

        # 2.2 Instalar politicas proactivas de Firewall (Prioridad 100)
        self.instalar_politicas_firewall(datapath)

    # BLOQUE 3: DEFINICION DE REGLAS DE BLOQUEO IP Y PUERTOS (ETAPA 4)
    def instalar_politicas_firewall(self, datapath):
        parser = datapath.ofproto_parser

        # POLITICA A (Capa 3 - Bloqueo por IP especifica):
        # Bloquear todo trafico IPv4 desde h7 (10.0.30.1) hacia srv_admin (10.0.10.100)
        # eth_type=0x0800 indica protocolo IPv4 obligatorio en OpenFlow 1.3
        match_bloqueo_ip = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src='10.0.30.1',
            ipv4_dst='10.0.10.100'
        )
        # Lista de acciones vacia [] equivale a DROP (descarte silencioso en el switch)
        self.add_flow(datapath, 100, match_bloqueo_ip, [])

        # POLITICA B (Capa 4 - Bloqueo por puerto HTTP / TCP 80):
        # Bloquear peticiones web (TCP puerto 80) desde toda la subred Invitados (10.0.30.0/24)
        # hacia el servidor de Laboratorios srv_lab (10.0.20.100)
        # ip_proto=6 indica protocolo TCP
        match_bloqueo_http = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=6,
            ipv4_src=('10.0.30.0', '255.255.255.0'),
            ipv4_dst='10.0.20.100',
            tcp_dst=80
        )
        self.add_flow(datapath, 100, match_bloqueo_http, [])

    # BLOQUE 4: FUNCION AUXILIAR PARA INYECTAR FLUJOS (FlowMod)
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    # BLOQUE 5: CONMUTACION REACTIVA DE CAPA 2 CON AISLAMIENTO VLAN
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignorar paquetes LLDP usados internamente para descubrimiento de topologia
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
                # Prioridad 1: menor que las reglas de firewall (Prioridad 100)
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    return

            data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
