# Import some POX stuff
from pox.core import core                       # Main POX object
import pox.openflow.libopenflow_01 as of        # OpenFlow 1.0 library
from pox.lib.addresses import EthAddr, IPAddr   # Address types
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

log = core.getLogger()
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def log_color(color, msg):
    log.info(f"{color}{msg}{RESET}")


PRIVATE_SUBNET = IPAddr("192.168.1.0")      # Red interna
PRIVATE_MASK = 24                           # Máscara de la red interna
PRIVATE_IP = IPAddr("192.168.1.254")        # IP del router en la red privada
PUBLIC_IP = IPAddr("200.0.0.254")           # IP del router en la red pública
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")   # MAC del router hacia la red pública
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")  # MAC del router hacia la red privada
PUBLIC_PORT = 1                             # Puerto del switch conectado a la red pública


# H1_MAC = EthAddr("00:00:00:00:00:01")       # MAC del host externo


class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        # Tabla ARP: IP -> MAC
        self.arp_table = {}

        # Paquetes en espera de resolución ARP: IPAddr → [(ethernet_pkt, in_port), ...]
        # in_port es el puerto del switch por donde llegó el paquete desde la red privada.
        self.pending_packets = {}

    def _is_router_ip(self, ip_address):
        """Verifica si la IP pertenece al router"""
        return ip_address in [PRIVATE_IP, PUBLIC_IP]

    # -------------------------------------------------------------------------
    # Dispatcher principal
    # -------------------------------------------------------------------------

    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            log.warning("[DROP] PacketIn con trama no reconocida. POX no pudo decodificar el paquete.")
            return

        if event.parsed.type == ethernet.ARP_TYPE:
            self.handle_arp(event)
        elif event.parsed.type == ethernet.IP_TYPE:
            self.handle_ip(event)
        else:
            log_color(YELLOW, f"Paquete ignorado: protocolo distinto de IPv4.")

    # -------------------------------------------------------------------------
    # Manejo de ARP
    # -------------------------------------------------------------------------

    def handle_arp(self, event):
        """Procesamiento de un paquete ARP"""
        ethernet_frame = event.parsed
        arp_packet = ethernet_frame.payload
        log_color(
            YELLOW, f"ARP recibido de {arp_packet.protosrc} ({arp_packet.hwsrc}) "
                    f"para {arp_packet.protodst} | In Port: {event.port}")

        # Guardamos la entrada en la tabla ARP tanto para Request como Response
        self._add_arp_entry(arp_packet.protosrc, arp_packet.hwsrc)

        if arp_packet.opcode == arp.REQUEST:
            if self._is_router_ip(arp_packet.protodst):
                self._send_arp_reply(event, arp_packet)
            else:
                log_color(YELLOW, f"ARP Request no destinado al router. Ignorado.")

        elif arp_packet.opcode == arp.REPLY:
            self._process_pending(arp_packet.protosrc)


    def _add_arp_entry(self, ip_address, mac_address):
        """Agrega o actualiza una entrada en la tabla ARP del controlador."""
        self.arp_table[ip_address] = mac_address
        log_color(CYAN, f"ARP - Entrada Agregada: {ip_address} → {mac_address}")

    def _send_arp_reply(self, event, arp_request):
        """Responde un ARP Request con la MAC del router correspondiente."""
        reply_mac = PRIVATE_MAC if arp_request.protodst == PRIVATE_IP else PUBLIC_MAC

        arp_reply = arp()
        arp_reply.opcode   = arp.REPLY
        arp_reply.hwsrc    = reply_mac
        arp_reply.protosrc = arp_request.protodst   # mi IP (la que preguntaron)
        arp_reply.hwdst    = arp_request.hwsrc       # MAC del que preguntó
        arp_reply.protodst = arp_request.protosrc    # IP del que preguntó

        eth_reply = ethernet()
        eth_reply.type    = ethernet.ARP_TYPE
        eth_reply.src     = reply_mac
        eth_reply.dst     = arp_request.hwsrc        # unicast al que preguntó
        eth_reply.payload = arp_reply

        msg = of.ofp_packet_out()
        msg.data = eth_reply.pack()
        msg.actions.append(of.ofp_action_output(port=event.port))
        self.connection.send(msg)
        log_color(GREEN, f"ARP Reply enviado: {arp_request.protodst} está en {reply_mac} → port {event.port}")

    def _send_arp_request(self, target_ip, out_port, src_ip, src_mac):
        """Envía un ARP Request broadcast para descubrir la MAC de target_ip."""
        arp_req = arp()
        arp_req.opcode   = arp.REQUEST
        arp_req.hwsrc    = src_mac
        arp_req.protosrc = src_ip
        arp_req.hwdst    = EthAddr("00:00:00:00:00:00")
        arp_req.protodst = target_ip

        eth_req = ethernet()
        eth_req.type    = ethernet.ARP_TYPE
        eth_req.src     = src_mac
        eth_req.dst     = EthAddr("ff:ff:ff:ff:ff:ff")  # broadcast
        eth_req.payload = arp_req

        msg = of.ofp_packet_out()
        msg.data = eth_req.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)
        log_color(CYAN, f"ARP Request enviado: ¿Quién tiene {target_ip}? → port {out_port}")

    def _process_pending(self, ip):
        """Procesa los paquetes pendientes cuando se aprende la MAC de una IP."""
        if ip not in self.pending_packets:
            return
        pending_packages = self.pending_packets.pop(ip)
        destination_mac = self.arp_table[ip]
        log_color(GREEN, f"Procesando {len(pending_packages)} paquete(s) pendiente(s) para {ip}")
        for (packet, in_port) in pending_packages:
            self._install_and_forward(packet, in_port, destination_mac)

    # -------------------------------------------------------------------------
    # Manejo de IP
    # -------------------------------------------------------------------------

    def handle_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port

        log_color(YELLOW, f"RECIBIDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
                  f"MAC: {packet.src} → {packet.dst} | In Port: {in_port}")

        if not ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            log_color(RED, f"NO MATCH: {ip_pkt.srcip} no pertenece a {PRIVATE_SUBNET}/{PRIVATE_MASK}")
            return

        log_color(GREEN, f"MATCH: {ip_pkt.srcip} pertenece a la red privada {PRIVATE_SUBNET}/{PRIVATE_MASK}")

        dst_ip = ip_pkt.dstip

        if dst_ip in self.arp_table:
            dst_mac = self.arp_table[dst_ip]
            self._install_and_forward(packet, in_port, dst_mac)
        else:
            # MAC desconocida: encolar paquete y enviar ARP Request
            if dst_ip not in self.pending_packets:
                self.pending_packets[dst_ip] = []
                self._send_arp_request(dst_ip, PUBLIC_PORT, PUBLIC_IP, PUBLIC_MAC)
            self.pending_packets[dst_ip].append((packet, in_port))
            log_color(YELLOW, f"MAC de {dst_ip} desconocida. Paquete encolado, ARP Request enviado.")

    def _install_and_forward(self, packet, in_port, dst_mac):
        """Instala flujos saliente/entrante y reenvía el paquete actual."""
        ip_pkt = packet.payload
        private_host_mac = packet.src  # MAC del host privado (h2 o h3), antes de modificar

        # Instalar Flujo Saliente
        fm = of.ofp_flow_mod()
        fm.idle_timeout = 10

        # Filtro (Saliente)
        fm.match.nw_src = ip_pkt.srcip
        fm.match.dl_type = 0x800  # IPv4
        fm.match.in_port = in_port

        # Acción (Saliente)
        fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        self.connection.send(fm)

        # Instalar Flujo Entrante (para respuesta)
        fm_back = of.ofp_flow_mod()
        fm_back.idle_timeout = 10

        # Filtro (Entrante)
        fm_back.match.nw_src = ip_pkt.dstip
        fm_back.match.nw_dst = ip_pkt.srcip
        fm_back.match.dl_type = 0x800  # IPv4
        fm_back.match.in_port = PUBLIC_PORT

        # Acción (Entrante)
        fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
        fm_back.actions.append(of.ofp_action_dl_addr.set_dst(private_host_mac))
        fm_back.actions.append(of.ofp_action_output(port=in_port))
        self.connection.send(fm_back)

        # Reenviar paquete actual con MACs actualizadas (Los posteriores pasan por flujo)
        packet.src = PUBLIC_MAC
        packet.dst = dst_mac
        msg = of.ofp_packet_out()
        msg.data = packet.pack()
        msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        log_color(CYAN, f"ENVIANDO: {ip_pkt.srcip} → {ip_pkt.dstip} | MAC: {PUBLIC_MAC} → {dst_mac} | Out Port: {PUBLIC_PORT}")
        self.connection.send(msg)



def launch():

    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
