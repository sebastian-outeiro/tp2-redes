# Import some POX stuff
from pox.core import core                       # Main POX object
import pox.openflow.libopenflow_01 as of        # OpenFlow 1.0 library
from pox.lib.addresses import EthAddr, IPAddr   # Address types
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4

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

TIMEOUT_SECONDS = 10

NAT_PORT_START  = 1024
NAT_PORT_END    = 65535

class ProtoRouter(object):


    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        # Tabla ARP: IP -> MAC
        self.arp_table = {}

        # Paquetes en espera de resolución ARP: IP -> (Paquete, Puerto)
        self.pending_packets = {}

        # NAT
        self.next_nat_port  = NAT_PORT_START
        self.used_nat_ports = set()

    def _is_router_ip(self, ip_address):
        """Verifica si la IP pertenece al router"""
        return ip_address in [PRIVATE_IP, PUBLIC_IP]

    def _is_pat_protocol(self, protocol):
        """Verifica si el número de protocolo IP corresponde a TCP o UDP (protocolos con PAT)."""
        return protocol in (ipv4.TCP_PROTOCOL, ipv4.UDP_PROTOCOL)

    def _should_apply_pat(self, ip_pkt):
        """Determina si el paquete IP requiere traducción de puerto (PAT)."""
        return self._is_pat_protocol(ip_pkt.protocol)

    # -------------------------------------------------------------------------
    # Dispatcher principales
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


    def _handle_FlowRemoved(self, event):
        """Libera el puerto NAT cuando el flujo entrante expira en el switch.
          Para esto se genera un match que verifica:
        1. La IP de destino es la del Router.
        2. El protocolo cumple con que aplica para PAT.
        3. El puerto de destino no esta vacío. (Existe un puerto para liberar)
        """
        match = event.ofp.match
        # Solo nos interesan los flujos entrantes: nw_dst == PUBLIC_IP con protocolo TCP/UDP
        if match.nw_dst == PUBLIC_IP and self._is_pat_protocol(match.nw_proto) and match.tp_dst is not None:
            self._release_nat_port(match.tp_dst)

    # -------------------------------------------------------------------------
    # Manejo de ARP
    # -------------------------------------------------------------------------

    def handle_arp(self, event):
        """Procesamiento de un paquete ARP"""
        ethernet_frame = event.parsed
        arp_packet = ethernet_frame.payload
        arp_type = "REQUEST" if arp_packet.opcode == arp.REQUEST else "REPLY" if arp_packet.opcode == arp.REPLY else f"UNKNOWN({arp_packet.opcode})"
        log_color(
            YELLOW, f"ARP {arp_type} recibido de {arp_packet.protosrc} ({arp_packet.hwsrc}) "
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
        # Se obtiene la MAC dependiendo de que IP fue consultado.
        # La IP privada la utilziara un host interno de la red.
        # La IP pública la utilizará un host externo.
        reply_mac = PRIVATE_MAC if arp_request.protodst == PRIVATE_IP else PUBLIC_MAC

        # ARP Reply. Source: Router. Destination: Host que realizo la consulta.
        arp_reply = arp()
        arp_reply.opcode   = arp.REPLY
        arp_reply.hwsrc    = reply_mac
        arp_reply.protosrc = arp_request.protodst
        arp_reply.hwdst    = arp_request.hwsrc
        arp_reply.protodst = arp_request.protosrc

        # Ethernet Frame. Source: Router. Destination: Se usa la MAC de quien envio el mensaje.
        eth_reply = ethernet()
        eth_reply.type    = ethernet.ARP_TYPE
        eth_reply.src     = reply_mac
        eth_reply.dst     = arp_request.hwsrc
        eth_reply.payload = arp_reply

        # Se responde el mensaje ARP Reply al destination establecido junto con el puerto desde donde llego el request.
        msg = of.ofp_packet_out()
        msg.data = eth_reply.pack()
        msg.actions.append(of.ofp_action_output(port=event.port))
        self.connection.send(msg)
        log_color(GREEN, f"ARP Reply enviado: {arp_request.protodst} está en {reply_mac} → Out Port: {event.port}")

    def _send_arp_request(self, target_ip, out_port, src_ip, src_mac):
        """Envía un ARP Request broadcast para descubrir la MAC de target_ip."""

        # Se arma un ARP Request con destination MAC 0, ya que es lo que queremos conocer.
        # En este paquete, se incluye la IP objetivo como la IP destino.
        arp_req = arp()
        arp_req.opcode   = arp.REQUEST
        arp_req.hwsrc    = src_mac
        arp_req.protosrc = src_ip
        arp_req.hwdst    = EthAddr("00:00:00:00:00:00")
        arp_req.protodst = target_ip

        # Paquete Ethernet en broadcast a la red para conocer la MAC del destinatario.
        eth_req = ethernet()
        eth_req.type    = ethernet.ARP_TYPE
        eth_req.src     = src_mac
        eth_req.dst     = EthAddr("ff:ff:ff:ff:ff:ff")
        eth_req.payload = arp_req

        # Se envia el mensaje. Se utiliza el puerto recibido por la función.
        msg = of.ofp_packet_out()
        msg.data = eth_req.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)
        log_color(CYAN, f"ARP Request enviado: ¿Quién tiene {target_ip}? → port {out_port}")

    def _add_pending_packet(self, dst_ip, packet, in_port):
        """Encola un paquete en espera de resolución ARP para dst_ip."""
        if dst_ip not in self.pending_packets:
            self.pending_packets[dst_ip] = []
        self.pending_packets[dst_ip].append((packet, in_port))

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
    # Gestión de puertos NAT
    # -------------------------------------------------------------------------

    def _increment_next_nat_port(self):
        """ Avanza el puntero next_nat_port en 1.
        En caso de que se llegue al final de los puertos posibles, se asigna el primero."""
        self.next_nat_port += 1
        if self.next_nat_port > NAT_PORT_END:
            self.next_nat_port = NAT_PORT_START

    def _allocate_nat_port(self):
        """Asigna el siguiente puerto NAT disponible (desde NAT_PORT_START, con wrap-around)."""
        start = self.next_nat_port
        while self.next_nat_port in self.used_nat_ports:
            self._increment_next_nat_port()
            if self.next_nat_port == start:
                raise RuntimeError("No hay puertos NAT disponibles")
        port = self.next_nat_port
        self.used_nat_ports.add(port)
        self._increment_next_nat_port()
        log_color(CYAN, f"Puerto NAT asignado: {port} | En uso: {len(self.used_nat_ports)}")
        return port

    def _release_nat_port(self, port):
        """Libera un puerto NAT cuando el flujo entrante expira."""
        self.used_nat_ports.discard(port)
        log_color(CYAN, f"Puerto NAT liberado: {port} | En uso: {len(self.used_nat_ports)}")

    # -------------------------------------------------------------------------
    # Manejo de IP
    # -------------------------------------------------------------------------

    def handle_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port

        log_color(YELLOW, f"Paquete IP RECIBIDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
                  f"MAC: {packet.src} → {packet.dst} | In Port: {in_port}")

        if self._should_apply_pat(ip_pkt):
            transport = ip_pkt.payload
            log_color(YELLOW, f"Protocol {ip_pkt.protocol} | src_port: {transport.srcport} → dst_port: {transport.dstport}")

        # Si el mensaje no corresponde a un host de la red privada, se ignora el paquete.
        if not ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            log_color(RED, f"NO MATCH: {ip_pkt.srcip} no pertenece a {PRIVATE_SUBNET}/{PRIVATE_MASK}")
            return

        log_color(GREEN, f"MATCH: {ip_pkt.srcip} pertenece a la red privada {PRIVATE_SUBNET}/{PRIVATE_MASK}")

        dst_ip = ip_pkt.dstip

        # Si la MAC del destino ya se conoce, se instalan los flujos y se reenvía el paquete actual.
        # Caso contrario, se debe primero conocer la MAC y luego enviar el paquete. (Se encola el paquete)
        if dst_ip in self.arp_table:
            dst_mac = self.arp_table[dst_ip]
            self._install_and_forward(packet, in_port, dst_mac)
        else:
            self._add_pending_packet(dst_ip, packet, in_port)
            self._send_arp_request(dst_ip, PUBLIC_PORT, PUBLIC_IP, PUBLIC_MAC)
            log_color(YELLOW, f"MAC de {dst_ip} desconocida. Paquete encolado, ARP Request enviado.")

    def _create_flows(self, ip_pkt, origin_ip, origin_mac, origin_switch_port, dst_mac):
        """Construye y retorna los flow_mods base (saliente y entrante) sin considerar PAT.
        ip_pkt:             paquete IP original.
        origin_ip:          IP del host privado origen.
        origin_mac:         MAC del host privado origen.
        origin_switch_port: puerto del switch por donde llegó el paquete (red privada).
        dst_mac:            MAC del host destino (red pública), obtenida por ARP.
        """
        # Flujo Saliente
        fm = of.ofp_flow_mod()
        fm.idle_timeout = TIMEOUT_SECONDS

        # Filtro (Saliente)
        fm.match.nw_src  = origin_ip
        fm.match.dl_type = 0x800  # IPv4
        fm.match.in_port = origin_switch_port

        # Acción (Saliente)
        # 1. Se utiliza la IP y MAC pública del Router en vez de los datos del Host Privado.
        # 2. Se utiliza la MAC destino obtenida anteriormente por ARP.
        fm.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
        fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))

        # Flujo Entrante
        fm_back = of.ofp_flow_mod()
        fm_back.idle_timeout = TIMEOUT_SECONDS

        # Filtro (Entrante). Se recibe un mensaje en la IP pública del router.
        fm_back.match.nw_src  = ip_pkt.dstip
        fm_back.match.nw_dst  = PUBLIC_IP
        fm_back.match.dl_type = 0x800  # IPv4
        fm_back.match.in_port = PUBLIC_PORT

        # Acción (Entrante)
        # 1. Modificamos para enviar a la IP y MAC privada del Host.
        # 2. Se modifca el Origen para usar la MAC privada del router.
        fm_back.actions.append(of.ofp_action_nw_addr.set_dst(origin_ip))
        fm_back.actions.append(of.ofp_action_dl_addr.set_dst(origin_mac))
        fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
        fm_back.actions.append(of.ofp_action_output(port=origin_switch_port))

        return fm, fm_back

    def _apply_pat_to_flows(self, fm, fm_back, ip_pkt, private_port, public_port):
        """Modifica los flow_mods según corresponda dado la reasignación de puertos.
        1. Filtro saliente debe corresponder al protocolo y el puerto privado de origen.
        2. Como acción saliente, se debe insertar el puerto público elegido.
        3. Filtro entrante debe corresponder al protocolo pero al puerto público elegido.
        4. Al Filtro entrante se pide que notifique cierre de conexiones para liberar puertos.
        5. Como acción entrante, se debe modificar al puerto privado interno del host. """

        proto_name = "TCP" if ip_pkt.protocol == ipv4.TCP_PROTOCOL else "UDP"
        log_color(GREEN, f"PAT {proto_name}: {ip_pkt.srcip}:{private_port} → {ip_pkt.dstip}:{public_port}")

        # Filtro (Saliente): Agregar match de protocolo y puerto privado de origen.
        fm.match.nw_proto = ip_pkt.protocol
        fm.match.tp_src   = private_port
        # Acción (Saliente): Se modifica el puerto saliente para usar el puerto público elegido.
        fm.actions.insert(1, of.ofp_action_tp_port.set_src(public_port))

        # Filtro (Entrante): Agregar match de protocolo y puerto público.
        fm_back.match.nw_proto = ip_pkt.protocol
        fm_back.match.tp_dst   = public_port
        # Se agrega el FLAG para que se nos notifique cuando se libera el puerto.
        fm_back.flags = 1
        # Acción (Entrante): Se modifica el puerto entrante al puerto privado original.
        fm_back.actions.insert(1, of.ofp_action_tp_port.set_dst(private_port))

    def _install_and_forward(self, packet, in_port, dst_mac):
        """Instala flujos saliente/entrante y reenvía el paquete actual."""
        ip_pkt           = packet.payload
        private_ip       = ip_pkt.srcip
        private_host_mac = packet.src

        fm, fm_back = self._create_flows(ip_pkt, private_ip, private_host_mac, in_port, dst_mac)

        if self._should_apply_pat(ip_pkt):
            # Se realizan las modificaciones necesarias para el redireccionamiento de los puertos.
            transport    = ip_pkt.payload
            private_port = transport.srcport
            public_port  = self._allocate_nat_port()
            self._apply_pat_to_flows(fm, fm_back, ip_pkt, private_port, public_port)
            transport.srcport = public_port

        # Envío de los flujos al switch
        self.connection.send(fm)
        self.connection.send(fm_back)

        # Se modifica el paquete con la IP pública del router para reenviar el paquete actual.
        ip_pkt.srcip = PUBLIC_IP

        # Reenviar paquete actual con MACs e IP NAT actualizadas (Los posteriores pasan por flujo)
        packet.src   = PUBLIC_MAC
        packet.dst   = dst_mac
        msg = of.ofp_packet_out()
        msg.data = packet.pack()
        msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        log_color(CYAN, f"ENVIANDO: {private_ip} → {ip_pkt.dstip} | NAT IP: {PUBLIC_IP} | MAC: {PUBLIC_MAC} → {dst_mac} | Out Port: {PUBLIC_PORT}")
        self.connection.send(msg)


def launch():

    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
