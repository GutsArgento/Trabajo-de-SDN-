from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

def run():
    # Instanciar red apuntando al controlador remoto Ryu
    net = Mininet(switch=OVSSwitch, controller=RemoteController)
    print("[*] Levantando el controlador remoto...")
    c0 = net.addController('c0', ip='127.0.0.1', port=6653)

    print("[*] Creando 3 switches OpenFlow 1.3...")
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')

    print("[*] Instanciando hosts y servidores...")
    # VLAN 10 - Administración
    h1 = net.addHost('h1', ip='10.0.10.1/24', mac='00:00:00:00:10:01')
    h2 = net.addHost('h2', ip='10.0.10.2/24', mac='00:00:00:00:10:02')
    h3 = net.addHost('h3', ip='10.0.10.3/24', mac='00:00:00:00:10:03')
    srv_admin = net.addHost('srv_admin', ip='10.0.10.100/24', mac='00:00:00:00:10:99')

    # VLAN 20 - Laboratorios
    h4 = net.addHost('h4', ip='10.0.20.1/24', mac='00:00:00:00:20:04')
    h5 = net.addHost('h5', ip='10.0.20.2/24', mac='00:00:00:00:20:05')
    h6 = net.addHost('h6', ip='10.0.20.3/24', mac='00:00:00:00:20:06')
    srv_lab = net.addHost('srv_lab', ip='10.0.20.100/24', mac='00:00:00:00:20:99')

    # VLAN 30 - Invitados
    h7 = net.addHost('h7', ip='10.0.30.1/24', mac='00:00:00:00:30:07')
    h8 = net.addHost('h8', ip='10.0.30.2/24', mac='00:00:00:00:30:08')
    h9 = net.addHost('h9', ip='10.0.30.3/24', mac='00:00:00:00:30:09')

    print("[*] Conectando enlaces troncales...")
    net.addLink(s1, s2)
    net.addLink(s2, s3)

    print("[*] Distribuyendo nodos de acceso en los switches...")
    # Nodos en s1
    net.addLink(h1, s1)
    net.addLink(h4, s1)
    net.addLink(h7, s1)
    net.addLink(srv_admin, s1)
    # Nodos en s2
    net.addLink(h2, s2)
    net.addLink(h5, s2)
    net.addLink(h8, s2)
    net.addLink(srv_lab, s2)
    # Nodos en s3
    net.addLink(h3, s3)
    net.addLink(h6, s3)
    net.addLink(h9, s3)

    net.start()
    print("\n[*] Infraestructura lista. Abriendo CLI...")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
