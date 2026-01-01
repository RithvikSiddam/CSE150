#!/usr/bin/python3
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController

class MyTopology(Topo):
  def __init__(self):
    Topo.__init__(self)
   
    facultyWS = self.addHost('facultyWS', ip='169.233.3.10/24', mac='00:00:00:00:03:10', defaultRoute="facultyWS-eth1")
    printer = self.addHost('printer', ip='169.233.3.20/24', mac='00:00:00:00:03:20', defaultRoute="printer-eth1")
    facultyPC = self.addHost('facultyPC', ip='169.233.3.30/24', mac='00:00:00:00:03:30', defaultRoute="facultyPC-eth1")
    s2 = self.addSwitch('s2')

    self.addLink(facultyWS, s2, port1=1, port2=2)
    self.addLink(printer, s2, port1=1, port2=3)
    self.addLink(facultyPC, s2, port1=1, port2=4)

    examServer = self.addHost('examServer', ip='129.233.21.245/24', mac='00:00:00:00:21:24', defaultRoute="examServer-eth1")
    webServer = self.addHost('webServer', ip='129.233.21.2/24', mac='00:00:00:00:21:02', defaultRoute="webServer-eth1")
    dnsServer = self.addHost('dnsServer', ip='129.233.21.3/24', mac='00:00:00:00:21:03', defaultRoute="dnsServer-eth1")
    s5 = self.addSwitch('s5')

    self.addLink(examServer, s5, port1=1, port2=1)
    self.addLink(webServer, s5, port1=1, port2=3)
    self.addLink(dnsServer, s5, port1=1, port2=4)

    itBackup = self.addHost('itBackup', ip='169.233.1.250/24', mac='00:00:00:00:01:25', defaultRoute="itBackup-eth1")
    itWS = self.addHost('itWS', ip='169.233.1.100/24', mac='00:00:00:00:01:10', defaultRoute="itWS-eth1")
    itPC = self.addHost('itPC', ip='169.233.1.200/24', mac='00:00:00:00:01:20', defaultRoute="itPC-eth1")
    s4 = self.addSwitch('s4')

    self.addLink(itBackup, s4, port1=1, port2=1)
    self.addLink(itWS, s4, port1=1, port2=2)
    self.addLink(itPC, s4, port1=1, port2=4)

    studentPC1 = self.addHost('studentPC1', ip='129.244.41.1/24', mac='00:00:00:00:41:01', defaultRoute="studentPC1-eth1")
    labWS = self.addHost('labWS', ip='129.244.41.100/24', mac='00:00:00:00:41:03', defaultRoute="labWS-eth1")
    studentPC2 = self.addHost('studentPC2', ip='129.244.41.2/24', mac='00:00:00:00:41:02', defaultRoute="studentPC2-eth1")
    s3 = self.addSwitch('s3')

    self.addLink(studentPC1, s3, port1=1, port2=1)
    self.addLink(labWS, s3, port1=1, port2=2)
    self.addLink(studentPC2, s3, port1=1, port2=3)

    trustedPC1 = self.addHost('trustedPC1', ip='212.26.59.102/32', mac='00:00:00:00:99:01', defaultRoute="trustedPC1-eth1")
    trustedPC2 = self.addHost('trustedPC2', ip='10.100.198.6/32', mac='00:00:00:00:99:02', defaultRoute="trustedPC2-eth1")
    guest = self.addHost('guest', ip='10.100.198.10/32', mac='00:00:00:00:99:03', defaultRoute="guest-eth1")
    
    dServer = self.addHost('dServer', ip='17.20.4.80/24', mac='00:00:00:00:99:04', defaultRoute="dServer-eth1") # Change this to 32 once that is working

    s1 = self.addSwitch('s1')
    
    self.addLink(s2, s1, port1=1, port2=1)
    self.addLink(s5, s1, port1=2, port2=2)
    self.addLink(s4, s1, port1=3, port2=3)
    self.addLink(s3, s1, port1=4, port2=4) # student
    self.addLink(trustedPC2, s1, port1=1, port2=5)
    self.addLink(guest, s1, port1=1, port2=6)
    self.addLink(trustedPC1, s1, port1=1, port2=7)
    
    self.addLink(dServer, s1, port1=1, port2=8)
    

if __name__ == '__main__':
  #This part of the script is run when the script is executed
  topo = MyTopology() #Creates a topology
  c0 = RemoteController(name='c0', controller=RemoteController, ip='127.0.0.1', port=6633) #Creates a remote controller
  net = Mininet(topo=topo, controller=c0) #Loads the topology
  net.start() #Starts mininet
  
  
  guest = net.get('guest')
  trustedPC1 = net.get('trustedPC1')
  trustedPC2 = net.get('trustedPC2')
  dServer = net.get('dServer')
  
  guest.cmd('ifconfig guest-eth1 10.100.198.10 netmask 255.255.255.255')
  guest.cmd('ip route add default dev guest-eth1')
  
  trustedPC1.cmd('ifconfig trustedPC1-eth1 212.26.59.102 netmask 255.255.255.255')
  trustedPC1.cmd('ip route add default dev trustedPC1-eth1')
  
  trustedPC2.cmd('ifconfig trustedPC2-eth1 10.100.198.6 netmask 255.255.255.255')
  trustedPC2.cmd('ip route add default dev trustedPC2-eth1')
  
  dServer.cmd('ifconfig dServer-eth1 17.20.4.80 netmask 255.255.255.255')
  dServer.cmd('ip route add default dev dServer-eth1')
  
  
  CLI(net) #Opens a command line to run commands on the simulated topology
  net.stop() #Stops mininet
