from pox.core import core

import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Routing (object):

  def get_subnet(self, ip):
    print("Finding subnet")
    if ip.startswith("169.233.3."):
      print("Found Faculty")
      return "Faculty"
    elif ip.startswith("169.233.1."):
      print("Found IT")
      return "IT"
    elif ip.startswith("129.244.41."):
      print("Found Student")
      return "Student"
    elif ip.startswith("129.233.21."):
      print("Found Data Center")
      return "Data Center"
    elif (ip=="212.26.59.102"):
      print("Found Trusted1")
      return "Trusted1"
    elif (ip=="10.100.198.6"):
      print("Found Trusted2")
      return "Trusted2"
    elif (ip=="10.100.198.10"):
      print("Found Guest")
      return "Guest"
    elif (ip=="17.20.4.80"):
      print("Found Discord")
      return "Discord"
    else:
      return f'Unknown Source: {ip}'
  
  def get_subnet_from_switch(self, switch_id, port_on_switch):
    if switch_id == 2:
      print("Found Faculty")
      return "Faculty"
    elif switch_id == 4:
      print("Found IT")
      return "IT"
    elif switch_id == 3:
      print("Found Student")
      return "Student"
    elif switch_id == 5:
      print("Found Data Center")
      return "Data Center"
    elif switch_id == 1:
      if port_on_switch == 5:
          return "Trusted2"
      elif port_on_switch == 6:
          return "Guest"
      elif port_on_switch == 7:
          return "Trusted1"
      elif port_on_switch == 8:
          return "Discord"
    else:
      return "Unknown"

  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)
    
    self.mac_to_ip = {
    	"00:00:00:00:03:10":"169.233.3.10", #facultyWS
    	"00:00:00:00:03:20":"169.233.3.20", #printer
    	"00:00:00:00:03:30":"169.233.3.30", #facultyPC
    	"00:00:00:00:21:24":"129.233.21.245", #examServer
    	"00:00:00:00:21:02":"129.233.21.2", #webServer
    	"00:00:00:00:21:03":"129.233.21.3", #dnsServer
    	"00:00:00:00:01:25":"169.233.1.250", #itBackup
    	"00:00:00:00:01:10":"169.233.1.100", #itWS
    	"00:00:00:00:01:20":"169.233.1.200", #itPC
    	"00:00:00:00:41:01":"129.244.41.1", #studentPC1
    	"00:00:00:00:41:03":"129.244.41.100", #labWS
    	"00:00:00:00:41:02":"129.244.41.2", #studentPC2
    	"00:00:00:00:99:01":"212.26.59.102", #trustedPC1
    	"00:00:00:00:99:02":"10.100.198.6", #trustedPC2
    	"00:00:00:00:99:03":"10.100.198.10", #guest
    	"00:00:00:00:99:04":"17.20.4.80", #dServer
    }
    
  def get_core_uplink_port(self, switch_id):
        uplink_ports = {
  	        2: 1,
  	        3: 4,
  	        4: 3,
  	        5: 2,
    	}
        return uplink_ports.get(switch_id,None)
  
  def get_host_port_same_subnet(self, switch_id, IP):
      host_ports = {
          2: {'169.233.3.30':4, '169.233.3.10':2, '169.233.3.20':3},
          3: {'129.244.41.1':1, '129.244.41.100':2, '129.244.41.2':3},
          4: {'169.233.1.250':1, '169.233.1.100':2, '169.233.1.200':4},
          5: {'129.233.21.245':1, '129.233.21.2':3, '129.233.21.3':4},
          1: {'212.26.59.102':7, '10.100.198.6':5, '10.100.198.10':6, '17.20.4.80':8}
      }
      return host_ports.get(switch_id, {}).get(IP,None)
  
  def get_host_port(self, switch_id, subnet_name):
      host_ports = {
          2: {'facultyPC':4, 'facultyWS':2, 'printer':3},
          3: {'studentPC1':1, 'labWS':2, 'studentPC2':3},
          4: {'itBackup':1, 'itWS':2, 'itPC':4},
          5: {'examServer':1, 'webServer':3, 'dnsServer':4}
      }
      return host_ports.get(switch_id, {}).get(subnet_name,None)
    	
  def do_routing (self, packet, packet_in, port_on_switch, switch_id):
    # port_on_swtich - the port on which this packet was received
    # switch_id - the switch which received this packet
    
    print("***packet:")
    print(packet)
    print("***packet_in:")
    print(packet_in)
    print("***port on switch:")
    print(port_on_switch)
    print("***switch id:")
    print(switch_id)
    print("***subnet:")
    print(self.get_subnet_from_switch(switch_id, port_on_switch))
    
    arp = packet.find('arp')
    print("***arp:")
    print(arp)
    ip = packet.find('ip')
    print("****ip:")
    print(ip)
    tcp = packet.find('tcp')
    print("****tcp:")
    print(tcp)
    udp = packet.find('udp')
    print("****udp:")
    print(udp)
    icmp = packet.find('icmp')
    print("****icmp:")
    print(icmp)

    def accept(out_port=None):
      print("Running ACCEPT function")
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet, packet_in.in_port)
      msg.idle_timeout = 10
      msg.hard_timeout = 30
      if out_port is None:
        print("Flooding enabled")
        out_port = of.OFPP_FLOOD
      msg.actions.append(of.ofp_action_output(port=out_port))
      msg.data = packet_in
      self.connection.send(msg)
      log.info(f"Packet accepted on switch {switch_id}, out_port={out_port}")

    def drop():
      print("Running DROP function")
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet, packet_in.in_port)
      msg.idle_timeout = 10
      msg.hard_timeout = 30
      self.connection.send(msg)
      log.info(f"Packet dropped on switch {switch_id}")

    def get_port(device):
      port_map = {
        "Faculty": 1,
        "Data Center": 2,
        "IT": 3,
        "Student": 4,
        "Trusted2": 5,
        "Guest": 6,
        "Trusted1": 7,
        "Discord": 8
      }
      return port_map.get(device, None)
    
    #Accept ARP
    if arp is not None:
      print("Accept: ARP")
      accept()
      return
    
    src_mac = str(packet.src)
    print(src_mac)
    dst_mac = str(packet.dst)
    print(dst_mac)
    src_ip = None
    dst_ip = None

    if ip is not None:
      print("IP found")
      src_ip = str(ip.srcip)
      dst_ip = str(ip.dstip)
      src_subnet = self.get_subnet(src_ip)
      dst_subnet = self.get_subnet(dst_ip)
    else:
      print("No IP found - Using MAC Lookup instead")
      #drop()
      #return
      src_ip = self.mac_to_ip.get(src_mac, "Unknown") # Returns unknown if not found in lookup
      dst_ip = self.mac_to_ip.get(dst_mac, "Unknown")
      print(src_ip)
      print(dst_ip)
      if dst_ip == "Unknown":
      	print(f"Dropping switch={switch_id} due to unknown Destination IP")
      	drop()
      	return
      else:
      	src_subnet = self.get_subnet(src_ip)
      	dst_subnet = self.get_subnet(dst_ip)

    
    
    print("Source:")
    print(src_ip)
    print(src_subnet)
    print("Destination:")
    print(dst_ip)
    print(dst_subnet)
    
    #Discord Server Custom Rule
    #Switch_ID should always be 1 if running from dServer to Student, can be either 1 or studentSwitch if running from Student to dServer
    print("Testing if Student-Discord Traffic")
    
    if (src_subnet=="Student" and dst_ip=='17.20.4.80') or (dst_subnet=="Student" and src_ip=='17.20.4.80'):
        print(f"Accepted Student - Discord Traffic: Destination = {get_port(dst_subnet)}")
        print(f"self.get_subnet_from_switch: {self.get_subnet_from_switch(switch_id, port_on_switch)} => dst_subnet: {dst_subnet}")
        
        if dst_ip == '17.20.4.80':
            if switch_id == 1:
                print(f"Core switch, forwarding to dServer")
                accept(8)
                return
            elif switch_id == 3:
                print("Forwarding to Core")
                uplink = self.get_core_uplink_port(switch_id)
                print(f"Sending via uplink: {uplink}")
                accept(uplink)
                return
        elif dst_subnet == "Student":
            if switch_id == 1:
                print("Forwarding Discord Traffic to Student Subnet")
                accept(4)
                return
            elif switch_id == 3:
                print("Forwarding to End User")
                accept(self.get_host_port_same_subnet(switch_id, dst_ip))
                return
        else:
            print("Something went wrong!")
            drop()
            return
    
    #Rule 1
    if icmp is not None:
      print("Testing Rule 1: ICMP")
      print(f"Currently on switch {switch_id} trying to reach {dst_ip}")
      if ((src_subnet=="IT" and dst_subnet in ["Faculty", "Student"]) or
       (dst_subnet=="IT" and src_subnet in ["Faculty", "Student"]) or
        src_subnet==dst_subnet):
        print(f"Accepted ICMP: Destination = {get_port(dst_subnet)}")
        if self.get_subnet_from_switch(switch_id, port_on_switch) == dst_subnet:
            print(f"Same subnet, forwarding to {dst_ip} using {self.get_host_port_same_subnet(switch_id, dst_ip)}")
            accept(self.get_host_port_same_subnet(switch_id, dst_ip))
            return
        elif switch_id == 1:
            print(f"Core switch, forwarding to {dst_ip}'s switch using {get_port(dst_subnet)} port")
            accept(get_port(dst_subnet))
            return
        else:
            print(f"Subnet switch, forwarding to coreSwitch using {get_port(src_subnet)} port")
            uplink = self.get_core_uplink_port(switch_id)
            accept(uplink)
            return
      else:
        print(f"Dropping due to Rule 1: src_subnet={src_subnet}, dst_subnet={dst_subnet}")
        drop()
        return

    #Rule 2
    if tcp is not None:
      print("Testing Rule 2: TCP")
      print(f"Currently on switch {switch_id} trying to reach {dst_ip}")
      #Faculty LAN for Faculty Exam Server
      if (dst_ip == "129.233.21.245" or src_ip == "129.233.21.245"):
          if (src_subnet == "Faculty" or dst_subnet == "Faculty"):
              print("Accepted TCP: Faculty trying to reach Faculty Exam Server")
              if switch_id==1:
                  print(f"Core switch forwarding")
                  accept(get_port(dst_subnet))
              elif self.get_subnet_from_switch(switch_id, port_on_switch) == dst_subnet:
                  print(f"Same subnet, forwarding to {dst_ip} using {self.get_host_port_same_subnet(switch_id, dst_ip)}")
                  accept(self.get_host_port_same_subnet(switch_id, dst_ip))
              else:
                  uplink = self.get_core_uplink_port(switch_id)
                  accept(uplink)
              return
          else:
              print("Unauthorized Exam Server Request")
              drop()
              return
      
      if ((src_subnet in ["Data Center", "IT", "Faculty", "Student"] and dst_subnet in ["Data Center", "IT", "Faculty", "Student"]) or
          (src_subnet in ["Data Center", "Trusted1", "Trusted2", "Guest"] and dst_subnet in ["Data Center", "Trusted1", "Trusted2", "Guest"]) or
          (src_subnet==dst_subnet)):
        print(f"Accepted TCP: Destination = {get_port(dst_subnet)}")
        
        if self.get_subnet_from_switch(switch_id, port_on_switch) == dst_subnet:
            print(f"Same subnet, forwarding to {dst_ip} using {self.get_host_port_same_subnet(switch_id, dst_ip)}")
            accept(self.get_host_port_same_subnet(switch_id, dst_ip))
        elif switch_id == 1:
            print(f"Core switch, forwarding to {dst_ip}'s switch using {get_port(dst_subnet)} port")
            accept(get_port(dst_subnet))
        else:
            print(f"Subnet switch, forwarding to coreSwitch using {get_port(src_subnet)} port")
            uplink = self.get_core_uplink_port(switch_id)
            accept(uplink)
        return
      
      
      elif (src_subnet in ["Guest", "Trusted1", "Trusted2"] and dst_ip == "169.233.3.20") or (dst_subnet in ["Guest", "Trusted1", "Trusted2"] and src_ip == "169.233.3.20"): #Let printer pass without dropping yet
        print("Judging Printer Traffic Later...")
        pass
      else:
        print(f"Dropping TCP: Source={src_subnet}, Dest.={dst_subnet}")
        drop()
        return

    #Rule 3
    if udp is not None:
      if ((src_subnet in ["Data Center", "IT", "Faculty", "Student"] and dst_subnet in ["Data Center", "IT", "Faculty", "Student"]) or
          (src_subnet == dst_subnet)):
        print(f"Accepting UDP: Destination = {get_port(dst_subnet)}")
        if self.get_subnet_from_switch(switch_id, port_on_switch) == dst_subnet:
            print(f"Same subnet, forwarding to {dst_ip} using {self.get_host_port_same_subnet(switch_id, dst_ip)}")
            accept(self.get_host_port_same_subnet(switch_id, dst_ip))
            return
        elif switch_id == 1:
            print(f"Core switch, forwarding to {dst_ip}'s switch using {get_port(dst_subnet)} port")
            accept(get_port(dst_subnet))
            return
        else:
            print(f"Subnet switch, forwarding to coreSwitch using {get_port(src_subnet)} port")
            uplink = self.get_core_uplink_port(switch_id)
            accept(uplink)
            return
      else:
        drop()
        return

    #Rule 4
    if tcp is not None:
      if dst_ip == "169.233.3.20" and src_subnet in ["Guest", "Trusted1", "Trusted2"]:
        print(f"Accepted Printer-Bound TCP: Destination = {get_port(dst_subnet)}")
        if self.get_subnet_from_switch(switch_id, port_on_switch) == dst_subnet:
            print(f"Same subnet, forwarding to {dst_ip} using {self.get_host_port_same_subnet(switch_id, dst_ip)}")
            accept(self.get_host_port_same_subnet(switch_id, dst_ip))
            return
        elif switch_id == 1:
            print(f"Core switch, forwarding to {dst_ip}'s switch using {get_port(dst_subnet)} port")
            accept(get_port(dst_subnet))
            return
        else:
            print(f"Subnet switch, forwarding to coreSwitch using {get_port(src_subnet)} port")
            uplink = self.get_core_uplink_port(switch_id)
            accept(uplink)
            return
      elif (src_ip == "169.233.3.20" and dst_subnet in ["Guest", "Trusted1", "Trusted2"]):
        print(f"Accepted Printer-Sourced TCP: Destination = {get_port(dst_subnet)}")
        if self.get_subnet_from_switch(switch_id, port_on_switch) == dst_subnet:
            print(f"Same subnet, forwarding to {dst_ip} using {self.get_host_port_same_subnet(switch_id, dst_ip)}")
            accept(self.get_host_port_same_subnet(switch_id, dst_ip))
            return
        elif switch_id == 1:
            print(f"Core switch, forwarding to {dst_ip}'s switch using {get_port(dst_subnet)} port")
            accept(get_port(dst_subnet))
            return
        else:
            print(f"Subnet switch, forwarding to coreSwitch using {get_port(src_subnet)} port")
            uplink = self.get_core_uplink_port(switch_id)
            accept(uplink)
            return
      
      else:
        print("Dropping Unapproved Printer Traffic")
        drop()
        return

    #Rule 5
    drop()
    return
    

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.s
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_routing(packet, packet_in, event.port, event.dpid)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Routing(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
