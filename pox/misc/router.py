"""
[555 Comments]
Your router code and any other helper functions related to router should be written in this file
"""
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import *
from pox.lib.addresses import *
from pox.lib.packet.icmp import *
from pox.lib.packet.ipv4 import *
from collections import OrderedDict
import math

log = core.getLogger()

"""
[555 Comments]
  Function : router_handler
  Input Parameters:
      rt_object : The router object. This will be initialized in the controller file corresponding to the scenario in __init__
                  function of tutorial class. Any data structures you would like to use for a router should be initialized
                  in the contoller file corresponding to the scenario.
      packet    : The packet that is received from the packet forwarding switch.
      packet_in : The packet_in object that is received from the packet forwarding switch
"""
def switch_handler(sw_object, packet, packet_in):
  if packet.src not in sw_object.mac_to_port:
        print "Learning that " + str(packet.src) + " is attached at port " + str(packet_in.in_port)
        sw_object.mac_to_port[packet.src] = packet_in.in_port

  # if the port associated with the destination MAC of the packet is known:
  if packet.dst in sw_object.mac_to_port:
    # Send packet out the associated port
    print "Destination " + str(packet.dst) + " known. Forward msg to port " + str(sw_object.mac_to_port[packet.dst]) + "."
    sw_object.resend_packet(packet_in, sw_object.mac_to_port[packet.dst])

    # flow mod
    print "Installing flow..." + str(sw_object.mac_to_port[packet.dst])
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet, sw_object.mac_to_port[packet.dst])
    msg.match.dl_dst = packet.dst
    msg.actions.append(of.ofp_action_output(port = sw_object.mac_to_port[packet.dst]))
    sw_object.connection.send(msg)

  else:
    # Flood the packet out everything but the input port
    # This part looks familiar, right?
    print str(packet.dst) + " not known, resend to all ports."
    sw_object.resend_packet(packet_in, of.OFPP_ALL)

def get_subnet(ip):
  s = str(ip)
  (a,b,c,d) = s.split('.')
  return a+"."+b+"."+c+"."+"0"

def same_subnet(ip1, ip2):
  return (get_subnet(ip1) == get_subnet(ip2))

def is_in_local_routing_table(ip, local_routing_table):
  if ip in local_routing_table.keys():
    return True
  else:
    return False

def router_handler(rt_object, packet, packet_in):

  # if packet is arp
  if not isinstance(pacet.next, ipv4):
    # arp request
    # if destination ip (packet.payload.protodst) is on same network (longest prefix match) --> act like switch
    arp_dst_ip = str(packet.payload.protodst)
    arp_src_ip = str(packet.payload.protosrc)
    if same_subnet(arp_dst_ip, arp_src_ip):
      switch_handler(rt_object, packet, packet_in)
      
  # else --> act like router
    # respond with arp reply
  # Step 2: ICMP Request (from source) (if packet is icmp request or reply)
  # if destination ip is in THIS routing table --> make arp request
    # arp request to destination ip (packet.payload.dst)
  # else
    # broadcast arp request
  else:

 
  
  
  
  # Step 3: Arp Reply 
  # if reply successful --> forward ICMP request
  # else --> tell source (destination unreachable)

  

  my_subnet = get_subnet(src_ip)
  dest_subnet = get_subnet(dst_ip)
  if (my_subnet is dest_subnet):
    switch_handler(rt_object, )
  else if ()
