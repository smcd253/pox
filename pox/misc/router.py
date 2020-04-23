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

def router_handler(rt_object, packet, packet_in):

  # Step 1: Arp Request from Source
  # if destination ip (packet.payload.dst) is on same network (longest prefix match) --> act like switch
    # switch_handler(rt_object, packet, packet_in)
  # else --> act like router
    # respond with arp reply
  
  # Step 2: ICMP Request (from source)
  # if destination ip is in THIS routing table --> make arp request
    # arp request to destination ip (packet.payload.dst)
  # else
    # broadcast arp request
  
  # Step 3: Arp Reply 
  # if reply successful --> forward ICMP request
  # else --> tell source (destination unreachable)

  ip = packet.payload.dst

  prefix_table = [ 24, 24, 24]
  lengthof=len(prefix_table)
  x=0
  ip_bin=0
  while x <= 3:
      temp = ip.split(".")[x]
      temp_int= int(temp)<<24-x*8
      ip_bin=temp_int+ip_bin
      x=x+1

  for x in range(0, lengthof-1):
      temp_dec= math.pow(2,prefix_table[x])
      temp_dec = int(temp_dec-1)
      temp_bin = temp_dec<<32-int(prefix_table[x])
      result_bin = temp_bin & ip_bin
      print("Match #", x)
      first= result_bin>>24
      second= result_bin & 16711680
      second= second>>16
      third= result_bin & 65280
      third= third>>8
      fourth= result_bin & 255
      key= str(first)+"."+str(second)+"."+str(third)+"."+str(fourth)+"/"+str(prefix_table[x])
      print(key)
      if key in rt_object.routing_table.keys():
        print("ip " + rt_object.routing_table.keys().index(key) + " in our network. Call switch_handler().")
        switch_handler(rt_object, packet, packet_in)
        break
      else:
          print("ip " + rt_object.routing_table.keys().index(key) + " NOT in our network. drop.")