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