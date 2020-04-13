"""
[555 Comments]
Your switch code and any other helper functions related to switch should be written in this file
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
  Function : switch_handler
  Input Parameters:
      sw_object : The switch object. This will be initialized in the controller file corresponding to the scenario in __init__
                  function of tutorial class. Any data structures you would like to use for a switch should be initialized
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
    print "Destination " + str(packet.dst) + " known. Forward msg to port " + sw_object.mac_to_port[packet.dst] "."
    sw_object.resend_packet(packet_in, sw_object.mac_to_port[packet.dst])

    # Once you have the above working, try pushing a flow entry
    # instead of resending the packet (comment out the above and
    # uncomment and complete the below.)

    # log.debug("Installing flow...")
    # Maybe the log statement should have source/destination/port?

    #msg = of.ofp_flow_mod()
    #
    ## Set fields to match received packet
    #msg.match = of.ofp_match.from_packet(packet)
    #
    #< Set other fields of flow_mod (timeouts? buffer_id?) >
    #
    #< Add an output action, and send -- similar to resend_packet() >

  else:
    # Flood the packet out everything but the input port
    # This part looks familiar, right?
    print str(packet.dst) + " not known, resend to all ports."
    sw_object.resend_packet(packet_in, of.OFPP_ALL)