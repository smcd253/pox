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

def switch_handler(sw_object, dpid, packet, packet_in):
  format_src_mac_addr_str = str(EthAddr(format_src_mac_addr_str))
  format_dst_mac_addr_str = str(EthAddr(format_dst_mac_addr_str))

  if format_src_mac_addr_str not in sw_object.mac_to_port[dpid]:
    print("Learning that " + format_src_mac_addr_str + " is attached at port " + str(packet_in.in_port))
    sw_object.mac_to_port[dpid][format_src_mac_addr_str] = packet_in.in_port

  # if the port associated with the destination MAC of the packet is known:
  if format_dst_mac_addr_str in sw_object.mac_to_port[dpid]:
    # Send packet out the associated port
    print("Destination " + str(format_dst_mac_addr_str) + " known. Forward msg to port " + str(sw_object.mac_to_port[dpid][format_dst_mac_addr_str]) + ".")
    sw_object.resend_packet(dpid, packet_in, sw_object.mac_to_port[dpid][format_dst_mac_addr_str])

    # flow mod
    print("Installing flow..." + str(sw_object.mac_to_port[dpid][format_dst_mac_addr_str]))
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)
    msg.match = of.ofp_match(dl_dst = format_dst_mac_addr_str)
    msg.idle_timeout = 3600
    msg.hard_timeout = 7200
    msg.priority = 32768 # A0
    msg.actions.append(of.ofp_action_output(port = sw_object.mac_to_port[dpid][format_dst_mac_addr_str]))
    sw_object.connections[dpid].send(msg)

  else:
    # Flood the packet out everything but the input port
    # This part looks familiar, right?
    print("SWITCH_HANDLER(): DPID = %s. MAC %s not known. Resend to all ports." % (dpid, str(format_dst_mac_addr_str)))
    sw_object.resend_packet(dpid, packet_in, of.OFPP_ALL)
