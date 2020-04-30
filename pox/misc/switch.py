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
  src_mac = packet.src
  dst_mac = dst_mac_str
  if type(src_mac) is not EthAddr:
    src_mac = EthAddr(src_mac)
  src_mac_str = str(src_mac)
  if type(dst_mac) is not EthAddr:
    src_mac = EthAddr(dst_mac)
  dst_mac_str = str(dst_mac)

  print("SWITCH_HANDLER(%s): src_mac_str = %s | dst_mac_str = %s" % (dpid, src_mac_str, dst_mac_str))

  if src_mac_str not in sw_object.mac_to_port[dpid]:
    print("SWITCH_HANDLER(%s): Learning that SOURCE MAC %s is attached to port %d" % (dpid, src_mac_str, packet_in.in_port))
    sw_object.mac_to_port[dpid][src_mac_str] = packet_in.in_port

  # if the port associated with the destination MAC of the packet is known:
  if dst_mac_str in sw_object.mac_to_port[dpid]:
    # Send packet out the associated port
    print("SWITCH_HANDLER(%s): DESINTATION MAC %s known. Forward to port %d" % (dpid, dst_mac_str, sw_object.mac_to_port[dpid][dst_mac_str]))
    sw_object.resend_packet(dpid, packet_in, sw_object.mac_to_port[dpid][dst_mac_str])

    # flow mod
    print("SWITCH_HANDLER(%s): Installing flow... src_mac_str = %s | dst_mac_str = %s" % (dpid, src_mac_str, dst_mac_str))
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)
    msg.match = of.ofp_match(dl_dst = dst_mac)
    msg.idle_timeout = 3600
    msg.hard_timeout = 7200
    msg.priority = 32768 # A0
    msg.actions.append(of.ofp_action_output(port = sw_object.mac_to_port[dpid][dst_mac_str]))
    sw_object.connections[dpid].send(msg)

  else:
    # Flood the packet out everything but the input port
    # This part looks familiar, right?
    print("SWITCH_HANDLER(%s): MAC %s not known. Resend to all ports." % (dpid, str(dst_mac_str)))
    sw_object.resend_packet(dpid, packet_in, of.OFPP_ALL)
