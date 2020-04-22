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
# _flood_delay = 0
# def switch_handler(sw_object, packet, packet_in, port):

#   # floods packet instead of calling resend_packet
#   def flood (message = None):
#     """ Floods the packet """
#     msg = of.ofp_packet_out()
#     if time.time() - sw_object.connection.connect_time >= _flood_delay:
#       # Only flood if we've been connected for a little while...

#       if message is not None: log.debug(message)
#       #log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
#       # OFPP_FLOOD is optional; on some switches you may need to change
#       # this to OFPP_ALL.
#       msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
#     else:
#       pass
#       #log.info("Holding down flood for %s", dpid_to_str(event.dpid))
#     msg.data = packet
#     msg.in_port = port
#     sw_object.connection.send(msg)

#   def drop (duration = None):
#     """
#     Drops this packet and optionally installs a flow to continue
#     dropping similar ones for a while
#     """
#     if duration is not None:
#       if not isinstance(duration, tuple):
#         duration = (duration,duration)
#       msg = of.ofp_flow_mod()
#       msg.match = of.ofp_match.from_packet(packet)
#       msg.idle_timeout = duration[0]
#       msg.hard_timeout = duration[1]
#       sw_object.connection.send(msg)
#     elif packet.buffer_id is not None:
#       msg = of.ofp_packet_out()
#       msg.buffer_id = packet.buffer_id
#       msg.in_port = port
#       sw_object.connection.send(msg)

#   sw_object.mac_to_port[packet.src] = port # 1

#   if packet.dst.is_multicast:
#     flood() # 3a
#   else:
#     if packet.dst not in sw_object.mac_to_port: # 4
#       flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
#     else:
#       if port == sw_object.mac_to_port[packet.dst]: # 5
#         # 5a
#         log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
#             % (packet.src, packet.dst, sw_object.dpid, port))
#         drop(10)
#         return
#       # 6
#       log.debug("installing flow for %s.%i -> %s.%i" %
#                 (packet.src, port, packet.dst, sw_object.mac_to_port[packet.dst]))
#       msg = of.ofp_flow_mod()
#       msg.match = of.ofp_match.from_packet(packet, sw_object.mac_to_port[packet.dst])
#       msg.idle_timeout = 10
#       msg.hard_timeout = 30
#       msg.actions.append(of.ofp_action_output(port = sw_object.mac_to_port[packet.dst]))
#       msg.data = packet_in # 6a
#       sw_object.connection.send(msg)

def switch_handler(sw_object, packet, packet_in, _port):
  if packet.src not in sw_object.mac_to_port:
        print "Learning that " + str(packet.src) + " is attached at port " + str(packet_in.in_port)
        sw_object.mac_to_port[packet.src] = packet_in.in_port

  # if the port associated with the destination MAC of the packet is known:
  if packet.dst in sw_object.mac_to_port:
    # Send packet out the associated port
    print "Destination " + str(packet.dst) + " known. Forward msg to port " + str(sw_object.mac_to_port[packet.dst]) + "."
    # sw_object.resend_packet(packet_in, sw_object.mac_to_port[packet.dst])

    print "Installing flow..." + str(sw_object.mac_to_port[packet.dst])

    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet, sw_object.mac_to_port[packet.dst])
    msg.match.dl_dst = packet.dst
    # # msg.match.dl_type = 0x800
    # # msg.priority = 42
    # msg.idle_timeout = 60
    # msg.hard_timeout = 600
    msg.actions.append(of.ofp_action_output(port = sw_object.mac_to_port[packet.dst]))
    msg.data = packet_in
    sw_object.connection.send(msg)

  else:
    # Flood the packet out everything but the input port
    # This part looks familiar, right?
    print str(packet.dst) + " not known, resend to all ports."
    sw_object.resend_packet(packet_in, of.OFPP_ALL)
