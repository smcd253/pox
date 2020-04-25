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
    # DEBUG
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

# def is_in_local_routing_table(dest_subnet, local_routing_table):
#   strip_net_addrs = local_routing_table.keys()
#   for i in strip_net_addrs:
#     i = get_subnet(i)
#     print("routing table entry = " + i)
#   print("dest_subnet = " + dest_subnet)  
#   if dest_subnet in strip_net_addrs:
#     print("dest_subnet " + dest_subnet + " in routing table")
#     return True
#   else:
#     return False

def release_buffer(rt_object, dstip):
  while (len(rt_object.buffer[dstip]) > 0):
    # print("buffer[%s] = %s" % (dstip, rt_object.buffer[dstip]))
    msg = of.ofp_packet_out(buffer_id=rt_object.buffer[dstip][0]["buffer_id"], in_port=rt_object.buffer[dstip][0]["port"])
    msg.actions.append(of.ofp_action_dl_addr.set_dst(rt_object.ip_to_mac[dstip]))
    msg.actions.append(of.ofp_action_output(port = rt_object.ip_to_port[dstip]))
    rt_object.connection.send(msg)
    del rt_object.buffer[dstip][0]

def arp_handler(rt_object, packet, packet_in):
  print("this is an arp packet")

  # check if in rt_object.ip_to_mac, if not add
  if(packet.payload.protosrc not in rt_object.ip_to_mac):
    rt_object.ip_to_mac[packet.payload.protosrc] = packet.src

  # handle arp request
  # NOTE: this produces the same output. what is going on??
  print("packet.payload = " + str(packet.payload))
  print("packet._to_str() = " + packet._to_str())
  arp_dst_ip = str(packet.payload.protodst)
  arp_src_ip = str(packet.payload.protosrc)

  # DEBUG
  print("dst_ip = " + arp_dst_ip + ", src_ip = " + arp_src_ip)
  
  if packet.next.opcode == arp.REQUEST:
    # if destination ip is the router (default gw), generate arp response
    if (arp_dst_ip == rt_object.routing_table_r1[get_subnet(packet.payload.protosrc)]["router_interface"]):
      arp_reply = arp()
      arp_reply.opcode = arp.REPLY
      arp_reply.hwsrc = packet.dst #Destination now is the source MAC address
      arp_reply.hwdst = packet.src
      arp_reply.protosrc = packet.payload.protodst
      arp_reply.protodst= packet.payload.protosrc
      eth = ethernet()
      eth.type = ethernet.ARP_TYPE
      eth.dst = rt_object.ip_to_mac[packet.payload.protosrc]
      eth.src = packet.dst
      eth.payload = arp_reply
      msg = of.ofp_packet_out()
      msg.data = eth.pack()
      action = of.ofp_action_output(port = packet_in.in_port)
      msg.actions.append(action)

      print("ARP Reply: answering MAC %s on port %d" % (rt_object.ip_to_mac[packet.payload.protosrc], packet_in.in_port))
      rt_object.connection.send(msg)

    # if destination ip (packet.payload.protodst) is on same network and this network 
    # (longest prefix match) --> act like switch
    # if same_subnet(arp_dst_ip, arp_src_ip) and is_in_local_routing_table(get_subnet(arp_dst_ip), rt_object.routing_table_r1):
    elif same_subnet(arp_dst_ip, arp_src_ip):
      print("src ip: %s and dst ip: %s in same network." % (arp_src_ip, arp_dst_ip))
      switch_handler(rt_object, packet, packet_in)
    
    # DEBUG
    else:
      print("something went wrong")
  # if this is an arp reply    
  elif packet.next.opcode == arp.REPLY:
    # Learn source MAC addr of sender (next hop)
    rt_object.ip_to_mac[packet.payload.protosrc] = packet.next.hwsrc 
    rt_object.ip_to_port[packet.payload.protosrc] = packet_in.in_port

    # release buffer
    release_buffer(rt_object, packet.payload.protosrc)


# def ip_in_table(rt_object, packet, packet_in):
#   for (rt in rt_object):
#     if packet.next.dstip in rt:
#       return True
#   return False

def generate_arp_request(rt_object, packet, packet_in):
    arp_req = arp()
    arp_req.hwtype = arp_req.HW_TYPE_ETHERNET
    arp_req.prototype = arp_req.PROTO_TYPE_IP
    arp_req.hwlen = 6
    arp_req.protolen = arp_req.protolen
    arp_req.opcode = arp_req.REQUEST
    arp_req.hwdst = ETHER_BROADCAST
    arp_req.protodst = packet.next.dstip
    arp_req.hwsrc = packet.src 
    arp_req.protosrc = packet.next.srcip
    eth = ethernet(type=ethernet.ARP_TYPE, src=packet.src, dst=ETHER_BROADCAST)
    eth.set_payload(arp_req)
    msg = of.ofp_packet_out()
    msg.data = eth.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.in_port = packet_in.in_port
    rt_object.connection.send(msg)

    # log.debug("DPID %i, INPORT %i, sending ARP Request for %s on behalf of %s" % (dpid, inport, str(arp_req.protodst), str(arp_req.protosrc)))
    print("Sending ARP Request on behalf of host at IP %s on port %d." % (packet.next.srcip, packet_in.in_port))

def ipv4_handler(rt_object, packet, packet_in):
  print("got ipv4 packet!")
  print("packet.srcip = " + str(packet.next.srcip))
  print("packet.dstip = " + str(packet.next.dstip))
  print("packet.payload = " + str(packet.next.payload))
  # if destination ip is valid (in routing table or one of routers)
  # if ip_in_table(rt_object, packet, packet_in): # FIX THIS!!!
  valid_ip = True
  if valid_ip:
    # if packet meant for THIS router
      # if icmp packet and type == request
      # if isinstance(packet.next.next, icmp):

        # generate icmp reply
    # else (packet meant for someone else)
    # INDENT EVERYTHING UNDER HEAR!
    # if we are waiting for the arp reply to learn the mac address of the next hop
    # cache this packet
    if packet.next.dstip not in rt_object.ip_to_mac:
      # add a new buffer for this dstip if it does not already exist
      if packet.next.dstip not in rt_object.buffer:
        rt_object.buffer[packet.next.dstip] = []

      # cache packet
      buffer_entry = {"buffer_id": packet_in.buffer_id, "port": packet_in.in_port}
      rt_object.buffer[packet.next.dstip].append(buffer_entry)
      print("Destination: %s unknown. Buffer packet: %s" % (packet.next.dstip, packet_in.buffer_id))

      # generate arp request to learn next hop
      generate_arp_request(rt_object, packet, packet_in)
    
    # we've already received the arp reply, so forward to known destination
    else: 
      rt_object.resend_packet(packet_in, rt_object.ip_to_port[packet.next.dstip])

  # ip invalid, generate icmp reply dest unreachable
  else:
    # generate icmp reply (dest unreachable)
    return

def router_handler(rt_object, packet, packet_in):
  # if packet is arp
  if isinstance(packet.next, arp):
    arp_handler(rt_object, packet, packet_in)

  # else --> act like router 
  elif isinstance(packet.next, ipv4):
    ipv4_handler(rt_object, packet, packet_in)

  # Step 2: ICMP Request (from source) (if packet is icmp request or reply)
  # if destination ip is in THIS routing table --> make arp request
    # arp request to destination ip (packet.payload.dst)
  # else
    # broadcast arp request
  # else:
 
  
  
  
  # Step 3: Arp Reply 
  # if reply successful --> forward ICMP request
  # else --> tell source (destination unreachable)
