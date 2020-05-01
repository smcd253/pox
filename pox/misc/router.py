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

########################################## IP parsing functions ##########################################
#return network addr as string
def LPM(mask, ip):
    x=0
    ip_bin=0
    while x <= 3:
        temp = ip.split(".")[x]
        temp_int= int(temp)<<(24-x*8)
        ip_bin=temp_int+ip_bin
        x=x+1
    temp_dec= math.pow(2,int(mask))
    temp_dec = int(temp_dec-1)
    temp_bin = temp_dec<<(32-int(mask))
    result_bin = temp_bin & ip_bin
    first = result_bin>>24
    second = result_bin & 16711680
    second = second>>16
    third = result_bin & 65280
    third = third>>8
    fourth = result_bin & 255
    key = str(first)+"."+str(second)+"."+str(third)+"."+str(fourth)
    return key

def get_subnet(rt_object, dpid, ip):
  mask = 32
  match = ""
  while match not in rt_object.routing_table[dpid] and mask > 0:
    match = LPM(mask, str(ip))
    mask -= 1
  return match

def same_subnet(rt_object, dpid, ip1, ip2):
  return (get_subnet(rt_object, dpid, ip1) == get_subnet(rt_object, dpid, ip2))

def is_interface(rt_object, dpid, dstip):
  for subnet in rt_object.routing_table[dpid]:
    if(dstip == rt_object.routing_table[dpid][subnet]["router_interface"]):
      return True
  return False

def validate_ip(rt_object, dpid, ip):
  ip_sub = get_subnet(rt_object, dpid, ip)
  for subnet in rt_object.routing_table[dpid]:
    if ip_sub == subnet:
      return True
  return False

def get_subnet_from_interface_ip(rt_object, dpid, interface_ip):
  for subnet, table in rt_object.routing_table[dpid].iteritems():
    if(table["router_interface"] == interface_ip):
      return subnet
  return interface_ip

########################################## ARP functions ##########################################
def generate_arp_request(rt_object, dpid, endpoint_ip, destination_ip, packet, packet_in):
  """
  Composes and sends arp request.
  @param:   rt_object - controller object
  @param:   packet - ethernet packet (in this case, packet.next = arp packet)
  @param:   packet_in - ofp_packet_in object (switch to controller due to table miss)
  """
  arp_req = arp()
  arp_req.hwtype = arp_req.HW_TYPE_ETHERNET
  arp_req.prototype = arp_req.PROTO_TYPE_IP
  arp_req.hwlen = 6
  arp_req.protolen = arp_req.protolen
  arp_req.opcode = arp_req.REQUEST
  arp_req.hwdst = ETHER_BROADCAST
  arp_req.protodst = IPAddr(destination_ip)
  arp_req.hwsrc =  EthAddr(rt_object.routing_table[dpid][get_subnet(rt_object, dpid, packet.next.dstip)]["mac_interface"])
  # make source the interface for this route
  arp_req.protosrc = IPAddr(rt_object.routing_table[dpid][get_subnet(rt_object, dpid, endpoint_ip)]["router_interface"])
  eth = ethernet(type=ethernet.ARP_TYPE, src=packet.src, dst=ETHER_BROADCAST)
  eth.set_payload(arp_req)
  msg = of.ofp_packet_out()
  msg.data = eth.pack()
  msg.actions.append(of.ofp_action_output(port = rt_object.routing_table[dpid][get_subnet(rt_object, dpid, packet.next.dstip)]["port"]))
  msg.in_port = packet_in.in_port
  rt_object.connections[dpid].send(msg)

def generate_arp_reply(rt_object, dpid, packet, packet_in):
  arp_reply = arp()
  arp_reply.opcode = arp.REPLY
  ret_subnet = get_subnet_from_interface_ip(rt_object, dpid, packet.payload.protodst)
  arp_reply.hwsrc =  packet.dst
  # Destination now is the source MAC address
  arp_reply.hwdst = packet.src
  arp_reply.protosrc = packet.payload.protodst
  arp_reply.protodst = packet.payload.protosrc
  eth = ethernet()
  eth.type = ethernet.ARP_TYPE
  eth.dst = EthAddr(rt_object.ip_to_mac[dpid][str(packet.payload.protosrc)])
  # reply with this interface's mac addr
  eth.src =  rt_object.routing_table[dpid][get_subnet(rt_object, dpid, ret_subnet)]["mac_interface"]
  eth.payload = arp_reply
  msg = of.ofp_packet_out()
  msg.data = eth.pack()
  action = of.ofp_action_output(port = packet_in.in_port)
  msg.actions.append(action)
  rt_object.connections[dpid].send(msg)

def arp_handler(rt_object, dpid, packet, packet_in):
  """
  Handles all incoming arp packets.
  @param:   rt_object - controller object
  @param:   packet - ethernet packet (in this case, packet.next = arp packet)
  @param:   packet_in - ofp_packet_in object (switch to controller due to table miss)
  """
  # learn route
  # check if in rt_object.ip_to_mac[dpid], if not add
  if(str(packet.payload.protosrc) not in rt_object.ip_to_mac[dpid]):
    rt_object.ip_to_mac[dpid][str(packet.payload.protosrc)] = str(packet.src)
  # same with ip_to_port
  if(str(packet.payload.protosrc) not in rt_object.ip_to_port[dpid]):
    rt_object.ip_to_port[dpid][str(packet.payload.protosrc)] = packet_in.in_port

  # handle arp request
  arp_dst_ip = str(packet.payload.protodst)
  arp_src_ip = str(packet.payload.protosrc)

  if packet.next.opcode == arp.REQUEST:
    # if destination ip is the router (default gw), generate arp response
    if (arp_dst_ip == rt_object.routing_table[dpid][get_subnet(rt_object, dpid, get_subnet_from_interface_ip(rt_object, dpid, str(packet.payload.protodst)))]["router_interface"] or get_subnet(rt_object, dpid, arp_dst_ip) == "192.168.0.0" or get_subnet(rt_object, dpid, arp_dst_ip) == "192.168.0.4"):
     generate_arp_reply(rt_object, dpid, packet, packet_in)

    elif same_subnet(rt_object, dpid, arp_dst_ip, arp_src_ip):
      if(packet.dst == rt_object.routing_table[dpid][get_subnet(rt_object, dpid, arp_dst_ip)]["mac_interface"]):
        generate_arp_reply(rt_object, dpid, packet, packet_in)

  # if this is an arp reply    
  elif packet.next.opcode == arp.REPLY:
    # Learn source MAC addr of sender (next hop)
    rt_object.ip_to_mac[dpid][str(packet.payload.protosrc)] = str(packet.next.hwsrc)
    # release buffer
    release_buffer(rt_object, dpid, packet.payload.protosrc)

########################################## ICMP functions ##########################################
def generate_icmp_reply(rt_object, dpid, packet, icmp_type):
  """
  Composes and sends ICMP reply. Only happens if router interface is destination or destination unreachable.
  @param:   rt_object - controller object
  @param:   packet - ethernet packet (in this case, packet.next = arp packet)
  @param:   icmp_type - icmp reply or destinatio unreachable
  """
  p_icmp = icmp()
  p_icmp.type = icmp_type

  if icmp_type == TYPE_ECHO_REPLY:
    p_icmp.payload = packet.next.next.payload

  elif icmp_type == TYPE_DEST_UNREACH:
    ip = packet.find('ipv4')
    dest_unreach = ip.pack()
    dest_unreach = dest_unreach[:ip.hl * 4 + 8] # add 'destination unreachable" icmp code
    dest_unreach = struct.pack("!HH", 0, 0) + dest_unreach
    p_icmp.payload = dest_unreach

  ip_packet = ipv4()
  ip_packet.protocol = ip_packet.ICMP_PROTOCOL
  ip_packet.srcip = packet.next.dstip  
  ip_packet.dstip = packet.next.srcip

  eth_packet = ethernet()
  # force eth src to be this mac interface
  eth_packet.src = rt_object.routing_table[dpid][get_subnet(rt_object, dpid, packet.next.srcip)]["mac_interface"]
  eth_packet.dst = packet.src
  eth_packet.type = eth_packet.IP_TYPE
 
  ip_packet.payload = p_icmp
  eth_packet.payload = ip_packet
 
  msg = of.ofp_packet_out()
  msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
  msg.data = eth_packet.pack()
  msg.in_port = rt_object.ip_to_port[dpid][str(packet.next.srcip)]
  rt_object.connections[dpid].send(msg)

########################################## IPV4 functions ##########################################
def ip_flow_mod(rt_object, dpid, packet, dest_ip):
  """
  Performs IP flow modification and route learning so router does not have to contact controller
  on arrival of every ipv4 packet.
  @param:   rt_object - controller object
  @param:   packet - ethernet packet (in this case, packet.next = arp packet)
  """
  msg = of.ofp_flow_mod()
  msg.priority = 1000 # set priority to highest
  msg.match.dl_type = 0x800 # type: ip
  msg.match.nw_src = packet.next.srcip
  msg.match.nw_dst = packet.next.dstip
  msg.actions.append( of.ofp_action_dl_addr.set_dst(EthAddr(rt_object.ip_to_mac[dpid][str(dest_ip)])))
  msg.actions.append( of.ofp_action_output(port = rt_object.ip_to_port[dpid][str(dest_ip)]))
  rt_object.connections[dpid].send(msg)


def send_ip_packet(rt_object, dpid, buf_id, inport, dstip):
  """
  Sends ip packet to selected destination ip.
  @param:   rt_object - controller object
  @param:   buf_id - buffer id of outgoing packet
  @param:   inport - port we received packet from
  @param:   dstip - destination ip
  """
  msg = of.ofp_packet_out(buffer_id=buf_id, in_port=inport)
  msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(rt_object.ip_to_mac[dpid][str(dstip)])))
  msg.actions.append(of.ofp_action_output(port = rt_object.ip_to_port[dpid][str(dstip)]))
  rt_object.connections[dpid].send(msg)

def release_buffer(rt_object, dpid, dstip):
  """
  Releases ipv4 buffer.
  @param:   rt_object - controller object
  @param:   dstip - destination ip
  """
  while (len(rt_object.buffer[dpid][str(dstip)]) > 0):
    send_ip_packet(rt_object, dpid, rt_object.buffer[dpid][str(dstip)][0]["buffer_id"], rt_object.buffer[dpid][str(dstip)][0]["port"], dstip)
    del rt_object.buffer[dpid][str(dstip)][0]

def ipv4_handler(rt_object, dpid, packet, packet_in):
  """
  Handles all incoming ipv4 packets.
  @param:   rt_object - controller object
  @param:   packet - ethernet packet (in this case, packet.next = arp packet)
  @param:   packet_in - ofp_packet_in object (switch to controller due to table miss)
  """
  # learn route
  rt_object.ip_to_port[dpid][str(packet.next.srcip)] = packet_in.in_port

  # if destination ip is valid (in routing table or one of routers)
  # if ip_in_table(rt_object, packet, packet_in): # FIX THIS!!!
  if validate_ip(rt_object, dpid, packet.next.dstip):
    # if packet meant for THIS router
    if(is_interface(rt_object, dpid, str(packet.next.dstip))):
      if isinstance(packet.next.next, icmp):
        if(packet.next.next.type == TYPE_ECHO_REQUEST):
          generate_icmp_reply(rt_object, dpid, packet, TYPE_ECHO_REPLY)

    else:
      destination_ip = None
      # if packet is meant for network connected to another router, forward to next hop
      next_hop = rt_object.routing_table[dpid][get_subnet(rt_object, dpid, packet.next.dstip)]["next_hop"]
      if(next_hop != "0.0.0.0"):
        destination_ip = next_hop
      else:
        destination_ip = str(packet.next.dstip)

      # if we are waiting for the arp reply to learn the mac address of the next hop
      # cache this packet
      if destination_ip not in rt_object.ip_to_mac[dpid] or destination_ip not in rt_object.ip_to_port[dpid]:
        # add a new buffer for this dstip if it does not already exist
        if destination_ip not in rt_object.buffer[dpid]:
          rt_object.buffer[dpid][destination_ip] = []


        # cache packet
        buffer_entry = {"buffer_id": packet_in.buffer_id, "port": packet_in.in_port}
        rt_object.buffer[dpid][destination_ip].append(buffer_entry)

        # generate arp request to learn next hop
        generate_arp_request(rt_object, dpid, packet.next.dstip, destination_ip, packet, packet_in)
 
      # we've already received the arp reply, so forward to known destination
      else:
        send_ip_packet(rt_object, dpid, packet_in.buffer_id, packet_in.in_port, destination_ip)

        # flow mod
        ip_flow_mod(rt_object, dpid, packet, destination_ip)

  # ip invalid, generate icmp reply dest unreachable
  else:
    generate_icmp_reply(rt_object, dpid, packet, TYPE_DEST_UNREACH)

########################################## MAIN CODE ##########################################
def router_handler(rt_object, dpid, packet, packet_in):
  """
  Handles all packet coming into switch type 'router.'
  @param:   rt_object - controller object
  @param:   packet - ethernet packet (in this case, packet.next = arp packet)
  @param:   packet_in - ofp_packet_in object (switch to controller due to table miss)
  """
  if isinstance(packet.next, arp):
    arp_handler(rt_object, dpid, packet, packet_in)

  elif isinstance(packet.next, ipv4):
    ipv4_handler(rt_object, dpid, packet, packet_in)