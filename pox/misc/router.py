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

# TODO: modify all datastructures and functions to take dpid

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
#return netwrok addr as a string
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

########################################## ARP functions ##########################################
def generate_arp_reply(rt_object, dpid, packet, packet_in): 
  arp_reply = arp() 
  arp_reply.opcode = arp.REPLY 
  arp_reply.hwsrc = packet.dst 
  #Destination now is the source MAC address 
  arp_reply.hwdst = packet.src 
  arp_reply.protosrc = packet.payload.protodst 
  arp_reply.protodst = packet.payload.protosrc 
  eth = ethernet() 
  eth.type = ethernet.ARP_TYPE 
  eth.dst = rt_object.ip_to_mac[dpid][packet.payload.protosrc] 
  eth.src = packet.dst 
  eth.payload = arp_reply 
  msg = of.ofp_packet_out() 
  msg.data = eth.pack() 
  action = of.ofp_action_output(port = packet_in.in_port) 
  msg.actions.append(action) 
  rt_object.connections[dpid].send(msg) 
  print("GENERATE_ARP_REPLY(): eth.src = " + str(eth.src))
  
def arp_handler(rt_object, dpid, packet, packet_in):
  """
  Handles all incoming arp packets.
  @param:   rt_object - controller object
  @param:   packet - ethernet packet (in this case, packet.next = arp packet)
  @param:   packet_in - ofp_packet_in object (switch to controller due to table miss)
  """
  # learn route
  rt_object.ip_to_port[dpid][packet.next.protosrc] = packet_in.in_port

  # check if in rt_object.ip_to_mac[dpid], if not add
  if(packet.payload.protosrc not in rt_object.ip_to_mac[dpid]):
    rt_object.ip_to_mac[dpid][packet.payload.protosrc] = packet.src
  # same with ip_to_port
  if(packet.payload.protosrc not in rt_object.ip_to_port[dpid]):
    rt_object.ip_to_port[dpid][packet.payload.protosrc] = packet_in.in_port

  # handle arp request
  # NOTE: this produces the same output. what is going on??
  print("ARP_HANDLER(): packet.payload = " + str(packet.payload))
  arp_dst_ip = str(packet.payload.protodst)
  arp_src_ip = str(packet.payload.protosrc)

  # DEBUG
  print("ARP_HANDLER(): dst_ip = " + arp_dst_ip + ", src_ip = " + arp_src_ip)
  
  if packet.next.opcode == arp.REQUEST:
    # if destination ip is the router (default gw), generate arp response
    if (arp_dst_ip == rt_object.routing_table[dpid][get_subnet(rt_object, dpid, packet.payload.protosrc)]["router_interface"]):
      generate_arp_reply(rt_object, dpid, packet, packet_in)

      # DEBUG
      print("ARP_HANDLER(): Generate ARP Reply: answering MAC %s on port %d" % (rt_object.ip_to_mac[dpid][packet.payload.protosrc], packet_in.in_port))

    # if destination ip (packet.payload.protodst) is on same network and this network 
    # (longest prefix match) --> act like switch
    # if same_subnet(rt_object, dpid, arp_dst_ip, arp_src_ip) and is_in_local_routing_table(get_subnet(rt_object, dpid, arp_dst_ip), rt_object.routing_table[dpid]):
    elif same_subnet(rt_object, dpid, arp_dst_ip, arp_src_ip):
      print("ARP_HANDLER(): src ip: %s and dst ip: %s in same network." % (arp_src_ip, arp_dst_ip))
      # act_like_switch(rt_object, dpid, packet, packet_in)
      if(packet.dst == rt_object.routing_table[dpid][get_subnet(rt_object, dpid, arp_dst_ip)]["mac_interface"]):
        generate_arp_reply(rt_object, dpid, packet, packet_in)

    # DEBUG
    else:
      print("ARP_HANDLER(): something went wrong")
    

  # if this is an arp reply    
  elif packet.next.opcode == arp.REPLY:
    # DEBUG
    print("ARP_HANDLER(): Received ARP reply... learn source MAC Addr and release ip buffer.")
    
    # Learn source MAC addr of sender (next hop)
    rt_object.ip_to_mac[dpid][packet.payload.protosrc] = packet.next.hwsrc 

    # release buffer
    release_buffer(rt_object, dpid, packet.payload.protosrc)

def generate_arp_request(rt_object, dpid, destination_ip, packet, packet_in):
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
  arp_req.protodst = destination_ip
  arp_req.hwsrc = packet.src 
  arp_req.protosrc = packet.next.srcip
  eth = ethernet(type=ethernet.ARP_TYPE, src=packet.src, dst=ETHER_BROADCAST)
  eth.set_payload(arp_req)
  msg = of.ofp_packet_out()
  msg.data = eth.pack()
  msg.actions.append(of.ofp_action_output(port = rt_object.routing_table[dpid][get_subnet(rt_object, dpid, packet.next.dstip)]["port"]))
  msg.in_port = packet_in.in_port
  rt_object.connections[dpid].send(msg)

  print("Sending ARP Request on behalf of host at IP %s on port %d." % (packet.next.srcip, packet_in.in_port))

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
  eth_packet.src = packet.dst
  eth_packet.dst = packet.src
  eth_packet.type = eth_packet.IP_TYPE
  
  ip_packet.payload = p_icmp
  eth_packet.payload = ip_packet
  
  msg = of.ofp_packet_out()
  msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
  msg.data = eth_packet.pack()
  msg.in_port = rt_object.ip_to_port[dpid][packet.next.srcip]
  rt_object.connections[dpid].send(msg)

  # DEBUG
  print('GENERATE_ICMP_REPLY(): Replying to %s with code %d.', str(packet.next.srcip), icmp_type)

########################################## IPV4 functions ##########################################
def ip_flow_mod(rt_object, dpid, packet):
  """
  Performs IP flow modification and route learning so router does not have to contact controller
  on arrival of every ipv4 packet.
  @param:   rt_object - controller object
  @param:   packet - ethernet packet (in this case, packet.next = arp packet)
  """
  msg = of.ofp_flow_mod()
  msg.idle_timeout = 3600
  msg.hard_timeout = 7200
  msg.priority = 1000 # set priority to highest
  msg.match.dl_type = 0x800 # type: ip
  msg.match.nw_dst = packet.next.dstip
  msg.actions.append( of.ofp_action_dl_addr.set_dst(rt_object.ip_to_mac[dpid][packet.next.dstip]) )
  msg.actions.append( of.ofp_action_output(port = rt_object.ip_to_port[dpid][packet.next.dstip]) )
  rt_object.connections[dpid].send(msg)

  # DEBUG
  print("IP_FLOW_MOD(): Learning IP %s corresponds to MAC %s on PORT %d." % (str(packet.next.dstip), str(rt_object.ip_to_mac[dpid][packet.next.dstip]), rt_object.ip_to_port[dpid][packet.next.dstip]))

def send_ip_packet(rt_object, dpid, buf_id, inport, dstip):
  """
  Sends ip packet to selected destination ip.
  @param:   rt_object - controller object
  @param:   buf_id - buffer id of outgoing packet
  @param:   inport - port we received packet from
  @param:   dstip - destination ip
  """
  msg = of.ofp_packet_out(buffer_id=buf_id, in_port=inport)
  msg.actions.append(of.ofp_action_dl_addr.set_dst(rt_object.ip_to_mac[dpid][dstip]))
  msg.actions.append(of.ofp_action_output(port = rt_object.ip_to_port[dpid][dstip]))
  rt_object.connections[dpid].send(msg)

  # DEBUG
  print("SEND_IP_PACKET(): Sending BUFFER_ID %d from IN_PORT %d to IP %s at MAC %s on OUT_PORT %d." % (buf_id, inport, str(dstip), str(rt_object.ip_to_mac[dpid][dstip]), rt_object.ip_to_port[dpid][dstip]))

def release_buffer(rt_object, dpid, dstip):
  """
  Releases ipv4 buffer.
  @param:   rt_object - controller object
  @param:   dstip - destination ip
  """
  while (len(rt_object.buffer[dpid][dstip]) > 0):
    send_ip_packet(rt_object, dpid, rt_object.buffer[dpid][dstip][0]["buffer_id"], rt_object.buffer[dpid][dstip][0]["port"], dstip)
    del rt_object.buffer[dpid][dstip][0]
  
  # DEBUG
  # print("RELEASE_BUFFER(): buffer[%s] = %s" % (dstip, rt_object.buffer[dpid][dstip]))
  print("RELEASE_BUFFER(): Not logging right now. Uncomment above to get more info.")

def ipv4_handler(rt_object, dpid, packet, packet_in):
  """
  Handles all incoming ipv4 packets.
  @param:   rt_object - controller object
  @param:   packet - ethernet packet (in this case, packet.next = arp packet)
  @param:   packet_in - ofp_packet_in object (switch to controller due to table miss)
  """
  # learn route
  rt_object.ip_to_port[dpid][packet.next.srcip] = packet_in.in_port

  print("IPV4_HANDLER(): packet.srcip = " + str(packet.next.srcip))
  print("IPV4_HANDLER(): packet.dstip = " + str(packet.next.dstip))
  print("IPV4_HANDLER(): packet.payload = " + str(packet.next.payload))

  # if destination ip is valid (in routing table or one of routers)
  # if ip_in_table(rt_object, packet, packet_in): # FIX THIS!!!
  if validate_ip(rt_object, dpid, packet.next.dstip):
    # if packet meant for THIS router
    if(is_interface(rt_object, dpid, packet.next.dstip)):
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
        destination_ip = packet.next.dstip

      # if we are waiting for the arp reply to learn the mac address of the next hop
      # cache this packet
      if destination_ip not in rt_object.ip_to_mac[dpid] or destination_ip not in rt_object.ip_to_port[dpid]:
        # add a new buffer for this dstip if it does not already exist
        if destination_ip not in rt_object.buffer[dpid]:
          rt_object.buffer[dpid][destination_ip] = []

        # cache packet
        buffer_entry = {"buffer_id": packet_in.buffer_id, "port": packet_in.in_port}
        rt_object.buffer[dpid][destination_ip].append(buffer_entry)
        print("IPV4_HANDLER(): Destination: %s unknown. Buffer packet: %s" % (packet.next.dstip, packet_in.buffer_id))

        # generate arp request to learn next hop
        generate_arp_request(rt_object, dpid, destination_ip, packet, packet_in)
  
      # we've already received the arp reply, so forward to known destination
      else:
        print("IPV4_HANDLER(): Sending packet %s out PORT %d" % (str(packet.payload), rt_object.ip_to_port[dpid][packet.next.dstip]))
        send_ip_packet(rt_object, dpid, packet_in.buffer_id, packet_in.in_port, packet.next.dstip) 

        # flow mod
        ip_flow_mod(rt_object, dpid, packet)

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
  # if packet is arp
  if isinstance(packet.next, arp):
    arp_handler(rt_object, dpid, packet, packet_in)

  # else --> act like router 
  elif isinstance(packet.next, ipv4):
    ipv4_handler(rt_object, dpid, packet, packet_in)

