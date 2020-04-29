# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
[555 Comments]
This is the controller file corresponding to scenario 2.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import *
from pox.lib.addresses import *
from pox.lib.packet.icmp import *
from pox.lib.packet.ipv4 import *
from switch import *
from router import *
from collections import OrderedDict
from pox.lib.util import dpid_to_str

log = core.getLogger()

class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)
    self.dpid = dpid_to_str(connection.dpid)
    
    """
    [555 Comments]
    In scenario 2, there is only one router. So, classify it as a router and initialize all the data structures you need for
    the router here.
    For the details of port info table, routing table, look into the project description document provided.
    Initialize all the data structures you wish to for the router in this function

    A word of caution:
    Your router and switch code should be the same for all scenarios. So, be careful to design your data structures for router
    and switches in such a way that your single piece of switch code and router code along with your data structure design
    should work for all the scenarios
    """
    # mannage all connections
    self.connections = {}

    # mac to port table (for in-network switching)
    self.mac_to_port = {}

    # buffer
    self.buffer = {}

    # ip to mac table
    self.ip_to_mac = {}
    
    # ip to port table
    self.ip_to_port = {}

    # self.routing_table = {""" fill with routing table """}
    self.routing_table_r1 = { "10.0.0.0": {"prefix": 24, "port": 1, "mac_interface": "02:00:DE:AD:BE:11", "router_interface": "10.0.0.1", "next_hop": "0.0.0.0"},
                              "20.0.0.0": {"prefix": 24, "port": 2, "mac_interface": "02:00:DE:AD:BE:12", "router_interface": "20.0.0.1", "next_hop": "0.0.0.0"},
                              "30.0.0.0": {"prefix": 24, "port": 3, "mac_interface": "02:00:DE:AD:BE:13", "router_interface": "30.0.0.1", "next_hop": "0.0.0.0"}}
    
    self.routing_table = {self.dpid: self.routing_table_r1}

  def add_new_switch(self, event):
    """
    Creates relevant data structures for newly connected switch.
    @param: event - switch connection event
    """
    dpid = dpid_to_str(event.connection.dpid)
    if dpid not in self.connections:
      self.connections[dpid] = event.connection
    if dpid not in self.mac_to_port:
      self.mac_to_port[dpid] = {}
    if dpid not in self.buffer:
      self.buffer[dpid] = {}
    if dpid not in self.ip_to_mac:
      self.ip_to_mac[dpid] = {}
    if dpid not in self.ip_to_port:
      self.ip_to_port[dpid] = {}

  def resend_packet(self, dpid, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connections[dpid].send(msg)
    
  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    # add new switches and routers for every connection made
    self.add_new_switch(event)

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    """
    [555 Comments]
    You need to classify a device as either switch or router based on its DPID received in the connection object during
    initialization in __init__ function in tutorial class. Based on the device type you need to call the respective function
    Here is the pseudo code to write

    if packet received from device type is switch:
      invoke switch_handler and pass the object (i.e., self) and the packet and packet_in
    else: (if it is not switch, it means router. We have only two kinds of devices, one is switch and one is router)
      invoke router_handler and pass the object (i.e., self) and the packet and packet_in
    """
    router_handler(self, self.dpid, packet, packet_in)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    #log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)