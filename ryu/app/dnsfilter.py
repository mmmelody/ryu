from ryu.lib import pcaplib
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller import ofp_event
from ryu.lib.packet import packet, ethernet, udp, ipv4
import dnslib
import re

class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		self.mac_to_port = {}
		self.pcap_pen = pcaplib.Writer(open('record.pcap', 'wb'))
		self.handle = open('/home/gui/Downloads/hosts.txt')
		self.check = 0

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]
		ipa = pkt.get_protocols(ipv4.ipv4)[0]
		self.logger.info("	-----[PACKET IN]-----")
		
		string = dnslib.DNSRecord.parse(pkt[3]).questions[0]
		m_string = str(string)
		self.logger.info(m_string)
		domain_name = re.findall('\w+\.', m_string)
		domain_name = ''.join(domain_name)
		domain_name = domain_name[:-1]
		self.logger.info("DNS PACKET : %s", domain_name)
		if eth.ethertype==2048:
			if self.check:
				ipa = re.findall('\d+', ipa)
				ipa.reverse()
				ipa = '.'.join(ipa)
			
				dp = msg.datapath
				parser = dp.ofproto_parser

				self.logger.info("IP add: %s",ipa)
				actions = [] #DROP
				match1 = parser.OFPMatch(eth_type = 2048, ipv4_src = ipa)
				match2 = parser.OFPMatch(eth_type = 2048, ipv4_dst = ipa)

				self.add_flow(dp, 4001, match1, actions)
				self.add_flow(dp, 4002, match2, actions)
				self.logger.info("	-----DROP: %s-----",ipa)
				o_pkt = None
				if msg.buffer_id == ofproto.OFP_NO_BUFFER:
					o_pkt = msg.data
				out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
        			datapath.send_msg(out) 
				self.check = 0

			else:
				self.handle.seek(0,0)
				for line in self.handle:
					line = line.rstrip()
					if re.search(domain_name, line):
						self.logger.info("MATCH :%s",domain_name)
						self.check = 1
		
		self.pcap_pen.write_pkt(msg.data)

	def add_flow(self, datapath, priority, match, actions):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		mod = parser.OFPFlowMod(datapath = datapath, priority = priority, match = match, instructions = inst)
		datapath.send_msg(mod)
