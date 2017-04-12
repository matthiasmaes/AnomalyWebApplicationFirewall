import iptc
from datetime import datetime

def blockIpTable(ip):
	table = iptc.Table(iptc.Table.FILTER)
	chain = iptc.Chain(table, "INPUT")
	rule = iptc.Rule()
	rule.src = ip
	rule.target = rule.create_target("DROP")
	rule.match = rule.create_match("comment").comment = str(datetime.now())
	chain.insert_rule(rule)