import iptc
from datetime import datetime

table = iptc.Table(iptc.Table.FILTER)
chain = iptc.Chain(table, "INPUT")
index = 0

for rule in chain.rules:
	index += 1
	print index
	for match in rule.matches:

		datetime_object = datetime.strptime(match.comment, "%y-%m-%d %H:%M:%S")

		if datetime.now() > datetime_object:
			chain.delete_rule(rule)
