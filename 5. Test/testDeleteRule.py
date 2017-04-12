import iptc
table = iptc.Table(iptc.Table.FILTER)
chain = iptc.Chain(table, "INPUT")
index = 0

for rule in chain.rules:
	index += 1
	print index
	for match in rule.matches:
		print match.comment
		if match.comment == 'Eindelijk werkt dit!!!':
			chain.delete_rule(rule)
