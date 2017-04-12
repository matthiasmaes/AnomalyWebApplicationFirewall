import iptc
from datetime import datetime
# CREATE NEW TABLE #
table = iptc.Table(iptc.Table.FILTER)

chain = iptc.Chain(table, "INPUT")

rule = iptc.Rule()
rule.src = "192.168.137.129" 
rule.target = rule.create_target("DROP")
rule.match = rule.create_match("comment").comment = str(datetime.now())
chain.insert_rule(rule)
