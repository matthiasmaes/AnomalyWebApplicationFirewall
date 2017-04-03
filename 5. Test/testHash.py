import hashlib



def md5(fname):
	hash_md5 = hashlib.md5()
	with open(fname, "rb") as f:
		f.seek(-500, 2)
		hash_md5.update(f.read(500))

	return hash_md5.hexdigest()




print md5('C:/Users/bebxadvmmae/Desktop/BigLogs/BigAccessLogs/access.log')