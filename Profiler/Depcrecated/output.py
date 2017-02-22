#### Write storage to file (JSON)	####
if not os.path.exists(newpath):
	os.makedirs(newpath)
outputFileObj = open(outputProfilePath,"w") 
outputFileObj.write("[")
for index, objToWrite in enumerate(tmpStorage):


	# #### Connection obj -> dict ####
	# tmpJSON = []
	# for connection in objToWrite.connection:
	# 	tmpJSON.append(connection.__dict__)
	# objToWrite.connection = tmpJSON
	# ################################


	# #### Storage to JSON	####
	# dumpedObj = json.dumps(objToWrite.__dict__, indent=4)
	# outputFileObj.write(dumpedObj)
	# ############################


	#### Add ] add the end (valid JSON)	####
	if not index + 1 == len(tmpStorage):
		outputFileObj.write(",\n")
	else:
		outputFileObj.write("]")
	########################################


	# #### Save to MongoDB ####
	# MongoDB.insert_one(objToWrite.__dict__)		
	# #########################

outputFileObj.close()
########################################