<?php
	$connection = new MongoClient();
	$dbname = $connection -> selectDB('engine_log');
	$collection = $dbname -> selectCollection('firewall_messages');
	$cursor = $collection -> find();

	$response = array();
	foreach ($cursor as $doc) array_push($response, $doc);

	echo json_encode($response)
?>