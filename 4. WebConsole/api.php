<?php
	$connection = new MongoClient();
	if(isset($_GET['function'])) {
		if($_GET['function'] == 'getLog') {
			$dbname = $connection -> selectDB('engine_log');
			$collection = $dbname -> selectCollection('firewall_messages');
			$cursor = $collection -> find();
			$response = array();
			foreach ($cursor as $doc) array_push($response, $doc);
			echo json_encode($response);
		} elseif($_GET['function'] == 'addAdmin') {
			$dbname = $connection -> selectDB('config_static');
			$collection = $dbname -> selectCollection('profile_admin');
			$collection->insert(array('name' => $_GET['data']));
		} elseif($_GET['function'] == 'addUser') {
			$dbname = $connection -> selectDB('config_static');
			$collection = $dbname -> selectCollection('profile_user');
			$collection->insert(array('name' => $_GET['data']));
		}
	}
?>