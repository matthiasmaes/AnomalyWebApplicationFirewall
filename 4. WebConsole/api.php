<?php
	$connection = new MongoClient();
	if(isset($_GET['function'])) {
		if($_GET['function'] == 'getLog') {
			$dbname = $connection -> selectDB('engine_log');
			$collection = $dbname -> selectCollection('firewall_messages');
			$cursor = $collection -> find();
			$cursor -> sort(array('_id' => -1));
			$cursor -> limit(100);
			$response = array();
			foreach ($cursor as $doc) array_push($response, $doc);
			echo json_encode($response);
		} elseif($_GET['function'] == 'addAdmin') {
			$dbname = $connection -> selectDB('config_static');
			$collection = $dbname -> selectCollection('profile_admin');
			$collection -> insert(array('name' => $_GET['data']));
		} elseif($_GET['function'] == 'addUser') {
			$dbname = $connection -> selectDB('config_static');
			$collection = $dbname -> selectCollection('profile_user');
			$collection -> insert(array('name' => $_GET['data']));
		} elseif ($_GET['function'] == 'addBot') {
			$dbname = $connection -> selectDB('config_static');
			$collection = $dbname -> selectCollection('profile_bots');
			$collection -> insert(array('agent' => $_GET['data']));
		} elseif ($_GET['function'] == 'addIP') {
			$dbname = $connection -> selectDB('config_static');
			$collection = $dbname -> selectCollection('firewall_blocklist');
			$collection -> insert(array('ip' => $_GET['data']));
		} elseif ($_GET['function'] == 'clearLog') {
			$dbname = $connection -> selectDB('engine_log');
			$collection = $dbname -> selectCollection('firewall_messages');
			$collection -> remove(array());
		}
	}
?>