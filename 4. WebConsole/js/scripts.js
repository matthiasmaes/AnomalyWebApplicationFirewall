$finalResult = {}

var dialogAdmin = document.querySelector('#adminURL');
var showDialogButtonAdmin = document.querySelector('#show-dialog-admin');

var dialogUser = document.querySelector('#userURL');
var showDialogButtonUser = document.querySelector('#show-dialog-user');

var dialogBot = document.querySelector('#botAgent');
var showDialogButtonBot = document.querySelector('#show-dialog-bot');

var dialogIP = document.querySelector('#malIP');
var showDialogButtonIP = document.querySelector('#show-dialog-ip');



if (!dialogAdmin.showModal) dialogPolyfill.registerDialog(dialogAdmin);
if (!dialogUser.showModal) dialogPolyfill.registerDialog(dialogUser);
if (!dialogBot.showModal) dialogPolyfill.registerDialog(dialogBot);
if (!dialogIP.showModal) dialogPolyfill.registerDialog(dialogIP);





showDialogButtonAdmin.addEventListener('click', function() { dialogAdmin.showModal(); });
showDialogButtonUser.addEventListener('click', function() { dialogUser.showModal(); });
showDialogButtonBot.addEventListener('click', function() { dialogBot.showModal(); });
showDialogButtonIP.addEventListener('click', function() { dialogIP.showModal(); });





dialogAdmin.querySelector('.submit').addEventListener('click', function() {
	dialogAdmin.close();
	$.ajax({url: 'api.php', data: "function=addAdmin&data=" + encodeURIComponent($('#adminUrlSubmission').val()) , dataType: "json"});
});

dialogUser.querySelector('.submit').addEventListener('click', function() {
	dialogUser.close();
	$.ajax({url: 'api.php', data: "function=addUser&data=" + encodeURIComponent($('#userUrlSubmission').val()) , dataType: "json"})
});

dialogBot.querySelector('.submit').addEventListener('click', function() {
	dialogBot.close();
	$.ajax({url: 'api.php', data: "function=addBot&data=" + encodeURIComponent($('#botAgentSubmission').val()) , dataType: "json"})
});

dialogIP.querySelector('.submit').addEventListener('click', function() {
	dialogIP.close();
	$.ajax({url: 'api.php', data: "function=addIP&data=" + encodeURIComponent($('#malIPSubmission').val()) , dataType: "json"})
});

document.querySelector('#clear-log').addEventListener('click', function() {
	$.ajax({url: 'api.php', data: "function=clearLog" , dataType: "json"})
	window.location.replace("index.html");
});




window.setInterval(function(){
	$.ajax({url: 'api.php', data: "function=getLog", dataType: "json", success: function(result){
		$(result).each(function(index){
			if (!($(this)[0]['_id']['$id'] in $finalResult)) {
				$finalResult[$(this)[0]['_id']['$id']] = $(this)[0]['message']
				$('#logMsg').prepend('<p class="logMsgEntry">' + $(this)[0]['message'] + '<p>')
			}
		});
	}});
}, 1000);



