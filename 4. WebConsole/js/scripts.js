$finalResult = {}
$colors = ['#9C27B0', '#009688', '#FF9800', '#607D8B']
oldColor = '0'


var dialogAdmin = document.querySelector('#adminURL');
var showDialogButtonAdmin = document.querySelector('#show-dialog-admin');

var dialogUser = document.querySelector('#userURL');
var showDialogButtonUser = document.querySelector('#show-dialog-user');







if (!dialogAdmin.showModal) dialogPolyfill.registerDialog(dialogAdmin);
if (!dialogUser.showModal) dialogPolyfill.registerDialog(dialogUser);

showDialogButtonAdmin.addEventListener('click', function() { dialogAdmin.showModal(); });
showDialogButtonUser.addEventListener('click', function() { dialogUser.showModal(); });




dialogAdmin.querySelector('.submit').addEventListener('click', function() {
	dialogAdmin.close();
	$.ajax({url: 'api.php', data: "function=addAdmin&data=" + encodeURIComponent($('#adminUrlSubmission').val()) , dataType: "json"});
});

dialogUser.querySelector('.submit').addEventListener('click', function() {
	dialogUser.close();
	$.ajax({url: 'api.php', data: "function=addUser&data=" + encodeURIComponent($('#userUrlSubmission').val()) , dataType: "json"});

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

	newColor = Math.floor(Math.random() * 3)
	do {newColor = Math.floor(Math.random() * 3)} while (newColor == oldColor)
	oldColor = newColor

}, 1000);



