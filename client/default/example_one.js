$fh.ready(function(){
  $('#submit_input_btn').bind("click", function(){
    doInputSubmit();
  });
  $('#clear_first_log_btn').bind('click', function(){
    clearLogs();
  })
})

function doInputSubmit(){
  log('Check if a public key already exists...');
  if(null == _public_key){
    log('No public key found, get one from server...');
    $fh.act({ act :'getPublicKey', secure: _use_secure, req:{}}, function(res){
      log('Got publick key...');
      _public_key = res;
      encryptAndSubmit();
    })
  } else {
    encryptAndSubmit();
  }
}

function getInputData(){
  return $('#example_one_input').val();
}

function encryptAndSubmit(){
  var input_data = getInputData();
  var params = {algorithm:'RSA', plaintext: input_data, modulu: _public_key.modulu};
  log('Encrypt data using the public key before sending to the server...');
  $fh.sec({act:'encrypt', params:params}, function(cipher){
    log('Data encrypted, ready to send...');
    var data_to_send = cipher.ciphertext;
    log('Sending data to server...');
    $fh.act({act:'decryptInput', secure: _use_secure, req:{
      details: data_to_send
    }}, function(response){
      log('Got response back from server...');
      if(response.result = "ok"){
        log("Server received message. The decrypt message is '" + response.message + "'");
      } else {
        log("Error : " + response.error);
      }
    })
  })
}
