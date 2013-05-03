//bind events when the app is ready
$fh.ready(function(){
  $('#login_btn').unbind().bind("click", function(){
    preLogin();
  });
  $('#clear_two_log_btn_one, #clear_two_log_btn_two').unbind().bind('click', function(){
    clearLogs();
  });
  $('#get_secret_key_enc').unbind().bind("click", function(){
    getSecretKeyEnc();
  })
   $('#get_secret_key_dec').unbind().bind("click", function(){
    getSecretKeyDec();
  })
  //reset the pages
  $('#example_div_second_first_page, #example_div_second_second_page').bind('pagebeforeshow', function(){
    $(this).find('textarea').attr('rows', 3).empty();
    $(this).find('.hidden').css('display', 'none');
  })
})

function preLogin(){
  log('Check if public key already exists...');
  if(null == _public_key){
    log('Public key not found, request for the server\'s public key...');
    $fh.act({ act :'getPublicKey', secure: _use_secure, req:{}}, function(res){
      log('Got server\'s public key...');
      _public_key = res;
      generateSecretKey(doOnlineBankingLogin);
    })
  } else {
    log('Public key found, continue...');
    generateSecretKey(doOnlineBankingLogin);
  }
}

function generateSecretKey(cb){
  log('Check if there is a secret key already been generated...');
  if(null == _secret_key){
    log('No secret key found, generate a new one...');
    //keysize is in bytes, a bug really, should be in bits
    $fh.sec({act:'keygen', params:{algorithm:'AES', keysize:'128'}}, function(sec_key){
      log('A secret key has been generated.');
      _secret_key = sec_key.secretkey;
      _initial_iv = sec_key.iv;
      log('secretkey is ' + _secret_key);
      exchangeSecretKey(cb);
    });
  }else{
    log('A secret key found, no need to generate another one.');
    exchangeSecretKey(cb);
  }
}

//exchange the secret key securely using RSA
function exchangeSecretKey(cb){
  log('Check if the client and the server has exchanged the secret key before...');
  if(null != _session_id){
    log('Secret key exchange has been done before, continue...');
    cb();
  }else{
    log('Going to exchange the secret key with the server...');
    log('Generate a random nonce for verfication...');
    var nonce = generate_random_text(24);
    log('A random nonce has been generated.');
    log('Encrypt the secret key with server\'s public key...');
    $fh.sec({act:'encrypt', params:{algorithm:"RSA", plaintext: JSON.stringify({key: _secret_key, iv:_initial_iv}), modulu: _public_key.modulu}}, 
      function(cipher){
        log('Secret key has been encrypted. Send it to the server...');
        var exchange_data = {'cipher': cipher.ciphertext, 'nonce': nonce, 'keysize': 128};
        $fh.act({act:'exchangeSecretKey', secure: _use_secure, req:exchange_data}, function(response){
          log('Server got the encrypted secret key. Verify the server response to make sure it\'s correct...');
          var encrypt_hash_value = response.verify;
          log("verification value is " + encrypt_hash_value);
          log('To verify, decrypt the server reponse with the secret key...');
          $fh.sec({act:'decrypt', params:{algorithm:'AES', ciphertext: encrypt_hash_value, key: _secret_key, iv: _initial_iv}}, function(decrypt_data){
            log('Decryption complete. Compare it with the md5 hash value of the nonce, it should be the same.');
            var hash_value = decrypt_data.plaintext;
            log("remote hash value is " + hash_value);
            $fh.sec({act:'hash', params:{algorithm:'MD5', text: nonce}}, function(local_hash){
              log("local hash value is " + local_hash.hashvalue);
              if(hash_value == local_hash.hashvalue){
                log('Hash values are the same. Secret key has been verified. Secret key exchange completed.');
                _session_id = response.__session_id;
                cb();
              } else {
                log('Hash values are different. Secret key verification failed.');
                alert("Error. Secret key verification failed.");
              }
            })
          })
        })
      }
    )
  }
}

//ecrypt all the outbound requests and decrypt all the inbound requests
function doSecureCommunication(action, data, callback){
  log('Encrypt data using the shared secret key before sending to server...');
  $fh.sec({act:'encrypt', params: {algorithm:'AES', plaintext: JSON.stringify(data), key: _secret_key, iv:_initial_iv}}, function(result){
    var encrypt_data = result.ciphertext;
    var req = {};
    req.payload = encrypt_data;
    req.__session_id = _session_id;
    log('Encryption finished. Send it to server now...');
    $fh.act({act: action, secure: _use_secure, req: req}, function(response){
      log('Got response from server.');
      var res_encrypt_data = response.payload;
      log('Decrypt the response data...');
      $fh.sec({act:'decrypt',params:{algorithm:'AES', ciphertext: res_encrypt_data, key: _secret_key, iv: _initial_iv}}, function(plaintext){
        log('Decryption completed. Pass decrypted data to the callback functions');
        var res_decrypt_data = plaintext.plaintext;
        callback(JSON.parse(res_decrypt_data));
      })
    })
  })
}

function doOnlineBankingLogin(){
  var user_name = $('#user_name').val();
  var user_password = $('#user_pass').val();
  log('Sending login details using secure channel...');
  doSecureCommunication('userLogin', {u:user_name, p:user_password}, function(res){
    log('Received decrypted response.');
    if(res.result == "ok"){
      log('Login succeeded.');
      _user_id = res.uid;
      $('#example_two_next_one').css('display', 'block').unbind().bind('click', function(){
        $.mobile.changePage('#example_div_second_second_page');
        $('#view_balance_btn').unbind().bind('click', showAccountBalance);
        $('#view_trans_btn').unbind().bind('click', showAccountTrans);
      })
    }else{
      log('Login failed.');
      alert("Login failed");
    }
  });
}

function showAccountBalance(){
  log('check bank account balances using secure channel...');
  doSecureCommunication('checkBalance', {uid:_user_id}, function(res){
    log('Received decrypted data.');
    var balances = res.balances;
    var html = "<ul data-role='listview' data-inset='true' data-divider-theme='b'>";
    for(var i=0;i<balances.length;i++){
      html += "<li data-role='list-divider'>" + balances[i].name + "</li>";
      html += "<li>" + balances[i].value + "</li>";
    }
    html += "</ul>";
    $('#balance_details').html(html).find('ul').listview();
    $('#example_two_next_two').css('display', 'block').unbind().bind('click', function(){
      $.mobile.changePage('#example_div_second_third_page');
    });
  })
}

function showAccountTrans(){
  log('check recent transactions using secure channel...');
  doSecureCommunication('listTransactions', {uid:_user_id}, function(res){
    log('Received decrypted data.');
    var transactions = res.transactions;
    var html = "<ul data-role='listview' data-inset='true' data-divider-theme='b'>";
    for(var i=0;i<transactions.length;i++){
      html += "<li>" + transactions[i].type + " : " + transactions[i].value;
    }
    html += "</ul>";
    $('#trans_details').html(html).find('ul').listview();
    $('#example_two_next_two').css('display', 'block').unbind().bind('click', function(){
      $.mobile.changePage('#example_div_second_fourth_page');
    });
  });
}

//encrypt data using AES without saving the secret key on the device
function getSecretKeyEnc(){
  $fh.act({act:'generateSecretKey', req:{}}, function(res){
    log("Got secret key : " + res.value + " - iv: " + res.iv);
    var dataTosave = "This is important";
    $fh.sec({act:"encrypt", params: {algorithm:"AES", key: res.value, iv: res.iv, plaintext: dataTosave}}, function(data){
      var encrypted = data.ciphertext;
      log("encrypted data is " + encrypted);
      $fh.data({act:'save', key: "encryptedData", val: encrypted}, function(){
        log("Data saved");
      })
    });
  })
}

//decrypt the data using AES without saving the secret key on the device
function getSecretKeyDec(){
  $fh.act({act:'generateSecretKey', req:{}}, function(res){
    log("Got secret key : " + res.value + " - iv: " + res.iv);
    $fh.data({act:'load', key:"encryptedData"}, function(val){
      log("Got encrypt data : " + val.val);
      $fh.sec({act:"decrypt", params: {algorithm:"AES", key: res.value, iv: res.iv, ciphertext: val.val}}, function(data){
        var dec = data.plaintext;
        log("dec data is " + dec);
      });
    });
  })
}
