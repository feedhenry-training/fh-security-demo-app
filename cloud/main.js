var util = require('util');
$fh = $fh || {};
$fh.sec = require('fh-security').security;

var KEY_SIZE = 1024;
var sessionCounter = 0;

//read the public key for the request if it exists, otherwise generate a new pair and save it
exports.getPublicKey = function(params, callback) {
  var cuid = params.__fh.cuid;
  $fh.sec({act:'getkey', params:{keytype:'public', id: cuid}}, function(err, modulu){
    if(err) return callback(err);
    if(modulu){
      return callback(undefined, {modulu: modulu});
    } else {
      $fh.sec({act:'keygen', params: {algorithm:'RSA', keysize: KEY_SIZE}}, function(err, keys){
        if(err) return callback(err);
        if(keys){
          $fh.sec({act:'savekey', params:{keytype:'public', key: keys.public, id: cuid}}, function(){});
          $fh.sec({act:'savekey', params:{keytype:'private',key: keys.private, id: cuid}}, function(){});
          $fh.sec({act:'savekey', params:{keytype:'modulu', key: keys.modulu, id: cuid}}, function(){});
          return callback(undefined, {key: keys.public, modulu: keys.modulu, keysize: KEY_SIZE});
        } else {
          return callback("Key generation failed");
        }
      });
    }
  });
}

//decrypt data using RSA
exports.decryptInput = function(params, callback){
  var encrypt_data = params.details;
  var cuid = params.__fh.cuid;
  $fh.sec({act:'getkey', params:{keytype:'private', id: cuid}}, function(err, keyvalue){
    if(err) return callback(err);
    $fh.sec({act:'decrypt', params:{algorithm:'RSA', ciphertext:encrypt_data, private:keyvalue}}, function(err, plaintext){
      if(err) return callback(err);
      console.log("Received data is : " + plaintext.plaintext);
      return callback(undefined, {result:'ok', message: plaintext.plaintext});
    });
  });
}

//decrypt the data to get the secret key sent by the client, and return verification value
exports.exchangeSecretKey = function(params, callback){
  var cuid = params.__fh.cuid;
  var encrypt_key = params.cipher;  //get the RSA public encrypted secret key
  var nuance = params.nuance;   //for vevification
  var keysize = parseInt(params.keysize);
  $fh.sec({act:'getkey', params:{keytype:'private', id:cuid}}, function(err, keyvalue){
    if(err) return callback(err);
    $fh.sec({act:'decrypt', params:{algorithm:'RSA', ciphertext:encrypt_key, private:keyvalue}}, function(err, plaintext){
      if(err) return callback(err);
      console.log('Secret key is ' + plaintext.plaintext);
      var secretkey = JSON.parse(plaintext.plaintext);
      var secret_key = secretkey.key;
      var iv = secretkey.iv;
      $fh.sec({act:'hash', params:{algorithm:'MD5', text: nuance}}, function(err, hashvalue){
        if(err) return callback(err);
        var hv = hashvalue.hashvalue;
        console.log('hash value is ' + hv);
        var sessionId = ++sessionCounter;
        $fh.sec({act:'encrypt', params: {algorithm:'AES', plaintext: hv, key: secret_key, iv: iv}}, function(err, ciphertext){
          if(err) return callback(err);
          console.log("eccrypted hash value is " + ciphertext.ciphertext);
          $fh.sec({act:'savekey', params:{id: sessionId, keytype:'secret', key: JSON.stringify({value: secret_key, iv: iv})}}, function(err, result){
            if(err) return callback(err);
            return callback(undefined, {verify: ciphertext.ciphertext, __session_id: sessionId});
          });
        })
      });
    });
  });
}

exports.generateSecretKey = function(params, callback){
  var cuid = params.__fh.cuid;
  $fh.sec({act:'getkey', params:{keytype:'secret', id: cuid}}, function(err, keyvalue){
    if(err) return callback(err);
    if(keyvalue){
      return callback(undefined, JSON.parse(keyvalue));
    } else {
      $fh.sec({act:'keygen', params:{algorithm:'AES', keysize:128}}, function(err, secret_key){
        if(err) return callback(err);
        $fh.sec({act:'savekey', params:{id: cuid, keytype:'secret', key: JSON.stringify({value: secret_key.secretkey, iv: secret_key.iv})}}, function(err, result){
          if(err) return callback(err);
          return callback(undefined, {value: secret_key.secretkey, iv: secret_key.iv});
        })
      });
    }
  });
}

exports.userLogin = function(params, callback){
  receiveSecureData(params, function(err, data){
    if(err) return callback(err);
    var user_name = data.data.u;
    var pass = data.data.p;
    console.log('The login user is ' + user_name + ' :: password is ' + pass);
    var retdata = { result: 'ok', uid : 1};
    sendSecureData(data.key, retdata, callback);
  });
  
}

exports.checkBalance = function(params, callback){
  receiveSecureData(params, function(err, data){
    if(err) return callback(err);
    var uid = data.data.uid;
    console.log('Check balance : uid is ' + uid);
    var balances = [{name:'Saving Account', value:'EUR 10,000'}, {name:'Credit Card Account', value: 'EUR 500DR'}];
    var retdata = {balances: balances};
    sendSecureData(data.key, retdata, callback);
  });
  
}

exports.listTransactions = function(params, callback){
  receiveSecureData(params, function(err, data){
    if(err) return callback(err);
    var uid = data.data.uid;
    console.log('List Transactions : uid is ' + uid);
    var trans = [{type:'Debit', value: 'EUR 20'}, {type:'Debit', value: 'EUR 40'}, {type:'Debit', value: 'EUR 30'}, {type:'Credit', value: 'EUR 200'}, {type:'Debit', value: 'EUR 20'}, {type:'Debit', value: 'EUR 20'}];
    var retdata = { transactions: trans};
    sendSecureData(data.key, retdata, callback);
  });
}


//decrypt the data which has been eccrypted using the shared secret key
function receiveSecureData(params, callback){
  var data = params.payload;
  var id = params.__session_id;
  $fh.sec({act:'getkey', params:{keytype:'secret', id: id}}, function(err, secret_key){
    if(err) return callback(err);
    if(secret_key){
      secret_key = JSON.parse(secret_key);
      var keyvalue = secret_key.value;
      var iv = secret_key.iv;
      $fh.sec({act:'decrypt', params: {algorithm:'AES', key: keyvalue, ciphertext: data, iv: iv}}, function(err, plaintext){
        if(err) return callback(err);
        console.log("Received data is " + plaintext.plaintext);
        return callback(undefined, {key: secret_key, data: JSON.parse(plaintext.plaintext)});
      })
    } else {
      return callback("no secret key found");
    }
  });
}

//encrypt the data using the shared secret key before sending to the client
function sendSecureData(key, data, callback){
  $fh.sec({act:'encrypt', params:{algorithm:'AES', key: key.value, iv: key.iv, plaintext: JSON.stringify(data)}}, function(err, ciphertext){
    if(err) return callback(err);
    return callback(undefined, {payload: ciphertext.ciphertext});
  });
}

