var util = require('util');
$fh = $fh || {};
$fh.sec = require('fh-security').security;

var KEY_SIZE = 1024;
var sessionCounter = 0;

var getKeyId = function(params){
  var cuid = params.__fh.cuid;
  var appid = params.__fh.appid;
  var keyid = cuid + "_" + appid;
  return keyid;
}

//read a key using $fh.db
var getKey = function(id, keytype, cb){
  if(typeof $fh !== "undefined" && $fh.db){
    $fh.db({
      act:'list',
      'type': 'securityKeys',
      eq: {
        "id": id,  //The id is generated using the above example code
        "keyType": keytype
      }
    }, function(err, data){
      if(err) return cb(err);
      if(data.count > 0){
        return cb(undefined, data.list[0].fields.keyValue);
      } else {
        return cb(undefined, undefined);
      }
    });
  } else {
    console.log("$fh.db not defined");
    cb("$fh.db not defined");
  }
}

//save a key using $fh.db
var saveKey = function(id, keytype, keyvalue, cb){
  if(typeof $fh !== "undefined" && $fh.db){
    //first check if a key with the same id and type already exsists
    $fh.db({
      act:'list',
      'type': 'securityKeys',
      eq: {
        "id": id,
        "keyType": keytype
      }
    }, function(err, data){
      if(err) return cb(err);
      //a key with the same id and type already exists, update it
      if(data.count > 0){
        $fh.db({
          'act':'update',
          'type': 'securityKeys',
          'guid': data.list[0].guid,
          'fields' : {
            'id': id,
            'keyType': keytype,
            'keyValue' : keyvalue
          }
        }, function(err, result){
          if(err) return cb(err);
          return cb(undefined, result);
        })
      } else {
        //a key with the same id and type is not found, create it
        $fh.db({
          'act': 'create',
          'type': 'securityKeys',
          'fields': {
            'id' : id,
            'keyType': keytype,
            'keyValue': keyvalue
          }
        }, function(err, result){
          if(err) return cb(err);
          return cb(undefined, result);
        });
      }
    });
  } else {
    console.log("$fh.db not defined");
    cb("$fh.db not defined");
  }
}

//read the public key for the request if it exists, otherwise generate a new pair and save it
exports.getPublicKey = function(params, callback) {
  var keyid = getKeyId(params);

  getKey(keyid, "public", function(err, pubkey){
    if(err){
      return callback(err);
    }
    if(pubkey){
      getKey(keyid, "modulu", function(err, modulu){
        if(err) return callback(err);
        return callback(undefined, {modulu: modulu, public: pubkey});
      })
    } else {
      $fh.sec({act:'keygen', params: {algorithm:'RSA', keysize: KEY_SIZE}}, function(err, keys){
        if(err) return callback(err);
        if(keys){
          saveKey(keyid, "public", keys.public, function(){});
          saveKey(keyid, "private", keys.private, function(){});
          saveKey(keyid, "modulu", keys.modulu, function(){});
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
  var keyid = getKeyId(params);
  getKey(keyid, "private", function(err, keyvalue){
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
  var keyid = getKeyId(params);
  var encrypt_key = params.cipher;  //get the RSA public encrypted secret key
  var nonce = params.nonce;   //for vevification
  var keysize = parseInt(params.keysize);
  getKey(keyid, "private", function(err, keyvalue){
    if(err) return callback(err);
    $fh.sec({act:'decrypt', params:{algorithm:'RSA', ciphertext:encrypt_key, private:keyvalue}}, function(err, plaintext){
      if(err) return callback(err);
      console.log('Secret key is ' + plaintext.plaintext);
      var secretkey = JSON.parse(plaintext.plaintext);
      var secret_key = secretkey.key;
      var iv = secretkey.iv;
      $fh.sec({act:'hash', params:{algorithm:'MD5', text: nonce}}, function(err, hashvalue){
        if(err) return callback(err);
        var hv = hashvalue.hashvalue;
        console.log('hash value is ' + hv);
        var sessionId = ++sessionCounter;
        $fh.sec({act:'encrypt', params: {algorithm:'AES', plaintext: hv, key: secret_key, iv: iv}}, function(err, ciphertext){
          if(err) return callback(err);
          console.log("eccrypted hash value is " + ciphertext.ciphertext);
          saveKey(sessionId, "secret", JSON.stringify({value: secret_key, iv: iv}), function(err, result){
            if(err) return callback(err);
            return callback(undefined, {verify: ciphertext.ciphertext, __session_id: sessionId});
          });
        })
      });
    });
  });
}

exports.generateSecretKey = function(params, callback){
  var keyid = getKeyId(params);
  getKey(keyid, "secret", function(err, keyvalue){
    if(err) return callback(err);
    if(keyvalue){
      return callback(undefined, JSON.parse(keyvalue));
    } else {
      $fh.sec({act:'keygen', params:{algorithm:'AES', keysize:128}}, function(err, secret_key){
        if(err) return callback(err);
        saveKey(keyid, "secret", JSON.stringify({value: secret_key.secretkey, iv: secret_key.iv}), function(err, result){
          if(err) return callback(err);
          return callback(undefined, {value: secret_key.secretkey, iv: secret_key.iv});
        });
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
  getKey(id, "secret", function(err, secret_key){
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

