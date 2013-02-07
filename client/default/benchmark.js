$fh.ready(function(){
  //bind events when app is ready
  $('#rsa_run_btn').bind("click", function(){
    showRunningMessage();
    var keysize = {"second": 1024, "third": 2048};
    var datasize = {"first" : 16, "second" : 32, "third": 64};
    var keysize_selected = $("input[name='rsa_keysize_choice']:checked").val();
    var datasize_selected = $("input[name='rsa_datasize_choice']:checked").val();
    pre_benchmark("rsa", "enc", keysize[keysize_selected], datasize[datasize_selected], function(){
      finish_benchmark();
    });
  });
  $('#aes_run_btn').bind("click", function(){
    showRunningMessage();
    var keysize = {"first": 128, "second": 256 };
    var datasize = {"first" : 1024, "second" : 2048, "third": 3072};
    var keysize_selected = $("input[name='aes_keysize_choice']:checked").val();
    var datasize_selected = $("input[name='aes_datasize_choice']:checked").val();
    var mode = $("input[name='aes_mode_choice']:checked").val();
    pre_benchmark("aes", mode, keysize[keysize_selected], datasize[datasize_selected], function(){
      finish_benchmark();
    });
  });
  $('#rsa_run_all_btn').bind('click', function(){
    showRunningMessage();
    var keysize = [1024, 2048];
    var datasize = [16, 32, 64];
    //get all the combinations and run them
    for(var i = 0;i<keysize.length;i++){
      for(var j=0;j<datasize.length;j++){
        pre_benchmark("rsa", "enc", keysize[i], datasize[j], (i==keysize.length -1 && j == datasize.length -1) ? function(){ finish_benchmark() } : undefined);
      }
    }
  });
  $('#aes_run_all_btn').bind('click', function(){
    showRunningMessage();
    var keysize = [128, 256];
    var datasize = [1024, 2048, 3072];
    //get all the combinations and run them
    for(var i = 0;i<keysize.length;i++){
      for(var j=0;j<datasize.length;j++){
        pre_benchmark("aes", "dec", keysize[i], datasize[j], (i==keysize.length -1 && j == datasize.length -1) ? function(){ finish_benchmark() } : undefined);
      }
    }
  })
  $('#rsa_stop_btn, #aes_stop_btn').bind('click', function(){
    _stop = true;
  });
  $('#rsa_div, #aes_div').live('pagebeforeshow', function(event, ui){
    //make sure the "View Results" button is hidden
    if(timers.length == 0){
      $(this).find('.result_btn').css('display', 'none');
    }
  });
  $('#result_div').live('pagebeforeshow', function(event, ui){
    //the listview is only initialised the first time when the page is loaded, so force it to initialise every time before the page is shown
    $(this).find('ul').listview();
  });
})


function showRunningMessage(){
  $('.ui-page-active').find('.progress_btn').css('display', 'block');
}

//before start benchmark, generate a secret key if it's necessary
function pre_benchmark(alg, mode, keysize, datasize, cb){
  var data = generate_random_text(datasize); 
  if(!_stop){
    if(alg.toLowerCase() == "aes"){
      counter++;
      timer_start("aes key generation. kl = " + keysize + " :: counter = " + counter, {keysize : keysize});
      $fh.sec({act:'keygen', params:{algorithm:'AES', keysize:keysize}}, function(key){
        timer_end("aes key generation. kl = " + keysize + " :: counter = " + counter);
        start_benchmark(alg, mode, key.secretkey, data, keysize, cb, key.iv);
      }, function(msg){
        alert(msg);
      })
    }else if(alg.toLowerCase() == "rsa"){
      start_benchmark(alg, mode, rsa_keys[keysize], data, keysize, cb);
    }
  }
}

function start_benchmark(alg, mode, key, data, keysize, callback, iv){
  if(!_stop){
    if(mode == "enc"){
      do_benchmark(alg, key, data, keysize, false, callback, iv);
    } else {
      if(mode == "dec" && alg.toLowerCase() == "aes"){
        do_benchmark(alg, key, data, keysize, true, callback, iv);
      }
    }
  }
}

function do_benchmark(alg, key, data, keysize, do_decrypt, callback, iv){
  //prepare the parameters for encryption/decryption
  var params = {plaintext : data, algorithm: alg};
  if(alg.toLowerCase() == "aes"){
    params.key = key;
    params.iv = iv;
  } else {
    params.key = key.e;
    params.keysize = key.s;
    params.modulu = key.m;
  }
  //start with encryption
  timer_start(alg + " encryption. dl = " + data.length + " :: kl = " + keysize, {datasize: data.length, keysize: keysize});
  $fh.sec({act:'encrypt', params: params}, function(cipher){
    timer_end(alg + " encryption. dl = " + data.length + " :: kl = " + keysize);
    if(_stop){
      finish_benchmark();
      return;
    }
    //decryption is aes only
    if(do_decrypt){
      var decrypt_params = {ciphertext: cipher.ciphertext, key: key.secretkey, algorithm : 'AES', iv: iv};
      timer_start(alg + " decryption. dl = " + data.length + " :: kl = " + keysize, {datasize: data.length, keysize: keysize});
      $fh.sec({act:'decrypt', params:decrypt_params}, function(plaintext){
        timer_end(alg + " decryption. dl = " + data.length + " :: kl = " + keysize);
        if(_stop){
          finish_benchmark();
          return;
        }
        if(typeof callback == "function"){
          callback();
        }
      }, function(msg){
        alert(msg);
      })
    } else {
      if(typeof callback == "function"){
        callback();
      }
    }
  }, function(err){
    alert(err);
  });
}

function finish_benchmark(){
  _stop = false;
  counter = 0;
  fill_results(timers);
  timers = [];
}

function fill_results(results){
  var html = "<ul data-role='listview' data-inset='true' data-divider-theme='b'>";
  for(var i=0;i<results.length;i++){
    var r = results[i];
    html += "<li data-role='list-divider'>"+ r.desc.split(".")[0] + ". Keysize = " + r.params.keysize  + ". Datasize = " + r.params.datasize + "</li>";
    html += "<li>" + "Time taken : " + r.dur + " ms" + "</li>"; 
  }
  html += "</ul>";
  $('#result_page_content').html(html);
  $('.ui-page-active').find('.progress_btn').css('display', 'none');
  $('.ui-page-active').find('.result_btn').css('display', 'block').unbind().bind('click', function(){
    $.mobile.changePage('#result_div');
  })
}

function timer_start(desc, params){
  var timer = {};
  timer.desc = desc;
  timer.params = params;
  timer.start = new Date().getTime();
  timers.push(timer); 
}

function timer_end(desc){
  var timer, found;
  var end = new Date().getTime();
  for(var i=0;i<timers.length;i++){
    if(timers[i].desc == desc){
      timer = timers[i];
      found = true;
      break;
    }
  }
  if(!found){
    alert("Timer for " + desc + " is not started yet!");
    return;
  }
  timer.end = end;
  timer.dur = timer.end - timer.start;
}
