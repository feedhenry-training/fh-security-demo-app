# FeedHenry Security API Demo App

This app is to demonstrate how to use $fh.sec APIs in the client side and the cloud side to implement secure data communications and storage.

$fh.sec API documents:

* client: http://docs.feedhenry.com/v2/api_client_hybrid.html#$fh.sec
* cloud: http://docs.feedhenry.com/v2/api_cloud_apis.html#$fh.sec

The app contains three examples: 

* Benchmark

This example is to test the performance of the client side APIs. 

* RSA Example

This example is to show how to get the public key from the cloud side and use it to encrypt small amount of data.

* RSA&AES Example

This example is to show how to exchange secret key between the client and the cloud securely using RSA and then encrypt the data of all the communications with the secret key using AES. It also shows how to store encrypted data on the device and decrypt it using AES without saving the secret key on the device.


