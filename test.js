var request = require('request');
var jwt = require('jsonwebtoken');
var express = require('express');
var pubKeyUrl = process.env.PUBLIC_KEY_URL || "http://v0.token.concurawsdev.com/token-service/v0/jwks";
var guid = require('guid');
var q = require('q');
var rsapem = require('rsa-pem-from-mod-exp');


var app = express();

var publicKeys = null;


function fetchJwks() {
    var options = {
      url: pubKeyUrl,
        headers: {
            'concur-correlationid': guid.raw()
        }
    };
    var def = q.defer();
    request(options, function(error, response, body) {
        if (!error && response.statusCode == 200) {
            var arr = [];
            var jwks = JSON.parse(body);
            //for (var i in jwks.keys)
            //    arr.push({"kid": jwks.keys[i].kid, "pem": rsapem(jwks.keys[i].n, jwks.keys[i].e)});
            //def.resolve(arr);
            def.resolve(jwks);
        }
        else
            def.reject( "Cannot fetch public keys from " + pubKeyUrl );
    });

    return def.promise;
}

app.get('/', validate);

function validate(req, res) {
    try {
        var theJwt = req.query.jwt;
        var decodedJwt = jwt.decode(theJwt, {complete: true});
        var kid = decodedJwt.header.kid;
        console.log('kid: ' + kid);
        verifyJwt(theJwt, kid, function (data) {
            res.send(data);
        });
    } catch (e) {
        console.log("Error in validate(): " + e);
        res.json({"Error": "invalid JWT"});
    }
}


function verifyJwt(theJwt, kid, cb) {
  
 function doVerify(theJwt, kid, cb) {
    var key = publicKeys.keys[0].n;
    if (process.argv[2] == '-pem') {
      key = rsapem(publicKeys.keys[0].n, publicKeys.keys[0].e);
    }
    console.log('key: ' + key);
    try {
       cb(jwt.verify(theJwt, key , { algorithms: ['RS256'] }));
    } catch(e) {
     console.log(e);
   }
 }

  if (!publicKeys) {
    var t = fetchJwks();
    t.then(function(data) {
      publicKeys = data;
      doVerify(theJwt, kid, cb);
    });
  }
  else {
   doVerify(theJwt, kid, cb);
  }
}


app.listen(3000);
