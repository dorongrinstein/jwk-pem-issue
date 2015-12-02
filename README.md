# jwk-pem-issue

Ravi,

I created this repo to illustrate that the key generated by the token service need to be converted to PEM, otherwise an error results when validating the JWT.

To see it in action, first run node test.js -pem and all works well when you try in the browser:

http://localhost:3000?jwt=PUT_JWT_HERE

Then to see the error, run node test.js 
[note: without the -pem flag]

This will yield an error


