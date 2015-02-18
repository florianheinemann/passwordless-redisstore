# Passwordless-RedisStore

This module provides token storage for [Passwordless](https://github.com/florianheinemann/passwordless), a node.js module for express that allows website authentication without password using verification through email or other means. Visit the project's [website](https://passwordless.net) for more details.

Tokens are stored in a Redis database and are hashed and salted using [bcrypt](https://github.com/ncb000gt/node.bcrypt.js/).

## Usage

First, install the module:

`$ npm install passwordless-redisstore --save`

Afterwards, follow the guide for [Passwordless](https://github.com/florianheinemann/passwordless). A typical implementation may look like this:

```javascript
var passwordless = require('passwordless');
var RedisStore = require('passwordless-redisstore');

passwordless.init(new RedisStore(6379, '127.0.0.1'));

passwordless.addDelivery(
    function(tokenToSend, uidToSend, recipient, callback) {
        // Send out a token
    });
    
app.use(passwordless.sessionSupport());
app.use(passwordless.acceptToken());
```

## Initialization

```javascript
new RedisStore([port], [host], [options]);
```
* **[port]:** *(Number)* Optional. Port of your Redis server. Defaults to: 6379
* **[host]:** *(String)* Optional. Your Redis server. Defaults to: '127.0.0.1'
* **[options]:** *(Object)* Optional. This can include options of the node.js Redis client as described in the [docs](https://github.com/mranney/node_redis) and the ones described below combined in one object as shown in the example

Example:
```javascript
passwordless.init(new RedisStore(6379, '127.0.0.1', {
	// option of the node.js redis client
    auth_pass: 'password',
    // option of bcrypt, defaults to 12
    bcryptRounds: 12,
    // options of RedisStore
    redisstore: {
        database: 15,
        tokenkey: 'token:'
    }
}));
```

### Options
* **[redisstore.database]:** *(Number)* Optional. Database to be used. Defaults to: 0
* **[redisstore.tokenkey]:** *(String)* Optional. Keys to be used. UIDs will be appended. Defaults to: 'pwdless:UID'

## Hash and salt
As the tokens are equivalent to passwords (even though only for a limited time) they have to be protected in the same way. passwordless-redisstore uses [bcrypt](https://github.com/ncb000gt/node.bcrypt.js/) with automatically created random salts. To generate the salt 12 rounds are used. This number can be overridden with a larger integer in the options.

## Tests

`$ npm test`

## License

[MIT License](http://opensource.org/licenses/MIT)

## Author
Florian Heinemann [@thesumofall](http://twitter.com/thesumofall/)
