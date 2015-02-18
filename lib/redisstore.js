'use strict';

var util = require('util');
var bcrypt = require('bcrypt');
var TokenStore = require('passwordless-tokenstore');
var redis = require('redis'); 
var async = require('async');

// a minimum number of rounds for bcrypt is configured below
// this value can be overridden with a larger integer in the options
// see the following SO answer in regards to determining the correct number
// http://security.stackexchange.com/questions/3959/recommended-of-iterations-when-using-pkbdf2-sha256/3993#3993
var bcryptMinRounds = 12;

/**
 * Constructor of RedisStore
 * @param {String} connection URI as defined by the MongoDB specification. Please 
 * check the documentation for details: 
 * http://mongodb.github.io/node-mongodb-native/driver-articles/mongoclient.html 
 * @param {Object} [options] Combines both the options for the MongoClient as well
 * as the options for RedisStore. For the MongoClient options please refer back to
 * the documentation. RedisStore understands the following options: 
 * (1) { mongostore: { collection: string }} to change the name of the collection
 * being used. Defaults to: 'passwordless-token'
 * @constructor
 */
function RedisStore(port, host, options) {
	this._options = options || {};
	this._options.redisstore = this._options.redisstore || {};
	if(this._options.redisstore.database && !isNumber(this._options.redisstore.database)) {
		throw new Error('database has to be a number (if provided at all)');
	} else if(this._options.redisstore.database) {
		this._database = this._options.redisstore.database;
	} else {
		this._database = 0;
	}

	this._tokenKey = this._options.redisstore.tokenkey || 'pwdless:';
	delete this._options.redisstore;

	this._client = redis.createClient(port, host, this._options);
}

util.inherits(RedisStore, TokenStore);

/**
 * Checks if the provided token / user id combination exists and is
 * valid in terms of time-to-live. If yes, the method provides the 
 * the stored referrer URL if any. 
 * @param  {String}   token to be authenticated
 * @param  {String}   uid Unique identifier of an user
 * @param  {Function} callback in the format (error, valid, referrer).
 * In case of error, error will provide details, valid will be false and
 * referrer will be null. If the token / uid combination was not found 
 * found, valid will be false and all else null. Otherwise, valid will 
 * be true, referrer will (if provided when the token was stored) the 
 * original URL requested and error will be null.
 */
RedisStore.prototype.authenticate = function(token, uid, callback) {
	if(!token || !uid || !callback) {
		throw new Error('TokenStore:authenticate called with invalid parameters');
	}

	var self = this;
	self._select(function(err) {
		if(err) {
			return callback(err, false, null);
		}
		var key = self._tokenKey + uid;
		self._client.hgetall(key, function(err, obj) {
			if(err) {
				return callback(err, false, null);
			}
			else if(!obj) {
				return callback(null, false, null);
			} else if(Date.now() > obj.ttl) {
				callback(null, false, null);
			} else {
				bcrypt.compare(token, obj.token, function(err, res) {
					if(err) {
						callback(err, false, null);
					} else if(res) {
						callback(null, true, obj.origin);
					} else {
						callback(null, false, null);
					}
				});			
			}
		});
	})
};

/**
 * Stores a new token / user ID combination or updates the token of an
 * existing user ID if that ID already exists. Hence, a user can only
 * have one valid token at a time
 * @param  {String}   token Token that allows authentication of _uid_
 * @param  {String}   uid Unique identifier of an user
 * @param  {Number}   msToLive Validity of the token in ms
 * @param  {String}   originUrl Originally requested URL or null
 * @param  {Function} callback Called with callback(error) in case of an
 * error or as callback() if the token was successully stored / updated
 */
RedisStore.prototype.storeOrUpdate = function(token, uid, msToLive, originUrl, callback) {
	if(!token || !uid || !msToLive || !callback || !isNumber(msToLive)) {
		throw new Error('TokenStore:storeOrUpdate called with invalid parameters');
	}

	var self = this;
	self._select(function(err) {
		if(err) {
			return callback(err, false, null);
		}

		var rounds = self._options.redisstore.rounds || bcryptMinRounds;
		if (typeof rounds != 'number' || rounds < bcryptMinRounds) {
			throw new Error("Invalid redisstore.rounds value. Should be an integer greater than "+bcryptMinRounds+".");
		}

		bcrypt.hash(token, parseInt(rounds, 10), function(err, hashedToken) {
			if(err) {
				return callback(err);
			}

			var key = self._tokenKey + uid;
			self._client.hmset(key, {
					token: hashedToken,
					origin: originUrl,
					ttl: (Date.now() + msToLive)
				}, function(err, res) {
					if(!err) {
						msToLive = Math.ceil(msToLive / 1000);
						self._client.expire(key, msToLive, function(err, res) {
							if(err)
								callback(err);
							else
								callback();
						})
					} else {
						callback(err);
					}
			});
		});
	})
}

/**
 * Invalidates and removes a user and the linked token
 * @param  {String}   user ID
 * @param  {Function} callback called with callback(error) in case of an
 * error or as callback() if the uid was successully invalidated
 */
RedisStore.prototype.invalidateUser = function(uid, callback) {
	if(!uid || !callback) {
		throw new Error('TokenStore:invalidateUser called with invalid parameters');
	}

	var self = this;
	self._select(function(err) {
		if(err) {
			return callback(err, false, null);
		}
		var key = self._tokenKey + uid;
		self._client.del(key, function(err) {
			if(err)
				callback(err);
			else
				callback();
		});
	})
}

/**
 * Removes and invalidates all token
 * @param  {Function} callback Called with callback(error) in case of an
 * error or as callback() otherwise
 */
RedisStore.prototype.clear = function(callback) {
	if(!callback) {
		throw new Error('TokenStore:clear called with invalid parameters');
	}

	var self = this;
	self._select(function(err) {
		if(err) {
			return callback(err, false, null);
		}
		var pattern = self._tokenKey + '*';
		self._client.keys(pattern, function(err, matches) {
			if(err) {
				callback(err);
			} else if(matches.length > 0) {
				async.each(matches, function(match, matchCallback) {
					self._client.del(match, matchCallback);
				}, callback);
			} else {
				callback();
			}
		});
	})
}

/**
 * Number of tokens stored (no matter the validity)
 * @param  {Function} callback Called with callback(null, count) in case
 * of success or with callback(error) in case of an error
 */
RedisStore.prototype.length = function(callback) {
	if(!callback) {
		throw new Error('TokenStore:length called with invalid parameters');
	}

	var self = this;
	self._select(function(err) {
		if(err) {
			return callback(err, false, null);
		}
		var pattern = self._tokenKey + '*';
		self._client.keys(pattern, function(err, matches) {
			if(err) {
				callback(err);
			} else {
				callback(null, matches.length);
			}
		});
	})
}

RedisStore.prototype._select = function(callback) {
	var self = this;
	if(self._selected) {
		callback();
	} else {
		self._client.select(self._database, function(err, res) {
			if(err) {
				callback(err);
			} else {
				self._selected = true;
				callback();	
			}
		});
	}
}

function isNumber(n) {
	return !isNaN(parseFloat(n)) && isFinite(n);
}

module.exports = RedisStore;
