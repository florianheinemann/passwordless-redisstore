'use strict';

var util = require('util');
var bcrypt = require('bcrypt');
var TokenStore = require('passwordless-tokenstore');
var redis = require('redis');
var async = require('async');

/**
 * Constructor of RedisStore
 * @param {Number} [port] Port of the Redis server (default: 6379)
 * @param {String} [host] Host, e.g. 127.0.0.1 (default: 127.0.0.1)
 * @param {Object} [options] Combines both the options for the Redis client as well
 * as the options for RedisStore. For the Redis options please refer back to
 * the documentation: https://github.com/NodeRedis/node_redis. RedisStore accepts
 * the following options: (1) { redisstore: { database: Number }} number of the 
 * Redis database to use (default: 0), (2) { redisstore: { tokenkey: String }} the
 * prefix used for the RedisStore entries in the database (default: 'pwdless:')
 * @constructor
 */
function RedisStore(port, host, options) {
	port = port || 6379;
	host = host || '127.0.0.1';
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

	if(this._options.client){
		this._client = this._options.client;
	} else {
		this._client = redis.createClient(port, host, this._options);
	}
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
		bcrypt.hash(token, 10, function(err, hashedToken) {
			if(err) {
				return callback(err);
			}

			originUrl = originUrl || "";
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
