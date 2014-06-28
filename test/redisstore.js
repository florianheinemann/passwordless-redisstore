'use strict';

var expect = require('chai').expect;
var uuid = require('node-uuid');
var chance = new require('chance')();

var RedisStore = require('../');
var TokenStore = require('passwordless-tokenstore');

var redis = require("redis");
var client = null;
var db = 15;

var standardTests = require('passwordless-tokenstore-test');

function TokenStoreFactory() {
	return new RedisStore(null, null, { redisstore: {database: db }} );
}

var beforeEachTest = function(done) {
	if(!client) {
		client = redis.createClient();
	}

	client.select(db, function(err, res) {
		done(err);
	})
}

var afterEachTest = function(done) {
	client.flushdb(function(err, res) {
		done(err);
	})
}

// Call all standard tests
standardTests(TokenStoreFactory, beforeEachTest, afterEachTest);

describe('Specific tests', function() {

	beforeEach(function(done) {
		beforeEachTest(done);
	})

	afterEach(function(done) {
		afterEachTest(done);
	})

	it('should allow the instantiation with an empty constructor', function () {
		expect(function() { new RedisStore() }).to.not.throw;
	})

	it('should allow the instantiation with host and port but no options', function () {
		expect(function() { new RedisStore(6379, '127.0.0.1') }).to.not.throw;
	})

	it('should allow the instantiation with a number passed as DB selector', function () {
		expect(function() { new RedisStore(null, null, {redisstore : { database: 0}}) }).to.not.throw;
	})

	it('should allow proper instantiation', function () {
		expect(function() { TokenStoreFactory() }).to.not.throw;
	})

	it('should not allow the instantiation with a DB selector that is not a number', function () {
		expect(function() { new RedisStore(null, null, {redisstore : { database: 'test'}}) }).to.throw(Error);
	})

	it('should default to 0 as database', function(done) {
		var store = new RedisStore();

		var user = chance.email();
		store.storeOrUpdate(uuid.v4(), user, 
			1000*60, 'http://' + chance.domain() + '/page.html', 
			function() {
				client.select(0, function(err, res) {
					expect(err).to.not.exist;
					client.hgetall('pwdless:' + user, function(err, obj) {
						expect(err).to.not.exist;
						expect(obj).to.exist;
						client.del('pwdless:' + user, function(err, dels) {
							expect(err).to.not.exist;
							expect(dels).to.equal(1);
							done();
						})
					})
				})
			});
	});

	it('should change name of token key based on "redisstore.tokenkey"', function(done) {
		var store = new RedisStore(null, null, { redisstore : { tokenkey: 'another_name_', database: db }});

		var user = chance.email();
		store.storeOrUpdate(uuid.v4(), user, 
			1000*60, 'http://' + chance.domain() + '/page.html', 
			function() {
				client.hgetall('another_name_' + user, function(err, obj) {
					expect(err).to.not.exist;
					expect(obj).to.exist;
					done();
				})
			});		
	});

	it('should default to "pwdless:" as token key', function(done) {
		var store = TokenStoreFactory();
		var user = chance.email();
		store.storeOrUpdate(uuid.v4(), user, 
			1000*60, 'http://' + chance.domain() + '/page.html', 
			function() {
				client.hgetall('pwdless:' + user, function(err, obj) {
					expect(err).to.not.exist;
					expect(obj).to.exist;
					done();
				})
			});
	});

	it('should store tokens only in their hashed form', function(done) {
		var store = TokenStoreFactory();
		var user = chance.email();
		var token = uuid.v4();
		store.storeOrUpdate(token, user, 
			1000*60, 'http://' + chance.domain() + '/page.html', 
			function() {
				client.hgetall('pwdless:' + user, function(err, obj) {
					expect(err).to.not.exist;
					expect(obj).to.exist;
					expect(obj.token).to.exist;
					expect(obj.token).to.not.equal(token);
					done();
				})
			});
	});

	it('should store tokens not only hashed but also salted', function(done) {
		var store = TokenStoreFactory();
		var user = chance.email();
		var token = uuid.v4();
		var hashedToken1;
		store.storeOrUpdate(token, user, 
			1000*60, 'http://' + chance.domain() + '/page.html', 
			function() {
				client.hgetall('pwdless:' + user, function(err, obj) {
					expect(err).to.not.exist;
					expect(obj).to.exist;
					expect(obj.token).to.exist;
					hashedToken1 = obj.token;
					store.storeOrUpdate(token, user, 
						1000*60, 'http://' + chance.domain() + '/page.html', 
						function() {
							client.hgetall('pwdless:' + user, function(err, obj) {
								expect(err).to.not.exist;
								expect(obj).to.exist;
								expect(obj.token).to.exist;
								expect(obj.token).to.not.equal(hashedToken1);
								done();
							});						
						});
				})
			});		
	});
})