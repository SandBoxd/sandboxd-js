/*!
 * Copyright (c) 2014 SandBoxd Inc.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * 
 * SandBoxd API Client Library
 * JavaScript/NodeJS Implementation
 */
 /** @module sandboxd */
 /**
  * @callback standardCallback
  * @param {String} [error] If present then an error has occured. You should always check this value before using the data. Check the string for a detailed description of the error.
  * @param {*} [data] The data returned by the call.
  */
 /**
  * @callback dataCallback
  * @param {*} [data] The data returned by the call.
  */
(function () {
	var sandboxd = (function () {
		/*
		CryptoJS v3.1.2
		code.google.com/p/crypto-js
		(c) 2009-2013 by Jeff Mott. All rights reserved.
		code.google.com/p/crypto-js/wiki/License
		*/
		var CryptoJS=CryptoJS||function(h,s){var f={},t=f.lib={},g=function(){},j=t.Base={extend:function(a){g.prototype=this;var c=new g;a&&c.mixIn(a);c.hasOwnProperty("init")||(c.init=function(){c.$super.init.apply(this,arguments)});c.init.prototype=c;c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},
		q=t.WordArray=j.extend({init:function(a,c){a=this.words=a||[];this.sigBytes=c!=s?c:4*a.length},toString:function(a){return(a||u).stringify(this)},concat:function(a){var c=this.words,d=a.words,b=this.sigBytes;a=a.sigBytes;this.clamp();if(b%4)for(var e=0;e<a;e++)c[b+e>>>2]|=(d[e>>>2]>>>24-8*(e%4)&255)<<24-8*((b+e)%4);else if(65535<d.length)for(e=0;e<a;e+=4)c[b+e>>>2]=d[e>>>2];else c.push.apply(c,d);this.sigBytes+=a;return this},clamp:function(){var a=this.words,c=this.sigBytes;a[c>>>2]&=4294967295<<
		32-8*(c%4);a.length=h.ceil(c/4)},clone:function(){var a=j.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var c=[],d=0;d<a;d+=4)c.push(4294967296*h.random()|0);return new q.init(c,a)}}),v=f.enc={},u=v.Hex={stringify:function(a){var c=a.words;a=a.sigBytes;for(var d=[],b=0;b<a;b++){var e=c[b>>>2]>>>24-8*(b%4)&255;d.push((e>>>4).toString(16));d.push((e&15).toString(16))}return d.join("")},parse:function(a){for(var c=a.length,d=[],b=0;b<c;b+=2)d[b>>>3]|=parseInt(a.substr(b,
		2),16)<<24-4*(b%8);return new q.init(d,c/2)}},k=v.Latin1={stringify:function(a){var c=a.words;a=a.sigBytes;for(var d=[],b=0;b<a;b++)d.push(String.fromCharCode(c[b>>>2]>>>24-8*(b%4)&255));return d.join("")},parse:function(a){for(var c=a.length,d=[],b=0;b<c;b++)d[b>>>2]|=(a.charCodeAt(b)&255)<<24-8*(b%4);return new q.init(d,c)}},l=v.Utf8={stringify:function(a){try{return decodeURIComponent(escape(k.stringify(a)))}catch(c){throw Error("Malformed UTF-8 data");}},parse:function(a){return k.parse(unescape(encodeURIComponent(a)))}},
		x=t.BufferedBlockAlgorithm=j.extend({reset:function(){this._data=new q.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=l.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var c=this._data,d=c.words,b=c.sigBytes,e=this.blockSize,f=b/(4*e),f=a?h.ceil(f):h.max((f|0)-this._minBufferSize,0);a=f*e;b=h.min(4*a,b);if(a){for(var m=0;m<a;m+=e)this._doProcessBlock(d,m);m=d.splice(0,a);c.sigBytes-=b}return new q.init(m,b)},clone:function(){var a=j.clone.call(this);
		a._data=this._data.clone();return a},_minBufferSize:0});t.Hasher=x.extend({cfg:j.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){x.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(c,d){return(new a.init(d)).finalize(c)}},_createHmacHelper:function(a){return function(c,d){return(new w.HMAC.init(a,
		d)).finalize(c)}}});var w=f.algo={};return f}(Math);
		(function(h){for(var s=CryptoJS,f=s.lib,t=f.WordArray,g=f.Hasher,f=s.algo,j=[],q=[],v=function(a){return 4294967296*(a-(a|0))|0},u=2,k=0;64>k;){var l;a:{l=u;for(var x=h.sqrt(l),w=2;w<=x;w++)if(!(l%w)){l=!1;break a}l=!0}l&&(8>k&&(j[k]=v(h.pow(u,0.5))),q[k]=v(h.pow(u,1/3)),k++);u++}var a=[],f=f.SHA256=g.extend({_doReset:function(){this._hash=new t.init(j.slice(0))},_doProcessBlock:function(c,d){for(var b=this._hash.words,e=b[0],f=b[1],m=b[2],h=b[3],p=b[4],j=b[5],k=b[6],l=b[7],n=0;64>n;n++){if(16>n)a[n]=
		c[d+n]|0;else{var r=a[n-15],g=a[n-2];a[n]=((r<<25|r>>>7)^(r<<14|r>>>18)^r>>>3)+a[n-7]+((g<<15|g>>>17)^(g<<13|g>>>19)^g>>>10)+a[n-16]}r=l+((p<<26|p>>>6)^(p<<21|p>>>11)^(p<<7|p>>>25))+(p&j^~p&k)+q[n]+a[n];g=((e<<30|e>>>2)^(e<<19|e>>>13)^(e<<10|e>>>22))+(e&f^e&m^f&m);l=k;k=j;j=p;p=h+r|0;h=m;m=f;f=e;e=r+g|0}b[0]=b[0]+e|0;b[1]=b[1]+f|0;b[2]=b[2]+m|0;b[3]=b[3]+h|0;b[4]=b[4]+p|0;b[5]=b[5]+j|0;b[6]=b[6]+k|0;b[7]=b[7]+l|0},_doFinalize:function(){var a=this._data,d=a.words,b=8*this._nDataBytes,e=8*a.sigBytes;
		d[e>>>5]|=128<<24-e%32;d[(e+64>>>9<<4)+14]=h.floor(b/4294967296);d[(e+64>>>9<<4)+15]=b;a.sigBytes=4*d.length;this._process();return this._hash},clone:function(){var a=g.clone.call(this);a._hash=this._hash.clone();return a}});s.SHA256=g._createHelper(f);s.HmacSHA256=g._createHmacHelper(f)})(Math);
		
		//Little helper function to get the parameters provided in the url
		function getQueryParameters () {
			var params = {};
			if (typeof location !== 'undefined') {
				var urlParams = location.search.substr(1).split("&");
				for (var i = 0; i < urlParams.length; i++) {
					if (urlParams[i] != "") {
						var keyValue = urlParams[i].split("=");
						params[decodeURIComponent(keyValue[0])] = decodeURIComponent(keyValue[1]);
					}
				}
			}
			return params;
		}
		
		//Config
		var _host = "api.sandboxd.com";
		var version = "20140305";
		var _gameid;
		var _apikey;
		var params = getQueryParameters();
		
		//Private vars
		var listeners = [];
		var currRegistration = null;
		var currTransaction = null;
		var autoStorageActivated = false;
		
		//Param defaults
		if (params["uid"] === undefined) params["uid"] = 0;
		if (params["name"] === undefined) params["name"] = "Guest";
		if (params["avatar"] === undefined) params["avatar"] = "https://static-sandboxd-com.s3.amazonaws.com/images/avatar-default.png";
		
		function sha256 (text) {
			return CryptoJS.SHA256(text).toString(CryptoJS.enc.Hex);
		}
		
		function checkInit () {
			if (_gameid == null || _apikey == null) throw "You must call sandboxd.init() before interacting with the SandBoxd API.";
		}
		
		function buildAuthHeader (params, uid, sid) {
			var hash = sha256(_apikey);
			if (params != null) {
				var arr = [];
				for (var p in params) {
					arr.push(p.toLowerCase());
				}
				arr.sort();
				var first = true;
				for (var i = 0; i < arr.length; i++) {
					if (!first) hash += "&";
					hash += encodeURIComponent(arr[i]) + "=" + encodeURIComponent(params[arr[i]]);
					first = false;
				}
			}
			if (uid === undefined) return _gameid + " " + sha256(hash);
			else return _gameid + " " + sha256(hash + uid + sid) + " " + uid + " " + sid;
		}
		
		function exponentialBackoff (f, cb, retries, maxRetries) {
			if (retries === undefined) retries = 0;
			if (maxRetries === undefined) maxRetries = 3;
			
			f(function (err, data) {
				if (err == null || retries == maxRetries) {
					if (cb != null) cb(err, data);
				} else {
					setTimeout(function () {
						exponentialBackoff(f, cb, retries + 1, maxRetries);
					}, (1 << retries) * 1000);
				}
			});
		}
		
		/**
		 * Execute a query to the SandBoxd API. Uses XMLHttpRequest for client and http.request for NodeJS.
		 */
		function query (method, apiUrl, cb, params, uid, sid, async, guestAllowed) {
			if (async === undefined) async = true;
			if (guestAllowed === undefined) guestAllowed = false;
			
			if (!guestAllowed && uid == 0 && sid !== undefined) {
				if (cb != null) cb("Only registered users can perform this action.");
				return;
			}
			
			var authHeader = _gameid != null ? buildAuthHeader(params, uid, sid) : null;
			var i;
				
			//Build query string
			var queryStr = "";
			if (params != null) {
				var first = true;
				for (i in params) {
					if (!first) queryStr += "&";
					queryStr += encodeURIComponent(i) + "=" + encodeURIComponent(params[i]);
					first = false;
				}
			}
			
			if (typeof XMLHttpRequest !== 'undefined') {
				//Browser
				var req = new XMLHttpRequest();
				
				//Response
				req.onreadystatechange = function (e) {
					if (req.readyState == 4) {
						if (req.status >= 200 && req.status < 400) {
							//Success
							if (cb != null) cb(null, JSON.parse(req.responseText));
						} else {
							//Error
							if (cb != null) {
								var err;
								try {
									err = JSON.parse(req.responseText).error;
								} catch (e) {
									err = req.status + " (" + req.statusText + ")";
								}
								cb(err);
							}
						}
					}
				};
				
				//Submit query
				if (method == "POST") {
					req.open(method, "https://" + _host + "/" + version + apiUrl, async);
					if (async) req.withCredentials = true;
					if (authHeader != null) req.setRequestHeader("X-SandBoxd-Authentication", authHeader);
					req.send(queryStr);
				} else {
					req.open(method, "https://" + _host + "/" + version + apiUrl + (queryStr.length > 0 ? "?" + queryStr : ""), async);
					if (async) req.withCredentials = true;
					if (authHeader != null) req.setRequestHeader("X-SandBoxd-Authentication", authHeader);
					req.send();
				}
			} else {
				//NodeJS
				var http = require("https");
				
				var opts = {
					hostname: _host,
					path: "/" + version + apiUrl + ((method == "POST" && queryStr.length > 0) ? "" : "?" + queryStr),
					method: method,
					headers: {}
				};
				
				if (authHeader != null) opts.headers["X-SandBoxd-Authentication"] = authHeader;
				if (method == "POST") opts.headers["Content-Length"] = queryStr.length;
				
				var req = http.request(opts, function (res) {
					var data = "";
					res.on('data', function(d) {
						data += d;
					});
					res.on('end', function () {
						if (res.statusCode >= 200 && res.statusCode < 400) {
							//Success
							if (cb != null) cb(null, JSON.parse(data));
						} else {
							//Error
							if (cb != null) {
								var err;
								try {
									err = JSON.parse(data).error;
								} catch (e) {
									err = res.statusCode;
								}
								cb(err);
							}
						}
					});
				});
				if (method == "POST") req.end(queryStr);
				else req.end();
			}
		}
		
		/**
		 * Executes query over a paginated list returning all results.
		 */
		function queryAll (method, apiUrl, cb, params, uid, sid, async, guestAllowed) {
			function QueryResult (method, apiUrl, cb, params, uid, sid, async, guestAllowed) {
				this.method = method;
				this.apiUrl = apiUrl;
				this.cb = cb;
				this.params = params;
				this.uid = uid;
				this.sid = sid;
				this.async = async;
				this.guestAllowed = guestAllowed;
				
				this.items = [];
				this.params.offset = 0;
			}
			QueryResult.prototype.run = function () {
				query(this.method, this.apiUrl, this.response.bind(this), this.params, this.uid, this.sid, this.async, this.guestAllowed);
			};
			QueryResult.prototype.response = function (err, data) {
				if (err == null) {
					if (data.items.length > 0) {
						this.items = this.items.concat(data.items);
						this.params.offset++;
						
						//If offset is null it means pagination is not supported
						if (data.offset != null) {
							this.run();
						} else {
							if (this.cb != null) this.cb(null, this.items);
						}
					} else {
						//End of the list
						if (this.cb != null) this.cb(null, this.items);
					}
				} else {
					if (this.cb != null) this.cb(err);
				}
			};
			
			new QueryResult(method, apiUrl, cb, params, async, guestAllowed).run();
		}
		
		/**
		 * Can be (), (callback) or (uid, callback).
		 */
		function uidCallbackOverload (a1, a2) {
			//Defaults
			var uid = a1;
			var cb = a2;
			
			if (typeof a2 == 'undefined') {
				//Pull uid from url
				cb = a1;
				uid = params["uid"];
			}
			
			return { uid:uid, cb:cb };
		}
		
		/**
		 * Can be (), (callback) or (uid, sid, callback).
		 */
		function uidSidCallbackOverload (a1, a2, a3) {
			//Defaults
			var uid = a1;
			var sid = a2;
			var cb = a3;
			
			if (typeof a3 == 'undefined' && typeof a2 == 'undefined') {
				//Pull uid and sid from url
				cb = a1;
				uid = params["uid"];
				sid = params["sid"];
			}
			
			return { uid:uid, sid:sid, cb:cb };
		}
		
		/**
		 * Provide each object in 'items' with a function 'f' named 'name'.
		 */
		function injectFunctionToEach (items, name, f) {
			for (var i = 0; i < items.length; i++) {
				items[i][name] = f.bind(items[i]);
			}
		}
		
		function dispatchEvent (type, data) {
			for (var i = 0; i < listeners.length; i++) {
				if (listeners[i].type === type) {
					listeners[i].cb(data);
				}
			}
		}
		
		/**
		 * Send a message to SandBoxd via iframe postMessage.
		 */
		function postMessage (type, data) {
			window.parent.postMessage({ type:type, data:data }, "*");
		}
		
		var storage = /** @lends module:sandboxd.storage */ {
			
			/**
			 * <p>Create or update a key/value pair in SandBoxd cloud storage for the specified user.</p>
			 * 
			 * @name module:sandboxd.storage.setItem
			 * @function
			 * @param {String} key A unique identifier.
			 * @param {String} value Some piece of data.
			 * @param {Integer} uid The unique identifier of the user.
			 * @param {String} sid The session identifier of the user.
			 * @param {standardCallback} [cb] The result of the query.
			 */
			/**
			 * <p><b>[Client Only]</b> Create or update a key/value pair in SandBoxd cloud storage for the current user.</p>
			 * 
			 * @name module:sandboxd.storage.setItem
			 * @function
			 * @param {String} key A unique identifier.
			 * @param {String} value Some piece of data.
			 * @param {standardCallback} [cb] The result of the query.
			 */
			setItem: function (key, value, a1, a2, a3) {
				checkInit();
				
				var o = uidSidCallbackOverload(a1, a2, a3);
				exponentialBackoff(
					function (cb) {
						query("POST", "/storage/update/" + _gameid, cb, { key:key, value:value }, o.uid, o.sid)
					},
					o.cb
				);
			},
			
			/**
			 * <p>Retrieve the data associated with the given key from SandBoxd cloud storage for the specified user.</p>
			 * 
			 * @name module:sandboxd.storage.getItem
			 * @function
			 * @param {String} key A unique identifier.
			 * @param {Integer} uid The unique identifier of the user.
			 * @param {String} sid The session identifier of the user.
			 * @param {standardCallback} [cb] The result of the query.
			 */
			/**
			 * <p><b>[Client Only]</b> Retrieve the data associated with the given key from SandBoxd cloud storage for the current user.</p>
			 * 
			 * @name module:sandboxd.storage.getItem
			 * @function
			 * @param {String} key A unique identifier.
			 * @param {standardCallback} [cb] The result of the query.
			 */
			getItem: function (key, a1, a2, a3) {
				checkInit();
				
				var o = uidSidCallbackOverload(a1, a2, a3);
				exponentialBackoff(
					function (cb) {
						query("GET", "/storage/" + _gameid, cb, { key:key }, o.uid, o.sid);
					},
					o.cb
				);
			},
			
			/**
			 * <p>Delete some data from SandBoxd cloud storage for the specified user.</p>
			 * 
			 * @name module:sandboxd.storage.removeItem
			 * @function
			 * @param {String} key A unique identifier.
			 * @param {Integer} uid The unique identifier of the user.
			 * @param {String} sid The session identifier of the user.
			 * @param {standardCallback} [cb] The result of the query.
			 */
			/**
			 * <p><b>[Client Only]</b> Delete some data from SandBoxd cloud storage for the current user.</p>
			 * 
			 * @name module:sandboxd.storage.removeItem
			 * @function
			 * @param {String} key A unique identifier.
			 * @param {standardCallback} [cb] The result of the query.
			 */
			removeItem: function (key, a1, a2, a3) {
				checkInit();
				
				var o = uidSidCallbackOverload(a1, a2, a3);
				exponentialBackoff(
					function (cb) {
						query("POST", "/storage/delete/" + _gameid, cb, { key:key }, o.uid, o.sid);
					},
					o.cb
				);
			},
			
			/**
			 * <p>Retrieve all data from SandBoxd cloud storage for the specified user.</p>
			 * 
			 * @name module:sandboxd.storage.all
			 * @function
			 * @param {Integer} uid The unique identifier of the user.
			 * @param {String} sid The session identifier of the user.
			 * @param {standardCallback} [cb] The result of the query.
			 */
			/**
			 * <p><b>[Client Only]</b> Retrieve all data from SandBoxd cloud storage for the current user.</p>
			 * 
			 * @name module:sandboxd.storage.all
			 * @function
			 * @param {standardCallback} [cb] The result of the query.
			 */
			all: function (a1, a2, a3) {
				checkInit();
				
				var o = uidSidCallbackOverload(a1, a2, a3);
				exponentialBackoff(
					function (cb) {
						queryAll("POST", "/storage", o.cb, { game:_gameid }, o.uid, o.sid);
					},
					o.cb
				);
			}
			
		};
		
		var autoCloudStorage = function () {
			checkInit();
			autoStorageActivated = true;
			
			if (params["uid"] == 0) return false;		//Cloud storage not available for guests
			
			var failure = false;
			var pendingUpdates = {};
			var keys = [];
			var cache = {};
			var _key = Storage.prototype.key;
			var _getItem = Storage.prototype.getItem;
			var _setItem = Storage.prototype.setItem;
			var _removeItem = Storage.prototype.removeItem;
			
			//Initialize the data -- need to do synchronously to make sure we have the data before any calls to localStorage
			query("GET", "/storage", function (err, data) {
				if (err == null) {
					for (var i = 0; i < data.items.length; i++) {
						keys.push(data.items[i].key);
						cache[data.items[i].key] = data.items[i].value;
					}
					keys.sort();
				} else {
					failure = true;
				}
			}, { game:_gameid }, params["uid"], params["sid"], false);
			
			if (!failure) {
				function setLength () {
					try {
						Object.defineProperty(localStorage, "length", {
							configurable: true,
							get: function () {
								return keys.length;
							}
						});
					} catch (e) {
						//Some browsers may not like setting the length
						//Unfortunatly we cannot do anything about this
					}
				}
				setLength();
				Storage.prototype.key = function (index) {
					if (this === window.localStorage) {
						setLength();
						
						return keys[index];
					} else {
						return _key.call(this, index);
					}
				};
				Storage.prototype.getItem = function (key) {
					if (this === window.localStorage) {
						setLength();
						
						return cache[key];
					} else {
						return _getItem.call(this, key);
					}
				};
				Storage.prototype.setItem = function (key, value) {
					if (this === window.localStorage) {
						setLength();
						
						if (cache[key] === undefined) {
							keys.push(key);
							keys.sort();
						}
						
						if (cache[key] !== value) {
							cache[key] = value;
							pendingUpdates[key] = "set";
						}
					} else {
						_setItem.call(this, key, value);
					}
				};
				Storage.prototype.removeItem = function (key) {
					if (this === window.localStorage) {
						setLength();
						
						delete cache[key];
						for (var i = 0; i < keys.length; i++) {
							if (keys[i] == key) {
								keys.splice(i, 1);
								break;
							}
						}
						pendingUpdates[key] = "rem";
					} else {
						_removeItem.call(this, key);
					}
				};
				Storage.prototype.clear = function () {
					if (this === window.localStorage) {
						setLength();
						
						for (var i = 0; i < keys.length; i++) {
							this.removeItem(key[i]);
						}
					} else {
						_removeItem.clear(this);
					}
				};
				
				//Every frame check for pending updates and apply them
				//This will cut down on calls because only the last command gets applied
				setInterval(function () {
					for (var i in pendingUpdates) {
						if (pendingUpdates[i] == "set") {
							storage.setItem(i, cache[i]);
						} else if (pendingUpdates[i] == "rem") {
							storage.removeItem(i);
						}
					}
					
					pendingUpdates = {};
				}, 10);
			}
			
			return !failure;
		};
		
		if (typeof window !== 'undefined') {
			//Watch for messages from SandBoxd
			window.addEventListener("message", function (e) {
				var onSessionUpdate = function (data) {
					//We need to turn on automatic cloud storage if we have just logged in/registered
					var justLoggedIn = params["uid"] == 0 && data.uid != 0;
					
					params["sid"] = data.sid;
					params["uid"] = data.uid;
					
					if (justLoggedIn) {
						if (autoStorageActivated) {
							//Write out local storage to cloud
							var len = window.localStorage.length;
							var successes = 0;
							for (var i = 0; i < len; i++) {
								var key = window.localStorage.key(i);
								storage.setItem(key, window.localStorage.getItem(key), function (err, data) {
									if (err == null) {
										successes++;
										
										if (successes == len) {
											//Activate automatic cloud storage
											autoCloudStorage();
										}
									} else {
										//Some error occurred -- do not turn on automatic cloud storage
									}
								});
							}
						}
						
						if (currRegistration != null) {
							//Save callback to local variable because we want currRegistration to be null even if there is an error
							var cb = currRegistration;
							currRegistration = null;
							cb(null, { uid:data.uid });
						}
					}
				};
				
				var onTransactionResponse = function (data) {
					if (currTransaction != null) {
						//Save callback to local variable because we want currTransaction to be null even if there is an error
						var cb = currTransaction;
						currTransaction = null;
						cb(data.error, data.microid);
					}
				};
				
				var o = e.data;
				
				if (typeof o === "object") {
					if (o.type === "session") {
						onSessionUpdate(o.data);
					} else if (o.type === "transactionResponse") {
						onTransactionResponse(o.data);
					}
					
					dispatchEvent(o.type, o.data);
				}
			}, false);
		}
		
		return /** @lends module:sandboxd */ {
			
			/**
			 * <p>Initialize the library. This function must be called before using the SandBoxd API.</p>
			 * 
			 * @name module:sandboxd.init
			 * @function
			 * @param {Integer} gameid The unique game identifier.
			 * @param {String} apikey The API key for this game.
			 * @param {String} [host=api.sandboxd.com] Set this if you want to override the default host.
			 */
			init: function (gameid, apikey, host) {
				_gameid = gameid;
				_apikey = apikey;
				if (host !== undefined) _host = host;
			},
			
			/**
			 * <p><b>[Client Only]</b> Turn on automatic management of storage via the localStorage object.</p>
			 * 
			 * <p>This will intercept all calls to localStorage and store the data in
			 * the SandBoxd cloud instead.</p>
			 * 
			 * @name module:sandboxd.autoCloudStorage
			 * @function
			 * @returns {Boolean} True if we are using cloud storage or false if an error occurred.
			 */
			autoCloudStorage: autoCloudStorage,
			
			/**
			 * <p>Verify that the specified user is who they claim to be.</p>
			 * 
			 * <p>This is most commonly used for server-side verification of a new
			 * user who has just connected to your server.</p>
			 * 
			 * @name module:sandboxd.verifyUser
			 * @function
			 * @param {Integer} uid The unique identifier of the user.
			 * @param {String} sid The session identifier of the user.
			 * @param {standardCallback} [cb] The result of the query.
			 */
			verifyUser: function (a1, a2, a3) {
				checkInit();
				
				var o = uidSidCallbackOverload(a1, a2, a3);
				query("GET", "/gamesessions/verify", o.cb, null, o.uid, o.sid, true, true);
			},
			
			/**
			 * <p>Get the user object for the specified user.</p>
			 * 
			 * @name module:sandboxd.getUser
			 * @function
			 * @param {Integer} uid The unique identifier of the user.
			 * @param {standardCallback} [cb] The result of the query.
			 */
			/**
			 * <p><b>[Client Only]</b> Get the user object for the current user.</p>
			 * 
			 * @name module:sandboxd.getUser
			 * @function
			 * @param {standardCallback} [cb] The result of the query.
			 */
			getUser: function (a1, a2) {
				var o = uidCallbackOverload(a1, a2);
				query("GET", "/users/" + o.uid, o.cb);
			},
			
			/**
			 * <p>Get all the specified user's friends.</p>
			 * 
			 * @name module:sandboxd.getUserFriends
			 * @function
			 * @param {Integer} uid The unique identifier of the user.
			 * @param {standardCallback} [cb] The result of the query.
			 */
			/**
			 * <p><b>[Client Only]</b> Get all the current user's friends.</p>
			 * 
			 * @name module:sandboxd.getUserFriends
			 * @function
			 * @param {standardCallback} [cb] The result of the query.
			 */
			getUserFriends: function (a1, a2) {
				var o = uidCallbackOverload(a1, a2);
				queryAll("GET", "/friends", o.cb, { user:o.uid });
			},
			
			/**
			 * <p>Retrieve the display group that the specified user has set for this game.</p>
			 * 
			 * @name module:sandboxd.getUserGroup
			 * @function
			 * @param {Integer} uid The unique identifier of the user.
			 * @param {String} sid The session identifier of the user.
			 * @param {standardCallback} [cb] The result of the query.
			 */
			/**
			 * <p><b>[Client Only]</b> Retrieve the display group that the current user has set for this game.</p>
			 * 
			 * @name module:sandboxd.getUserGroup
			 * @function
			 * @param {standardCallback} [cb] The result of the query.
			 */
			getUserGroup: function (a1, a2, a3) {
				checkInit();
				
				var o = uidSidCallbackOverload(a1, a2, a3);
				query("GET", "/displaygroups/" + _gameid, o.cb, null, o.uid, o.sid);
			},
			
			/**
			 * <p>Get the group object for the specified group.</p>
			 * 
			 * @name module:sandboxd.getGroup
			 * @function
			 * @param {Integer} gid The unique identifier of the group.
			 * @param {standardCallback} [cb] The result of the query.
			 */
			getGroup: function (gid, cb) {
				query("GET", "/groups/" + gid, cb);
			},
			
			/**
			 * <p>Get all previously completed transactions for the specified user.</p>
			 * 
			 * @name module:sandboxd.getUserTransactions
			 * @function
			 * @param {Integer} uid The unique identifier of the user.
			 * @param {String} sid The session identifier of the user.
			 * @param {standardCallback} [cb] The result of the query.
			 */
			/**
			 * <p><b>[Client Only]</b> Get all previously completed transactions for the current user.</p>
			 * 
			 * @name module:sandboxd.getUserTransactions
			 * @function
			 * @param {standardCallback} [cb] The result of the query.
			 */
			getUserTransactions: function (a1, a2, a3) {
				checkInit();
				
				var o = uidSidCallbackOverload(a1, a2, a3);
				queryAll("GET", "/transactions", o.cb, { game:_gameid }, o.uid, o.sid);
			},
			
			/**
			 * <p><b>[Client Only]</b> Create a micro-transaction for the current user. Calling this will present the user with a purchase dialog to accept or decline the amount specified.</p>
			 * 
			 * @name module:sandboxd.createTransaction
			 * @function
			 * @param {String} microid A unique identifier for this transaction you make up. You can use the microid to determine if a user has previously purchased this transaction.
			 * @param {String} description A description of the virtual item the user is purchasing. This will be presented to the user so they can decide whether to accept the purchase or not.
			 * @param {Integer} amount The cost of the transaction in credits. <b>100 credits = 1 USD</b>
			 */
			createTransaction: function (microid, description, amount, cb) {
				if (currTransaction != null) return;	//Only one transaction allowed at a time
				
				currTransaction = cb;
				postMessage("transaction", { microid:microid, desc:description, amount:amount });
			},
			
			/**
			 * <p>Since you can only initiate transactions on the client-side, it is sometimes useful to verify their success on the server.</p>
			 * 
			 * <p>Call this function to verify that the given user has indeed received the transaction in question.</p>
			 * 
			 * <p>A response with no error indicates the transaction is valid.</p>
			 * 
			 * @name module:sandboxd.verifyTransaction
			 * @function
			 * @param {String} microid The unique transaction identifier.
			 * @param {Integer} uid The unique identifier of the user.
			 * @param {String} sid The session identifier of the user.
			 * @param {standardCallback} [cb] The result of the query.
			 */
			verifyTransaction: function (microid, a1, a2, a3) {
				var o = uidSidCallbackOverload(a1, a2, a3);
				getUserTransactions(a1, a2, a3, function (err, data) {
					if (err) {
						o.cb(err, null);
						return;
					}
					
					for (var i = 0; i < data.length; i++) {
						if (data[i].microid === microid) {
							o.cb(null, null);
						}
					}
					
					o.cb("Transaction not found.", null);
				});
			},
			
			/**
			 * <p>Update the internal location of the specified user within your game.</p>
			 * 
			 * <p>The user's location will be displayed to their friends on the friends list. When a friend clicks to join
			 * the specified user's game the string provided in the <i>data</i> argument will be included as a URL
			 * parameter to the game.</p>
			 * 
			 * @example <caption>User 123 joins a multiplayer room with id 5 in a game called "Example Shooter"</caption>
			 * //Friends will see this below the user's name: "Example Shooter - Deathmatch".
			 * sandboxd.updateLocation("Deathmatch", "roomid:5", 123, "SessionID")
			 * 
			 * @name module:sandboxd.updateLocation
			 * @function
			 * @param {String} label A user friendly way to describe where the user is within your game.
			 * @param {String} data A unique way to identify where the user is within your game.
			 * @param {Integer} uid The unique identifier of the user.
			 * @param {String} sid The session identifier of the user.
			 * @param {standardCallback} [cb] The result of the query.
			 */
			/**
			 * <p><b>[Client Only]</b> Update the internal location of the curent user within your game.</p>
			 * 
			 * <p>The user's location will be displayed to their friends on the friends list. When a friend clicks to join
			 * the curent user's game the string provided in the <i>data</i> argument will be included as a URL
			 * parameter to the game.</p>
			 * 
			 * @example <caption>The current user joins a multiplayer room with id 5 in a game called "Example Shooter"</caption>
			 * //Friends will see this below the user's name: "Example Shooter - Deathmatch".
			 * sandboxd.updateLocation("Deathmatch", "roomid:5")
			 * 
			 * @name module:sandboxd.updateLocation
			 * @function
			 * @param {String} label A user friendly way to describe where the user is within your game.
			 * @param {String} data A unique way to identify where the user is within your game.
			 * @param {standardCallback} [cb] The result of the query.
			 */
			updateLocation: function (label, data, a1, a2, a3) {
				checkInit();
				
				var o = uidSidCallbackOverload(a1, a2, a3);
				query("POST", "/gamesessions/update", o.cb, { session:o.sid, label:label, data:data }, o.uid, o.sid);
			},
			
			/**
			 * <p><b>[Client Only]</b> Subscribe to an event sent by SandBoxd.</p>
			 * 
			 * @name module:sandboxd.subscribe
			 * @function
			 * @param {String} type The name of the event to subscribe to.
			 * @param {dataCallback} [cb] A callback to be called when the event fires.
			 */
			subscribe: function (type, cb) {
				listeners.push({type:type, cb:cb});
			},
			
			/**
			 * <p><b>[Client Only]</b> Unsubscribe from an event.</p>
			 * 
			 * @name module:sandboxd.unsubscribe
			 * @function
			 * @param {String} type The name of the event to unsubscribe from.
			 * @param {dataCallback} [cb] The callback that you used to subscribe.
			 */
			unsubscribe: function (type, cb) {
				for (var i = 0; i < listeners.length; i++) {
					if (listeners[i].type === type && listeners[i].cb === cb) {
						listeners.splice(i, 1);
						return;
					}
				}
			},
			
			/**
			 * <p><b>[Client Only]</b> Prompt the user to share their high score with others through various mediums, but only if the user's score beats their previous high score. This is usually called after at the end of a gameplay round.</p>
			 * 
			 * <p>If the user is logged in then they will be presented with an option to share their score to various mediums. Additionally the user's score stat will be updated. The callback will never be called in this case.</p>
			 * 
			 * <p>If the user is logged out then they will also be presented the option to register with SandBoxd. If the user decides to register, their high score will automatically be associated with their account. The provided callback will then be called so you can update any other relevant data for the user such as cloud storage, etc. Please note that if you have automatic cloud storage turned on then the user's SandBoxd storage will be updated automatically.</p>
			 * 
			 * @name module:sandboxd.highScore
			 * @function
			 * @param {String} statName The name of stat in which you got a high score.
			 * @param {Number} statValue The value of the player's high score.
			 * @param {Boolean} [showPopup] Set this to false if you don't want a share screen to popup. IE only the user's high score will be updated.
			 * @param {standardCallback} [cb] A callback that is called upon successful registration.
			 */
			highScore: function (statName, statValue, showPopup, cb) {
				if (currRegistration != null) return;
				if (showPopup == null) showPopup = true;
				
				if (params["uid"] == 0) {
					currRegistration = function (err, data) {
						sandboxd.stats.update(statName, statValue);
						
						if (cb != null) cb(null, data);
					};
					
					if (showPopup) postMessage("highScore", { statName:statName, statValue:statValue });
				} else {
					sandboxd.stats.get(statName, function (err, data) {
						if (err == null && (data == null || statValue > data.value)) {
							sandboxd.stats.update(statName, statValue);
							
							if (showPopup) postMessage("highScore", { statName:statName, statValue:statValue });
						}
					});
				}
			},
			
			/**
			 * <p><b>[Client Only]</b> Displays a prompt that allows the user to invite their friends.</p>
			 * 
			 * <p>You can supply custom data that will be provided to your game as query parameter when the user accepts the invite.</p>
			 * 
			 * @name module:sandboxd.invite
			 * @function
			 * @param {String} [data] Custom data to append to the query string when the user accepts the invite.
			 */
			invite: function (data) {
				postMessage("invite", { data:data });
			},
			
			/**
			 * Access to cloud storage.
			 * 
			 * @namespace {Object} module:sandboxd.storage
			 */
			storage: storage,
			
			/**
			 * Access to user achievements.
			 * 
			 * @namespace {Object} module:sandboxd.achievements
			 */
			achievements: {
				
				/**
				 * <p>Create or update an achievement for the specified user.</p>
				 * 
				 * @name module:sandboxd.achievements.update
				 * @function
				 * @param {String} key The achievement name.
				 * @param {Integer} value The value to set this achievement to. Must be between 0 and the maximum value for this achievement.
				 * @param {Integer} uid The unique identifier of the user.
				 * @param {String} sid The session identifier of the user.
				 * @param {standardCallback} [cb] The result of the query.
				 */
				/**
				 * <p><b>[Client Only]</b> Create or update an achievement for the current user.</p>
				 * 
				 * @name module:sandboxd.achievements.update
				 * @function
				 * @param {String} key The achievement name.
				 * @param {Integer} value The value to set this achievement to. Must be between 0 and the maximum value for this achievement.
				 * @param {standardCallback} [cb] The result of the query.
				 */
				update: function (key, value, a1, a2, a3) {
					checkInit();
					
					var o = uidSidCallbackOverload(a1, a2, a3);
					query("POST", "/achievements/update/" + _gameid, o.cb, { key:key, value:value }, o.uid, o.sid);
				},
				
				/**
				 * <p>View an achievement for the specified user. Returns null if the user does not have this achievement.</p>
				 * 
				 * @name module:sandboxd.achievements.get
				 * @function
				 * @param {String} key The achievement name.
				 * @param {Integer} uid The unique identifier of the user.
				 * @param {standardCallback} [cb] The result of the query.
				 */
				/**
				 * <p><b>[Client Only]</b> View an achievement for the current user. Returns null if the user does not have this achievement.</p>
				 * 
				 * <p>The achievement object returned will have a convenience function "update()" to update the value.</p>
				 * 
				 * @name module:sandboxd.achievements.get
				 * @function
				 * @param {String} key The achievement name.
				 * @param {standardCallback} [cb] The result of the query.
				 */
				get: function (key, a1, a2) {
					var self = this;
					var o = uidCallbackOverload(a1, a2);
					query("GET", "/achievements/" + o.uid, function (err, data) {
						if (err == null && data != null) {
							data.update = function (value) {
								this.value = value;
								self.update(this.achievement.name, value);
							}.bind(data);
						}
						
						if (o.cb != null) o.cb(err, data);
					}, { key:key, game:_gameid });
				},
				
				/**
				 * <p>List all achievements for the specified user.</p>
				 * 
				 * @name module:sandboxd.achievements.list
				 * @function
				 * @param {Integer} uid The unique identifier of the user.
				 * @param {standardCallback} [cb] The result of the query.
				 */
				/**
				 * <p><b>[Client Only]</b> List all achievements for the current user.</p>
				 * 
				 * <p>The achievement objects returned have a convenience function "update()" to update the value.</p>
				 * 
				 * @name module:sandboxd.achievements.list
				 * @function
				 * @param {standardCallback} [cb] The result of the query.
				 */
				list: function (a1, a2) {
					var self = this;
					var o = uidCallbackOverload(a1, a2);
					queryAll("GET", "/achievements", function (err, data) {
						if (err == null) {
							injectFunctionToEach(data, "update", function (value) {
								this.value = value;
								self.update(this.achievement.name, value);
							});
						}
						
						if (o.cb != null) o.cb(err, data);
					}, { user:o.uid, game:_gameid });
				},
				
				/**
				 * <p>List all achievement definitions for this game.</p>
				 * 
				 * <p>The achievement definition objects returned have a convenience function "create()" to create a new achievement for the current user.</p>
				 * 
				 * @name module:sandboxd.achievements.getDefinitions
				 * @function
				 * @param {standardCallback} [cb] The result of the query.
				 */
				getDefinitions: function (cb) {
					var self = this;
					queryAll("GET", "/achievementdefinitions", function (err, data) {
						if (err == null) {
							injectFunctionToEach(data, "create", function (value, cb) {
								self.update(this.name, value, function (err, data) {
									if (err == null) {
										data["update"] = (function (value) {
											this.value = value;
											self.update(this.achievement.name, value);
										}).bind(data);
									}
									
									if (cb != null) cb(err, data);
								});
							});
						}
						
						if (cb != null) cb(err, data);
					}, { game:_gameid });
				}
				
			},
			
			/**
			 * Access to user statistics.
			 * 
			 * @namespace {Object} module:sandboxd.stats
			 */
			stats: {
				
				/**
				 * <p>Create or update an statistic for the specified user.</p>
				 * 
				 * @name module:sandboxd.stats.update
				 * @function
				 * @param {String} key The statistic name.
				 * @param {String|Number} value The value to set this statistic to. If this statistic is ranked then value must be a number.
				 * @param {Integer} uid The unique identifier of the user.
				 * @param {String} sid The session identifier of the user.
				 * @param {standardCallback} [cb] The result of the query.
				 */
				/**
				 * <p><b>[Client Only]</b> Create or update an statistic for the current user.</p>
				 * 
				 * @name module:sandboxd.stats.update
				 * @function
				 * @param {String} key The statistic name.
				 * @param {String|Number} value The value to set this statistic to. If this statistic is ranked then value must be a number.
				 * @param {standardCallback} [cb] The result of the query.
				 */
				update: function (key, value, a1, a2, a3) {
					checkInit();
					
					var o = uidSidCallbackOverload(a1, a2, a3);
					query("POST", "/stats/update/" + _gameid, o.cb, { key:key, value:value }, o.uid, o.sid);
				},
				
				/**
				 * <p>View a statistic for the specified user. Returns null if the user does not have this stat.</p>
				 * 
				 * @name module:sandboxd.stats.get
				 * @function
				 * @param {String} key The statistic name.
				 * @param {Integer} uid The unique identifier of the user.
				 * @param {standardCallback} [cb] The result of the query.
				 */
				/**
				 * <p><b>[Client Only]</b> View an statistic for the current user. Returns null if the user does not have this stat.</p>
				 * 
				 * <p>The statistic object returned will have a convenience function "update()" to update the value.</p>
				 * 
				 * @name module:sandboxd.stats.get
				 * @function
				 * @param {String} key The statistic name.
				 * @param {standardCallback} [cb] The result of the query.
				 */
				get: function (key, a1, a2) {
					var self = this;
					var o = uidCallbackOverload(a1, a2);
					query("GET", "/stats/" + o.uid, function (err, data) {
						if (err == null && data != null) {
							data.update = function (value) {
								this.value = value;
								self.update(this.stat.name, value);
							}.bind(data);
						}
						
						if (o.cb != null) o.cb(err, data);
					}, { key:key, game:_gameid });
				},
				
				/**
				 * <p>List all statistics for the specified user.</p>
				 * 
				 * @name module:sandboxd.stats.list
				 * @function
				 * @param {Integer} uid The unique identifier of the user.
				 * @param {standardCallback} [cb] The result of the query.
				 */
				/**
				 * <p><b>[Client Only]</b> List all statistics for the specified user.</p>
				 * 
				 * <p>The stat objects returned have a convenience function "update()" to update the value.</p>
				 * 
				 * @name module:sandboxd.stats.list
				 * @function
				 * @param {standardCallback} [cb] The result of the query.
				 */
				list: function (a1, a2) {
					var self = this;
					var o = uidCallbackOverload(a1, a2);
					queryAll("GET", "/stats", function (err, data) {
						if (err == null) {
							injectFunctionToEach(data, "update", function (value) {
								this.value = value;
								self.update(this.stat.name, value);
							});
						}
						
						if (o.cb != null) o.cb(err, data);
					}, { user:o.uid, game:_gameid });
				},
				
				/**
				 * <p>List all statistic definitions for this game.</p>
				 * 
				 * <p>The stat definition objects returned have a convenience function "create()" to create a new stat for the current user.</p>
				 * 
				 * @name module:sandboxd.stats.getDefinitions
				 * @function
				 * @param {standardCallback} [cb] The result of the query.
				 */
				getDefinitions: function (cb) {
					var self = this;
					queryAll("GET", "/statdefinitions", function (err, data) {
						if (err == null) {
							injectFunctionToEach(data, "create", function (value, cb) {
								self.update(this.name, value, function (err, data) {
									if (err == null) {
										data["update"] = (function (value) {
											this.value = value;
											self.update(this.stat.name, value);
										}).bind(data);
									}
									
									if (cb != null) cb(err, data);
								});
							});
						}
						
						if (cb != null) cb(err, data);
					}, { game:_gameid });
				}
				
			}
			
		};
	})();
	
	if (typeof module !== 'undefined' && module.exports) {
		//CommonJS supported
		module.exports = sandboxd;
    } else {
		//Included as a script
		this.sandboxd = sandboxd;
    }
})();