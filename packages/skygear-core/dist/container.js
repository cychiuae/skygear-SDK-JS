'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.USER_CHANGED = undefined;

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asset = require('./asset');

var _asset2 = _interopRequireDefault(_asset);

var _user = require('./user');

var _user2 = _interopRequireDefault(_user);

var _role = require('./role');

var _role2 = _interopRequireDefault(_role);

var _acl = require('./acl');

var _acl2 = _interopRequireDefault(_acl);

var _record = require('./record');

var _record2 = _interopRequireDefault(_record);

var _reference = require('./reference');

var _reference2 = _interopRequireDefault(_reference);

var _query = require('./query');

var _query2 = _interopRequireDefault(_query);

var _database = require('./database');

var _database2 = _interopRequireDefault(_database);

var _pubsub = require('./pubsub');

var _pubsub2 = _interopRequireDefault(_pubsub);

var _relation = require('./relation');

var _geolocation = require('./geolocation');

var _geolocation2 = _interopRequireDefault(_geolocation);

var _store = require('./store');

var _store2 = _interopRequireDefault(_store);

var _type = require('./type');

var _error = require('./error');

var _util = require('./util');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/**
 * Copyright 2015 Oursky Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/* eslint camelcase: 0 */
var request = require('superagent');
var _ = require('lodash');
var ee = require('event-emitter');

var USER_CHANGED = exports.USER_CHANGED = 'userChanged';

var Container = function () {
  function Container() {
    _classCallCheck(this, Container);

    this.url = 'http://myapp.skygeario.com/';
    this.apiKey = null;
    this.token = null;
    this._accessToken = null;
    this._user = null;
    this._deviceID = null;
    this._getAccessToken();
    this._getDeviceID();
    this._privateDB = null;
    this._publicDB = null;
    this.request = request;
    this._internalPubsub = new _pubsub2.default(this, true);
    this._relation = new _relation.RelationAction(this);
    this._pubsub = new _pubsub2.default(this, false);
    this.autoPubsub = true;
    this._cacheResponse = true;
    this.ee = ee({});
    /**
     * Options for how much time to wait for client request to complete.
     *
     * @type {Object}
     * @property {number} [timeoutOptions.deadline] - deadline for the request
     * and response to complete (in milliseconds)
     * @property {number} [timeoutOptions.response=60000] - maximum time to
     * wait for an response (in milliseconds)
     *
     * @see http://visionmedia.github.io/superagent/#timeouts
     */
    this.timeoutOptions = {
      response: 60000
    };
  }

  _createClass(Container, [{
    key: 'config',
    value: function config(options) {
      var _this = this;

      if (options.apiKey) {
        this.apiKey = options.apiKey;
      }
      if (options.endPoint) {
        this.endPoint = options.endPoint;
      }

      var promises = [this._getUser(), this._getAccessToken(), this._getDeviceID()];
      return Promise.all(promises).then(function () {
        _this.reconfigurePubsubIfNeeded();
        return _this;
      }, function () {
        return _this;
      });
    }
  }, {
    key: 'configApiKey',
    value: function configApiKey(ApiKey) {
      this.apiKey = ApiKey;
    }
  }, {
    key: 'clearCache',
    value: function clearCache() {
      return this.store.clearPurgeableItems();
    }
  }, {
    key: 'onUserChanged',
    value: function onUserChanged(listener) {
      this.ee.on(USER_CHANGED, listener);
      return new _util.EventHandle(this.ee, USER_CHANGED, listener);
    }
  }, {
    key: 'signupWithUsername',
    value: function signupWithUsername(username, password) {
      return this._signup(username, null, password);
    }
  }, {
    key: 'signupWithEmail',
    value: function signupWithEmail(email, password) {
      return this._signup(null, email, password);
    }
  }, {
    key: 'signupWithUsernameAndProfile',
    value: function signupWithUsernameAndProfile(username, password) {
      var _this2 = this;

      var profile = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};

      return this.signupWithUsername(username, password).then(function (user) {
        return _this2._createProfile(user, profile);
      });
    }
  }, {
    key: 'signupWithEmailAndProfile',
    value: function signupWithEmailAndProfile(email, password) {
      var _this3 = this;

      var profile = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};

      return this.signupWithEmail(email, password).then(function (user) {
        return _this3._createProfile(user, profile);
      });
    }
  }, {
    key: 'signupAnonymously',
    value: function signupAnonymously() {
      return this._signup(null, null, null);
    }
  }, {
    key: '_signup',
    value: function _signup(username, email, password) {
      return this.makeRequest('auth:signup', {
        username: username,
        email: email,
        password: password
      }).then(this._authResolve.bind(this));
    }
  }, {
    key: '_createProfile',
    value: function _createProfile(user, profile) {
      var record = new this.UserRecord(_extends({
        _id: 'user/' + user.id
      }, profile));
      return this.publicDB.save(record);
    }
  }, {
    key: '_authResolve',
    value: function _authResolve(body) {
      var _this4 = this;

      return Promise.all([this._setUser(body.result), this._setAccessToken(body.result.access_token)]).then(function () {
        _this4.reconfigurePubsubIfNeeded();
        return _this4.currentUser;
      });
    }
  }, {
    key: 'loginWithUsername',
    value: function loginWithUsername(username, password) {
      return this.makeRequest('auth:login', {
        username: username,
        password: password
      }).then(this._authResolve.bind(this));
    }
  }, {
    key: 'loginWithEmail',
    value: function loginWithEmail(email, password) {
      return this.makeRequest('auth:login', {
        email: email,
        password: password
      }).then(this._authResolve.bind(this));
    }
  }, {
    key: 'loginWithProvider',
    value: function loginWithProvider(provider, authData) {
      return this.makeRequest('auth:login', {
        provider: provider,
        auth_data: authData
      }).then(this._authResolve.bind(this));
    }
  }, {
    key: 'logout',
    value: function logout() {
      var _this5 = this;

      return this.unregisterDevice().then(function () {
        _this5.clearCache();
        return _this5.makeRequest('auth:logout', {});
      }, function (error) {
        if (error.code === _error.ErrorCodes.InvalidArgument && error.message === 'Missing device id') {
          _this5.clearCache();
          return _this5.makeRequest('auth:logout', {});
        }
        return Promise.reject(error);
      }).then(function () {
        return Promise.all([_this5._setAccessToken(null), _this5._setUser(null)]).then(function () {
          return null;
        });
      }, function (err) {
        return _this5._setAccessToken(null).then(function () {
          return Promise.reject(err);
        });
      });
    }
  }, {
    key: 'whoami',
    value: function whoami() {
      return this.makeRequest('me', {}).then(this._authResolve.bind(this));
    }
  }, {
    key: 'changePassword',
    value: function changePassword(oldPassword, newPassword) {
      var invalidate = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : false;

      if (invalidate) {
        throw Error('Invalidate is not yet implemented');
      }
      return this.makeRequest('auth:password', {
        old_password: oldPassword,
        password: newPassword
      }).then(this._authResolve.bind(this));
    }
  }, {
    key: 'saveUser',
    value: function saveUser(user) {
      var _this6 = this;

      var payload = {
        _id: user.id, // eslint-disable-line camelcase
        email: user.email,
        username: user.username
      };
      if (user.roles) {
        payload.roles = _.map(user.roles, function (perRole) {
          return perRole.name;
        });
      }
      return this.makeRequest('user:update', payload).then(function (body) {
        var newUser = _this6.User.fromJSON(body.result);
        var currentUser = _this6.currentUser;

        if (newUser && currentUser && newUser.id === currentUser.id) {
          return _this6._setUser(body.result);
        } else {
          return newUser;
        }
      });
    }
  }, {
    key: '_getUsersBy',
    value: function _getUsersBy(emails, usernames) {
      var _this7 = this;

      return this.makeRequest('user:query', {
        emails: emails,
        usernames: usernames
      }).then(function (body) {
        return body.result.map(function (r) {
          return new _this7.User(r.data);
        });
      });
    }
  }, {
    key: 'getUsersByEmail',
    value: function getUsersByEmail(emails) {
      return this._getUsersBy(emails, null);
    }
  }, {
    key: 'getUsersByUsername',
    value: function getUsersByUsername(usernames) {
      return this._getUsersBy(null, usernames);
    }
  }, {
    key: 'discoverUserByEmails',
    value: function discoverUserByEmails(emails) {
      return this.publicDB.query(new _query2.default(this.UserRecord).havingEmails(emails));
    }
  }, {
    key: 'discoverUserByUsernames',
    value: function discoverUserByUsernames(usernames) {
      return this.publicDB.query(new _query2.default(this.UserRecord).havingUsernames(usernames));
    }
  }, {
    key: 'setAdminRole',
    value: function setAdminRole(roles) {
      var roleNames = _.map(roles, function (perRole) {
        return perRole.name;
      });

      return this.makeRequest('role:admin', {
        roles: roleNames
      }).then(function (body) {
        return body.result;
      });
    }
  }, {
    key: 'setDefaultRole',
    value: function setDefaultRole(roles) {
      var roleNames = _.map(roles, function (perRole) {
        return perRole.name;
      });

      return this.makeRequest('role:default', {
        roles: roleNames
      }).then(function (body) {
        return body.result;
      });
    }
  }, {
    key: 'setDefaultACL',
    value: function setDefaultACL(acl) {
      this.Record.defaultACL = acl;
    }
  }, {
    key: 'setRecordCreateAccess',
    value: function setRecordCreateAccess(recordClass, roles) {
      var roleNames = _.map(roles, function (perRole) {
        return perRole.name;
      });

      return this.makeRequest('schema:access', {
        type: recordClass.recordType,
        create_roles: roleNames
      }).then(function (body) {
        return body.result;
      });
    }
  }, {
    key: 'setRecordDefaultAccess',
    value: function setRecordDefaultAccess(recordClass, acl) {
      return this.makeRequest('schema:default_access', {
        type: recordClass.recordType,
        default_access: acl.toJSON()
      }).then(function (body) {
        return body.result;
      });
    }
  }, {
    key: 'inferDeviceType',
    value: function inferDeviceType() {
      // To be implmented by subclass
      // TODO: probably web / node, handle it later
      throw new Error('Failed to infer type, please supply a value');
    }

    /**
     * You can register your device for receiving push notifications.
     *
     * @param {string} token - The device token
     * @param {string} type - The device type (either 'ios' or 'android')
     * @param {string} topic - The device topic, refer to application bundle
     * identifier on iOS and application package name on Android.
     **/

  }, {
    key: 'registerDevice',
    value: function registerDevice(token, type, topic) {
      var _this8 = this;

      if (!token) {
        throw new Error('Token cannot be empty');
      }
      if (!type) {
        type = this.inferDeviceType();
      }

      var deviceID = void 0;
      if (this.deviceID) {
        deviceID = this.deviceID;
      }

      return this.makeRequest('device:register', {
        type: type,
        id: deviceID,
        topic: topic,
        device_token: token
      }).then(function (body) {
        return _this8._setDeviceID(body.result.id);
      }, function (error) {
        // Will set the deviceID to null and try again iff deviceID is not null.
        // The deviceID can be deleted remotely, by apns feedback.
        // If the current deviceID is already null, will regards as server fail.
        var errorCode = null;
        if (error.error) {
          errorCode = error.error.code;
        }
        if (_this8.deviceID && errorCode === _error.ErrorCodes.ResourceNotFound) {
          return _this8._setDeviceID(null).then(function () {
            return _this8.registerDevice(token, type);
          });
        } else {
          return Promise.reject(error);
        }
      });
    }
  }, {
    key: 'unregisterDevice',
    value: function unregisterDevice() {
      var _this9 = this;

      if (!this.deviceID) {
        return Promise.reject(new _error.SkygearError('Missing device id', _error.ErrorCodes.InvalidArgument));
      }

      return this.makeRequest('device:unregister', {
        id: this.deviceID
      }).then(function () {
        // do nothing
        return;
      }, function (error) {
        var errorCode = null;
        if (error.error) {
          errorCode = error.error.code;
        }
        if (errorCode === _error.ErrorCodes.ResourceNotFound) {
          // regard it as success
          return _this9._setDeviceID(null);
        } else {
          return Promise.reject(error);
        }
      });
    }
  }, {
    key: 'lambda',
    value: function lambda(name, data) {
      return this.makeRequest(name, {
        args: data
      }).then(function (resp) {
        return resp.result;
      });
    }
  }, {
    key: 'makeUploadAssetRequest',
    value: function makeUploadAssetRequest(asset) {
      var _this10 = this;

      return new Promise(function (resolve, reject) {
        _this10.makeRequest('asset:put', {
          filename: asset.name,
          'content-type': asset.contentType,
          'content-size': asset.file.size
        }).then(function (res) {
          var newAsset = _asset2.default.fromJSON(res.result.asset);
          var postRequest = res.result['post-request'];

          var postUrl = postRequest.action;
          if (postUrl.indexOf('/') === 0) {
            postUrl = postUrl.substring(1);
          }
          if (postUrl.indexOf('http') !== 0) {
            postUrl = _this10.url + postUrl;
          }

          var _request = _this10.request.post(postUrl).set('X-Skygear-API-Key', _this10.apiKey);
          if (postRequest['extra-fields']) {
            _.forEach(postRequest['extra-fields'], function (value, key) {
              _request = _request.field(key, value);
            });
          }

          _request.attach('file', asset.file).end(function (err) {
            if (err) {
              reject(err);
              return;
            }

            resolve(newAsset);
          });
        }, function (err) {
          reject(err);
        });
      });
    }
  }, {
    key: 'sendRequestObject',
    value: function sendRequestObject(action, data) {
      if (this.apiKey === null) {
        throw Error('Please config ApiKey');
      }
      var _data = _.assign({
        action: action,
        api_key: this.apiKey,
        access_token: this.accessToken
      }, data);
      var _action = action.replace(/:/g, '/');
      var req = this.request.post(this.url + _action).set('X-Skygear-API-Key', this.apiKey).set('X-Skygear-Access-Token', this.accessToken).set('Accept', 'application/json');
      if (this.timeoutOptions !== undefined && this.timeoutOptions !== null) {
        req = req.timeout(this.timeoutOptions);
      }
      return req.send(_data);
    }
  }, {
    key: 'makeRequest',
    value: function makeRequest(action, data) {
      var _this11 = this;

      var _request = this.sendRequestObject(action, data);
      return new Promise(function (resolve, reject) {
        _request.end(function (err, res) {
          // Do an application JSON parse because in some condition, the
          // content-type header will got strip and it will not deserial
          // the json for us.
          var body = getRespJSON(res);

          if (err) {
            var skyErr = body.error || err;
            if (skyErr.code === _this11.ErrorCodes.AccessTokenNotAccepted) {
              return Promise.all([_this11._setAccessToken(null), _this11._setUser(null)]).then(function () {
                reject({
                  status: err.status,
                  error: skyErr
                });
              });
            }
            reject({
              status: err.status,
              error: skyErr
            });
          } else {
            resolve(body);
          }
        });
      });
    }
  }, {
    key: '_getUser',
    value: function _getUser() {
      var _this12 = this;

      return this.store.getItem('skygear-user').then(function (userJSON) {
        var attrs = JSON.parse(userJSON);
        _this12._user = _this12.User.fromJSON(attrs);
      }, function (err) {
        console.warn('Failed to get user', err);
        _this12._user = null;
        return null;
      });
    }
  }, {
    key: '_setUser',
    value: function _setUser(attrs) {
      var _this13 = this;

      var value = void 0;
      if (attrs !== null) {
        this._user = new this.User(attrs);
        value = JSON.stringify(this._user.toJSON());
      } else {
        this._user = null;
        value = null;
      }

      var setItem = value === null ? this.store.removeItem('skygear-user') : this.store.setItem('skygear-user', value);
      return setItem.then(function () {
        _this13.ee.emit(USER_CHANGED, _this13._user);
        return value;
      }, function (err) {
        console.warn('Failed to persist user', err);
        return value;
      });
    }
  }, {
    key: '_getAccessToken',
    value: function _getAccessToken() {
      var _this14 = this;

      return this.store.getItem('skygear-accesstoken').then(function (token) {
        _this14._accessToken = token;
        return token;
      }, function (err) {
        console.warn('Failed to get access', err);
        _this14._accessToken = null;
        return null;
      });
    }
  }, {
    key: '_setAccessToken',
    value: function _setAccessToken(value) {
      this._accessToken = value;
      var setItem = value === null ? this.store.removeItem('skygear-accesstoken') : this.store.setItem('skygear-accesstoken', value);
      return setItem.then(function () {
        return value;
      }, function (err) {
        console.warn('Failed to persist accesstoken', err);
        return value;
      });
    }
  }, {
    key: '_getDeviceID',
    value: function _getDeviceID() {
      var _this15 = this;

      return this.store.getItem('skygear-deviceid').then(function (deviceID) {
        _this15._deviceID = deviceID;
        return deviceID;
      }, function (err) {
        console.warn('Failed to get deviceid', err);
        _this15._deviceID = null;
        return null;
      });
    }
  }, {
    key: '_setDeviceID',
    value: function _setDeviceID(value) {
      var _this16 = this;

      this._deviceID = value;
      var setItem = value === null ? this.store.removeItem('skygear-deviceid') : this.store.setItem('skygear-deviceid', value);
      return setItem.then(function () {
        return value;
      }, function (err) {
        console.warn('Failed to persist deviceid', err);
        return value;
      }).then(function (deviceID) {
        _this16.reconfigurePubsubIfNeeded();
        return deviceID;
      });
    }
  }, {
    key: 'reconfigurePubsubIfNeeded',
    value: function reconfigurePubsubIfNeeded() {
      if (!this.autoPubsub) {
        return;
      }

      this._internalPubsub.reset();
      if (this.deviceID !== null) {
        this._internalPubsub.subscribe('_sub_' + this.deviceID, function (data) {
          console.log('Receivied data for subscription: ' + data);
        });
      }
      this._internalPubsub.reconfigure();
      this._pubsub.reconfigure();
    }

    /**
     * Subscribe a function callback on receiving message at the specified
     * channel.
     *
     * @param {string} channel - Name of the channel to subscribe
     * @param {function(object:*)} callback - function to be trigger with
     * incoming data.
     **/

  }, {
    key: 'on',
    value: function on(channel, callback) {
      return this.pubsub.on(channel, callback);
    }

    /**
     * Unsubscribe a function callback on the specified channel.
     *
     * If pass in `callback` is null, all callbacks in the specified channel
     * will be removed.
     *
     * @param {string} channel - Name of the channel to unsubscribe
     * @param {function(object:*)=} callback - function to be trigger with
     * incoming data.
     **/

  }, {
    key: 'off',
    value: function off(channel) {
      var callback = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : null;

      this.pubsub.off(channel, callback);
    }
  }, {
    key: 'defaultACL',
    get: function get() {
      return this.Record.defaultACL;
    }
  }, {
    key: 'Query',
    get: function get() {
      return _query2.default;
    }
  }, {
    key: 'User',
    get: function get() {
      return _user2.default;
    }
  }, {
    key: 'Role',
    get: function get() {
      return _role2.default;
    }
  }, {
    key: 'ACL',
    get: function get() {
      return _acl2.default;
    }
  }, {
    key: 'Record',
    get: function get() {
      return _record2.default;
    }
  }, {
    key: 'UserRecord',
    get: function get() {
      return _record2.default.extend('user');
    }
  }, {
    key: 'Sequence',
    get: function get() {
      return _type.Sequence;
    }
  }, {
    key: 'Asset',
    get: function get() {
      return _asset2.default;
    }
  }, {
    key: 'Reference',
    get: function get() {
      return _reference2.default;
    }
  }, {
    key: 'Geolocation',
    get: function get() {
      return _geolocation2.default;
    }
  }, {
    key: 'ErrorCodes',
    get: function get() {
      return _error.ErrorCodes;
    }
  }, {
    key: 'currentUser',
    get: function get() {
      return this._user;
    }
  }, {
    key: 'cacheResponse',
    get: function get() {
      return this._cacheResponse;
    },
    set: function set(value) {
      var b = !!value;
      this._cacheResponse = b;
      if (this._publicDB) {
        this._publicDB.cacheResponse = b;
      }
      if (this._privateDB) {
        this._privateDB.cacheResponse = b;
      }
    }
  }, {
    key: 'accessToken',
    get: function get() {
      return this._accessToken;
    }
  }, {
    key: 'deviceID',
    get: function get() {
      return this._deviceID;
    }
  }, {
    key: 'endPoint',
    get: function get() {
      return this.url;
    },
    set: function set(newEndPoint) {
      // TODO: Check the format
      if (newEndPoint) {
        if (!_.endsWith(newEndPoint, '/')) {
          newEndPoint = newEndPoint + '/';
        }
        this.url = newEndPoint;
      }
    }
  }, {
    key: 'store',
    get: function get() {
      if (!this._store) {
        this._store = (0, _store2.default)();
      }
      return this._store;
    }
  }, {
    key: 'publicDB',
    get: function get() {
      if (this._publicDB === null) {
        this._publicDB = new _database2.default('_public', this);
        this._publicDB.cacheResponse = this._cacheResponse;
      }
      return this._publicDB;
    }
  }, {
    key: 'privateDB',
    get: function get() {
      if (this.accessToken === null) {
        throw new Error('You must login before access to privateDB');
      }
      if (this._privateDB === null) {
        this._privateDB = new _database2.default('_private', this);
        this._privateDB.cacheResponse = this._cacheResponse;
      }
      return this._privateDB;
    }
  }, {
    key: 'Database',
    get: function get() {
      return _database2.default;
    }
  }, {
    key: 'relation',
    get: function get() {
      return this._relation;
    }
  }, {
    key: 'pubsub',
    get: function get() {
      return this._pubsub;
    }
  }]);

  return Container;
}();

exports.default = Container;


function getRespJSON(res) {
  if (res && res.body) {
    return res.body;
  }
  if (res && res.text) {
    try {
      return JSON.parse(res.text);
    } catch (err) {
      console.log('getRespJSON error. error: ', err);
    }
  }

  return {};
}