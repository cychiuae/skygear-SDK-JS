'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.AuthContainer = exports.USER_CHANGED = undefined;

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _util = require('./util');

var _error = require('./error');

var _role = require('./role');

var _role2 = _interopRequireDefault(_role);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

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
var _ = require('lodash');

var USER_CHANGED = exports.USER_CHANGED = 'userChanged';

var AuthContainer = exports.AuthContainer = function () {
  function AuthContainer(container) {
    _classCallCheck(this, AuthContainer);

    /**
     * @private
     */
    this.container = container;

    this._accessToken = null;
    this._user = null;
    this._getAccessToken();
  }

  /**
   * Currently logged-in user
   * @type {Record}
   */


  _createClass(AuthContainer, [{
    key: 'onUserChanged',


    /**
     * Registers listener which user record changed.
     *
     * @param  {function()} listener
     * @return {EventHandle}
     */
    value: function onUserChanged(listener) {
      this.container.ee.on(USER_CHANGED, listener);
      return new _util.EventHandle(this.container.ee, USER_CHANGED, listener);
    }

    /**
     * Creates a user account with the specified auth data, password and user
     * record data.
     *
     * @param  {Object} authData - unique identifier of the user
     * @param  {String} password - password of the user
     * @param  {Object} [data={}] - data saved to the user record
     * @return {Promise<Record>} promise with created user record
     */

  }, {
    key: 'signup',
    value: function signup(authData, password) {
      var data = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};

      return this.container.makeRequest('auth:signup', {
        auth_data: authData, // eslint-disable-line camelcase
        password: password,
        profile: data
      }).then(this._authResolve.bind(this));
    }

    /**
     * Creates a user account with the specified username, password and user
     * record data.
     *
     * @param  {String} username - username of the user
     * @param  {String} password - password of the user
     * @param  {Object} [data={}] - data saved to the user record
     * @return {Promise<Record>} promise with the created user record
     */

  }, {
    key: 'signupWithUsername',
    value: function signupWithUsername(username, password) {
      var data = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};

      return this.signup({
        username: username
      }, password, data);
    }

    /**
     * Creates a user account with the specified email, password and user record
     * data.
     *
     * @param  {String} email - email of the user
     * @param  {String} password - password of the user
     * @param  {Object} [data={}] - data saved to the user record
     * @return {Promise<Record>} promise with the created user record
     */

  }, {
    key: 'signupWithEmail',
    value: function signupWithEmail(email, password) {
      var data = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};

      return this.signup({
        email: email
      }, password, data);
    }

    /**
     * Creates an anonymous user account and log in as the created user.
     *
     * @return {Promise<Record>} promise with the created user record
     */

  }, {
    key: 'signupAnonymously',
    value: function signupAnonymously() {
      return this.signup(null, null, null);
    }

    /**
     * Logs in to an existing user account with the specified auth data and
     * password.
     *
     * @param  {Object} authData - unique identifier of the user
     * @param  {String} password - password of the user
     * @return {Promise<Record>} promise with the logged in user record
     */

  }, {
    key: 'login',
    value: function login(authData, password) {
      return this.container.makeRequest('auth:login', {
        auth_data: authData, // eslint-disable-line camelcase
        password: password
      }).then(this._authResolve.bind(this));
    }

    /**
     * Logs in to an existing user account with the specified username and
     * password.
     *
     * @param  {String} username - username of the user
     * @param  {String} password - password of the user
     * @return {Promise<Record>} promise with the logged in user record
     */

  }, {
    key: 'loginWithUsername',
    value: function loginWithUsername(username, password) {
      return this.login({
        username: username
      }, password);
    }

    /**
     * Logs in to an existing user account with the specified email and
     * password.
     *
     * @param  {String} email - email of the user
     * @param  {String} password - password of the user
     * @return {Promise<Record>} promise with the logged in user record
     */

  }, {
    key: 'loginWithEmail',
    value: function loginWithEmail(email, password) {
      return this.login({
        email: email
      }, password);
    }

    /**
     * Logs in to an existing user account with custom auth provider.
     *
     * @param  {String} provider - provider name
     * @param  {Object} authData - provider auth data
     * @return {Promise<Record>} promise with the logged in user record
     */

  }, {
    key: 'loginWithProvider',
    value: function loginWithProvider(provider, authData) {
      return this.container.makeRequest('auth:login', {
        provider: provider,
        provider_auth_data: authData // eslint-disable-line camelcase
      }).then(this._authResolve.bind(this));
    }

    /**
     * Logs out the current user of this container.
     *
     * @return {Promise} promise
     */

  }, {
    key: 'logout',
    value: function logout() {
      var _this = this;

      return this.container.push.unregisterDevice().catch(function (error) {
        if (error.code === _error.ErrorCodes.InvalidArgument && error.message === 'Missing device id') {
          return Promise.resolve();
        }

        return Promise.reject(error);
      }).then(function () {
        _this.container.clearCache();
        return _this.container.makeRequest('auth:logout', {});
      }).then(function () {
        return Promise.all([_this._setAccessToken(null), _this._setUser(null)]).then(function () {
          return null;
        });
      }).catch(function (err) {
        return _this._setAccessToken(null).then(function () {
          return Promise.reject(err);
        });
      });
    }

    /**
     * Retrieves current user record from server.
     *
     * @return {Promise<Record>} promise with current user record
     */

  }, {
    key: 'whoami',
    value: function whoami() {
      return this.container.makeRequest('me', {}).then(this._authResolve.bind(this));
    }

    /**
     * Changes the password of the current user.
     *
     * @param  {String}  oldPassword - old password of current user
     * @param  {String}  newPassword - new password of current user
     * @param  {Boolean} [invalidate=false] - not implemented
     * @return {Promise<Record>} promise with current user record
     */

  }, {
    key: 'changePassword',
    value: function changePassword(oldPassword, newPassword) {
      var invalidate = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : false;

      if (invalidate) {
        throw Error('Invalidate is not yet implemented');
      }
      return this.container.makeRequest('auth:password', {
        old_password: oldPassword, // eslint-disable-line camelcase
        password: newPassword
      }).then(this._authResolve.bind(this));
    }

    /**
     * Defines roles to have admin right.
     *
     * @param {Role[]} roles - roles to have admin right
     * @return {Promise<String[]>} promise with role names
     */

  }, {
    key: 'setAdminRole',
    value: function setAdminRole(roles) {
      var roleNames = _.map(roles, function (perRole) {
        return perRole.name;
      });

      return this.container.makeRequest('role:admin', {
        roles: roleNames
      }).then(function (body) {
        return body.result;
      });
    }

    /**
     * Sets default roles for new registered users.
     *
     * @param {Role[]} roles - default roles
     * @return {Promise<String[]>} promise with role names
     */

  }, {
    key: 'setDefaultRole',
    value: function setDefaultRole(roles) {
      var roleNames = _.map(roles, function (perRole) {
        return perRole.name;
      });

      return this.container.makeRequest('role:default', {
        roles: roleNames
      }).then(function (body) {
        return body.result;
      });
    }

    /**
     * Gets roles of users from server.
     *
     * @param  {Record[]|String[]} users - user records or user ids
     * @return {Promise<Object>} promise with userIDs-to-roles map
     */

  }, {
    key: 'fetchUserRole',
    value: function fetchUserRole(users) {
      var userIds = _.map(users, function (perUser) {
        // accept either user record or user id
        return perUser._id || perUser;
      });

      return this.container.makeRequest('role:get', {
        users: userIds
      }).then(function (body) {
        return Object.keys(body.result).map(function (key) {
          return [key, body.result[key]];
        }).reduce(function (acc, pairs) {
          return _extends({}, acc || {}, _defineProperty({}, pairs[0], pairs[1].map(function (name) {
            return new _role2.default(name);
          })));
        }, null);
      });
    }

    /**
     * Assigns roles to users.
     *
     * @param  {Record[]|String[]} users - target users
     * @param  {Role[]|String[]} roles - roles to be assigned
     * @return {Promise<String[]>} proimse with the target users
     */

  }, {
    key: 'assignUserRole',
    value: function assignUserRole(users, roles) {
      var userIds = _.map(users, function (perUser) {
        // accept either user record or user id
        return perUser._id || perUser;
      });

      var roleNames = _.map(roles, function (perRole) {
        // accept either role object or role name
        return perRole.name || perRole;
      });

      return this.container.makeRequest('role:assign', {
        users: userIds,
        roles: roleNames
      }).then(function (body) {
        return body.result;
      });
    }

    /**
     * Revokes roles from users.
     *
     * @param  {Record[]|String[]} users - target users
     * @param  {Role[]|String[]} roles - roles to be revoked
     * @return {Promise<String[]>} promise with target users
     */

  }, {
    key: 'revokeUserRole',
    value: function revokeUserRole(users, roles) {
      var userIds = _.map(users, function (perUser) {
        // accept either user record or user id
        return perUser._id || perUser;
      });

      var roleNames = _.map(roles, function (perRole) {
        // accept either role object or role name
        return perRole.name || perRole;
      });

      return this.container.makeRequest('role:revoke', {
        users: userIds,
        roles: roleNames
      }).then(function (body) {
        return body.result;
      });
    }
  }, {
    key: '_getAccessToken',
    value: function _getAccessToken() {
      var _this2 = this;

      return this.container.store.getItem('skygear-accesstoken').then(function (token) {
        _this2._accessToken = token;
        return token;
      }, function (err) {
        console.warn('Failed to get access', err);
        _this2._accessToken = null;
        return null;
      });
    }
  }, {
    key: '_setAccessToken',
    value: function _setAccessToken(value) {
      this._accessToken = value;
      var setItem = value === null ? this.container.store.removeItem('skygear-accesstoken') : this.container.store.setItem('skygear-accesstoken', value);
      return setItem.then(function () {
        return value;
      }, function (err) {
        console.warn('Failed to persist accesstoken', err);
        return value;
      });
    }
  }, {
    key: '_authResolve',
    value: function _authResolve(body) {
      var _this3 = this;

      return Promise.all([this._setUser(body.result.profile), this._setAccessToken(body.result.access_token)]).then(function () {
        _this3.container.pubsub._reconfigurePubsubIfNeeded();
        return _this3.currentUser;
      });
    }
  }, {
    key: '_getUser',
    value: function _getUser() {
      var _this4 = this;

      return this.container.store.getItem('skygear-user').then(function (userJSON) {
        var attrs = JSON.parse(userJSON);
        _this4._user = new _this4._User(attrs);
      }, function (err) {
        console.warn('Failed to get user', err);
        _this4._user = null;
        return null;
      });
    }
  }, {
    key: '_setUser',
    value: function _setUser(attrs) {
      var _this5 = this;

      var value = void 0;
      if (attrs !== null) {
        this._user = new this._User(attrs);
        value = JSON.stringify(this._user.toJSON());
      } else {
        this._user = null;
        value = null;
      }

      var setItem = value === null ? this.container.store.removeItem('skygear-user') : this.container.store.setItem('skygear-user', value);
      return setItem.then(function () {
        _this5.container.ee.emit(USER_CHANGED, _this5._user);
        return value;
      }, function (err) {
        console.warn('Failed to persist user', err);
        return value;
      });
    }
  }, {
    key: 'currentUser',
    get: function get() {
      return this._user;
    }

    /**
     * Current access token
     * @type {String}
     */

  }, {
    key: 'accessToken',
    get: function get() {
      return this._accessToken;
    }
  }, {
    key: '_User',
    get: function get() {
      return this.container.UserRecord;
    }
  }, {
    key: '_Query',
    get: function get() {
      return this.container.Query;
    }
  }]);

  return AuthContainer;
}();