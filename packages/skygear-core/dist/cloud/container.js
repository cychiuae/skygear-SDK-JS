'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _lodash = require('lodash');

var _lodash2 = _interopRequireDefault(_lodash);

var _container = require('../container');

var _container2 = _interopRequireDefault(_container);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; } /**
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


var CloudCodeContainer = function (_Container) {
  _inherits(CloudCodeContainer, _Container);

  function CloudCodeContainer() {
    var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {},
        sendPluginRequest = _ref.sendPluginRequest,
        asUserId = _ref.asUserId;

    _classCallCheck(this, CloudCodeContainer);

    var _this = _possibleConstructorReturn(this, (CloudCodeContainer.__proto__ || Object.getPrototypeOf(CloudCodeContainer)).call(this));

    _this.asUserId = asUserId;
    _this.sendPluginRequest = !!sendPluginRequest;
    return _this;
  }

  _createClass(CloudCodeContainer, [{
    key: 'sendRequestObject',
    value: function sendRequestObject(action, data) {
      if (this.apiKey === null) {
        throw Error('Please config ApiKey');
      }

      var extraData = {
        action: action,
        api_key: this.apiKey
      };

      var route = action.replace(':', '/');
      var request = this.request.post(this.url + route).set('X-Skygear-API-Key', this.apiKey).set('Accept', 'application/json');

      if (this.accessToken) {
        extraData.access_token = this.accessToken;
        request.set('X-Skygear-Access-Token', this.accessToken);
      }

      if (this.asUserId) {
        extraData._user_id = this.asUserId;
      }

      if (this.sendPluginRequest) {
        extraData._from_plugin = true;
      }

      return request.send(_lodash2.default.assign(extraData, data));
    }
  }, {
    key: '_getUser',
    value: function _getUser() {
      return this._user;
    }
  }, {
    key: '_setUser',
    value: function _setUser(attrs) {
      if (attrs !== null) {
        this._user = new this.User(attrs);
      } else {
        this._user = null;
      }
      this.ee.emit(_container.USER_CHANGED, this._user);
      return Promise.resolve(this._user);
    }
  }, {
    key: '_getAccessToken',
    value: function _getAccessToken() {
      return Promise.resolve(this._accessToken);
    }
  }, {
    key: '_setAccessToken',
    value: function _setAccessToken(value) {
      this._accessToken = value;
      return Promise.resolve(value);
    }
  }, {
    key: '_getDeviceID',
    value: function _getDeviceID() {
      return Promise.resolve(this._deviceID);
    }
  }, {
    key: '_setDeviceID',
    value: function _setDeviceID(value) {
      this._deviceID = value;
      return Promise.resolve(value);
    }
  }]);

  return CloudCodeContainer;
}(_container2.default);

exports.default = CloudCodeContainer;
module.exports = exports['default'];