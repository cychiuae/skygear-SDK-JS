'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.setStore = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _cookieStorage = require('cookie-storage');

var _util = require('./util');

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
var cookieKeyWhiteList = ['skygear-deviceid', 'skygear-user', 'skygear-accesstoken'];
var store;

var PURGEABLE_KEYS_KEY = '_skygear_purgeable_keys_';

var SyncStorageDriver = function () {
  function SyncStorageDriver(syncImpl) {
    _classCallCheck(this, SyncStorageDriver);

    this._syncImpl = syncImpl;
  }

  _createClass(SyncStorageDriver, [{
    key: 'clear',
    value: function clear(callback) {
      this._syncImpl.clear();
      if (callback) {
        callback(null);
      }
      return Promise.resolve();
    }
  }, {
    key: 'getItem',
    value: function getItem(key, callback) {
      var value = this._syncImpl.getItem(key);
      if (callback) {
        callback(null, value);
      }
      return Promise.resolve(value);
    }
  }, {
    key: 'setItem',
    value: function setItem(key, value, callback) {
      try {
        this._syncImpl.setItem(key, value);
        if (callback) {
          callback(null);
        }
        return Promise.resolve();
      } catch (e) {
        if (callback) {
          callback(e);
        }
        return Promise.reject(e);
      }
    }
  }, {
    key: 'removeItem',
    value: function removeItem(key, callback) {
      this._syncImpl.removeItem(key);
      if (callback) {
        callback(null);
      }
      return Promise.resolve();
    }
  }, {
    key: 'multiGet',
    value: function multiGet(keys, callback) {
      var output = [];
      for (var i = 0; i < keys.length; ++i) {
        var key = keys[i];
        var value = this._syncImpl.getItem(key);
        output.push({
          key: key,
          value: value
        });
      }
      if (callback) {
        callback(null, output);
      }
      return Promise.resolve(output);
    }
  }, {
    key: 'multiSet',
    value: function multiSet(keyValuePairs, callback) {
      try {
        for (var i = 0; i < keyValuePairs.length; ++i) {
          var pair = keyValuePairs[i];
          var key = pair.key;
          var value = pair.value;
          this._syncImpl.setItem(key, value);
        }
        if (callback) {
          callback(null);
        }
        return Promise.resolve();
      } catch (e) {
        if (callback) {
          return Promise.callback(e);
        }
        return Promise.reject(e);
      }
    }
  }, {
    key: 'multiRemove',
    value: function multiRemove(keys, callback) {
      for (var i = 0; i < keys.length; ++i) {
        var key = keys[i];
        this._syncImpl.removeItem(key);
      }
      if (callback) {
        callback(null);
      }
      return Promise.resolve();
    }
  }, {
    key: 'key',
    value: function key(n, callback) {
      var result = this._syncImpl.key(n);
      if (callback) {
        callback(null, result);
      }
      return Promise.resolve(result);
    }
  }, {
    key: 'keys',
    value: function keys(callback) {
      var length = this._syncImpl.length;
      var output = [];
      for (var i = 0; i < length; ++i) {
        output.push(this._syncImpl.key(i));
      }
      if (callback) {
        callback(null, output);
      }
      return Promise.resolve(output);
    }
  }, {
    key: 'length',
    value: function length(callback) {
      var length = this._syncImpl.length;
      if (callback) {
        callback(null, length);
      }
      return Promise.resolve(length);
    }
  }]);

  return SyncStorageDriver;
}();

var Store = function () {
  function Store(driver, keyWhiteList) {
    _classCallCheck(this, Store);

    this._driver = driver;
    this.keyWhiteList = keyWhiteList;
    this._purgeableKeys = [];

    this._driver.getItem(PURGEABLE_KEYS_KEY).then(function (value) {
      if (value) {
        try {
          var originalKeys = JSON.parse(value);
          var recentKeys = this._purgeableKeys;

          this._purgeableKeys = this._maintainLRUOrder(originalKeys, recentKeys);
        } catch (e) {
          // ignore
        }
      }
    }.bind(this));
  }

  /*
   * @param originalKeys
   * @param recentKeys
   * @return newKeys with recentKeys come first, followed by deduped
   *         originalKeys
   */


  _createClass(Store, [{
    key: '_maintainLRUOrder',
    value: function _maintainLRUOrder(originalKeys, recentKeys) {
      var mapping = {};
      for (var i = 0; i < recentKeys.length; ++i) {
        mapping[recentKeys[i]] = true;
      }

      var output = recentKeys.slice();
      for (var _i = 0; _i < originalKeys.length; ++_i) {
        if (mapping[originalKeys[_i]]) {
          continue;
        }
        output.push(originalKeys[_i]);
      }
      return output;
    }

    /*
     * @param originalKeys
     * @param keysToRemove
     * @return newKeys without value contained in keysToRemove
     */

  }, {
    key: '_removeKeysInLRUOrder',
    value: function _removeKeysInLRUOrder(originalKeys, keysToRemove) {
      var mapping = {};
      for (var i = 0; i < keysToRemove.length; ++i) {
        mapping[keysToRemove[i]] = true;
      }

      var output = [];
      for (var _i2 = 0; _i2 < originalKeys.length; ++_i2) {
        if (mapping[originalKeys[_i2]]) {
          continue;
        }
        output.push(originalKeys[_i2]);
      }
      return output;
    }
  }, {
    key: 'clear',
    value: function clear(callback) {
      return this._driver.clear(callback);
    }
  }, {
    key: 'getItem',
    value: function getItem(key, callback) {
      return this._driver.getItem(key, callback);
    }
  }, {
    key: 'setItem',
    value: function setItem(key, value, callback) {
      var _this = this;

      if (this.keyWhiteList && this.keyWhiteList.indexOf(key) < 0) {
        return Promise.reject(new Error('Saving key is not permitted'));
      }
      return this._driver.setItem(key, value).then(function () {
        if (callback) {
          callback(null);
        }
        return Promise.resolve();
      }, function (error) {
        return _this._purge().then(function () {
          return Promise.reject(error);
        });
      }).catch(function (error) {
        if (callback) {
          callback(error);
        }
        return Promise.reject(error);
      });
    }
  }, {
    key: 'setPurgeableItem',
    value: function setPurgeableItem(key, value, callback) {
      var _this2 = this;

      if (this.keyWhiteList && this.keyWhiteList.indexOf(key) < 0) {
        return Promise.reject(new Error('Saving key is not permitted'));
      }
      this._purgeableKeys = this._maintainLRUOrder(this._purgeableKeys, [key]);

      var keyValuePairs = [{
        key: key,
        value: value
      }, {
        key: PURGEABLE_KEYS_KEY,
        value: JSON.stringify(this._purgeableKeys)
      }];
      return this.multiSetTransactionally(keyValuePairs).then(function () {
        if (callback) {
          callback(null);
        }
        return Promise.resolve();
      }, function (error) {
        return _this2._purge().then(function () {
          return Promise.reject(error);
        });
      }).catch(function (error) {
        if (callback) {
          callback(error);
        }
        return Promise.reject(error);
      });
    }
  }, {
    key: '_selectKeysToPurge',
    value: function _selectKeysToPurge(keys) {
      var index = Math.floor(keys.length / 2);
      var keysToPurge = keys.slice(index);
      return keysToPurge;
    }
  }, {
    key: '_purge',
    value: function _purge() {
      var keysToPurge = this._selectKeysToPurge(this._purgeableKeys);
      if (keysToPurge.length <= 0) {
        return Promise.reject(new Error('no more keys to purge'));
      }

      this._purgeableKeys = this._removeKeysInLRUOrder(this._purgeableKeys, keysToPurge);
      return this._driver.multiRemove(keysToPurge).then(function () {
        return this._driver.setItem(PURGEABLE_KEYS_KEY, JSON.stringify(this._purgeableKeys));
      }.bind(this));
    }
  }, {
    key: 'multiSetTransactionally',
    value: function multiSetTransactionally(keyValuePairs, callback) {
      var _this3 = this;

      var keys = [];
      for (var i = 0; i < keyValuePairs.length; ++i) {
        var pair = keyValuePairs[i];
        var key = pair.key;
        if (this.keyWhiteList && this.keyWhiteList.indexOf(key) < 0) {
          return Promise.reject(new Error('Saving key is not permitted'));
        }
        keys.push(key);
      }

      return this._driver.multiGet(keys).then(function (original) {
        return _this3._driver.multiSet(keyValuePairs).then(function () {
          if (callback) {
            callback(null);
          }
          return Promise.resolve();
        }, function (e) {
          return _this3._driver.multiRemove(keys).then(function () {
            return _this3._driver.multiSet(original).then(function () {
              if (callback) {
                callback(e);
              }
              return Promise.reject(e);
            });
          });
        });
      });
    }
  }, {
    key: 'clearPurgeableItems',
    value: function clearPurgeableItems(callback) {
      var keys = this._purgeableKeys.slice();
      this._purgeableKeys = [];
      return this._driver.multiRemove(keys, callback);
    }
  }, {
    key: 'removeItem',
    value: function removeItem(key, callback) {
      return this._driver.removeItem(key, callback);
    }
  }, {
    key: 'key',
    value: function key(n, callback) {
      return this._driver.key(n, callback);
    }
  }, {
    key: 'keys',
    value: function keys(callback) {
      return this._driver.keys(callback);
    }
  }, {
    key: 'length',
    value: function length(callback) {
      return this._driver.length(callback);
    }
  }]);

  return Store;
}();

var setStore = exports.setStore = function setStore(_store) {
  store = _store;
};

exports.default = function () {
  if (store) {
    return store;
  }
  /* global window: false */
  if (typeof window !== 'undefined') {
    // env: browser-like
    if ((0, _util.isLocalStorageValid)()) {
      // env: Modern browsers
      store = new Store(new SyncStorageDriver(window.localStorage));
    } else {
      // env: Legacy browsers
      var cookieImpl = new _cookieStorage.CookieStorage();
      store = new Store(new SyncStorageDriver(cookieImpl, cookieKeyWhiteList));
    }
  } else {
    // env: node
    var memoryImpl = require('localstorage-memory');
    store = new Store(new SyncStorageDriver(memoryImpl));
  }
  return store;
};