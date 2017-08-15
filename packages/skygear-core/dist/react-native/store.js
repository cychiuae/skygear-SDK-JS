'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _reactNative = require('react-native');

var _reactNative2 = _interopRequireDefault(_reactNative);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var ReactNativeAsyncStorageDriver = function () {
  function ReactNativeAsyncStorageDriver(rnImpl) {
    _classCallCheck(this, ReactNativeAsyncStorageDriver);

    this._rnImpl = rnImpl;
  }

  _createClass(ReactNativeAsyncStorageDriver, [{
    key: 'clear',
    value: function clear(callback) {
      return this._rnImpl.clear(callback);
    }
  }, {
    key: 'getItem',
    value: function getItem(key, callback) {
      return this._rnImpl.getItem(key, callback);
    }
  }, {
    key: 'setItem',
    value: function setItem(key, value, callback) {
      return this._rnImpl.setItem(key, value, callback);
    }
  }, {
    key: 'removeItem',
    value: function removeItem(key, callback) {
      return this._rnImpl.removeItem(key, callback);
    }
  }, {
    key: 'multiGet',
    value: function multiGet(keys, callback) {
      return this._rnImpl.multiGet(keys).then(function (rnKeyValuePairs) {
        var output = [];
        for (var i = 0; i < rnKeyValuePairs.length; ++i) {
          var rnPair = rnKeyValuePairs[i];
          var key = rnPair[0];
          var value = rnPair[1];
          output.push({
            key: key,
            value: value
          });
        }
        if (callback) {
          callback(null, output);
        }
        return output;
      }, function (errors) {
        if (callback) {
          callback(errors);
        }
        return Promise.reject(errors);
      });
    }
  }, {
    key: 'multiSet',
    value: function multiSet(keyValuePairs, callback) {
      var rnKeyValuePairs = [];
      for (var i = 0; i < keyValuePairs.length; ++i) {
        var pair = keyValuePairs[i];
        var key = pair.key;
        var value = pair.value;
        rnKeyValuePairs.push([key, value]);
      }
      return this._rnImpl.multiSet(rnKeyValuePairs, callback);
    }
  }, {
    key: 'multiRemove',
    value: function multiRemove(keys, callback) {
      return this._rnImpl.multiRemove(keys, callback);
    }
  }, {
    key: 'key',
    value: function key(n, callback) {
      return this._rnImpl.getAllKeys().then(function (allKeys) {
        var result = null;
        if (n >= 0 && n < allKeys.length) {
          result = allKeys[n];
        }
        if (callback) {
          callback(null, result);
        }
        return result;
      });
    }
  }, {
    key: 'keys',
    value: function keys(callback) {
      return this._rnImpl.getAllKeys(callback);
    }
  }, {
    key: 'length',
    value: function length(callback) {
      return this._rnImpl.getAllKeys().then(function (allKeys) {
        if (callback) {
          callback(null, allKeys.length);
        }
        return allKeys.length;
      });
    }
  }]);

  return ReactNativeAsyncStorageDriver;
}();

exports.default = new ReactNativeAsyncStorageDriver(_reactNative2.default.AsyncStorage);
module.exports = exports['default'];