'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _reactNative = require('react-native');

var _reactNative2 = _interopRequireDefault(_reactNative);

var _container = require('../container');

var _container2 = _interopRequireDefault(_container);

var _store = require('../store');

var _store2 = require('./store');

var _store3 = _interopRequireDefault(_store2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var ReactNativeContainer = function (_Container) {
  _inherits(ReactNativeContainer, _Container);

  function ReactNativeContainer() {
    _classCallCheck(this, ReactNativeContainer);

    return _possibleConstructorReturn(this, (ReactNativeContainer.__proto__ || Object.getPrototypeOf(ReactNativeContainer)).apply(this, arguments));
  }

  _createClass(ReactNativeContainer, [{
    key: 'inferDeviceType',
    value: function inferDeviceType() {
      if (_reactNative2.default.Platform.OS === 'ios') {
        return 'ios';
      }
      return 'android';
    }
  }]);

  return ReactNativeContainer;
}(_container2.default);

(0, _store.setStore)(_store3.default);

exports.default = new ReactNativeContainer();
module.exports = exports['default'];