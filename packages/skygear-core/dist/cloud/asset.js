'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.S3Signer = exports.CloudSigner = exports.FSSigner = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

exports.staticAssetHandler = staticAssetHandler;
exports.getSigner = getSigner;

var _crypto = require('crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _fs = require('fs');

var _fs2 = _interopRequireDefault(_fs);

var _path = require('path');

var _path2 = _interopRequireDefault(_path);

var _mimeTypes = require('mime-types');

var _mimeTypes2 = _interopRequireDefault(_mimeTypes);

var _common = require('./transport/common');

var _registry = require('./registry');

var _registry2 = _interopRequireDefault(_registry);

var _settings2 = require('./settings');

var _urlsafeBase = require('urlsafe-base64');

var _urlsafeBase2 = _interopRequireDefault(_urlsafeBase);

var _amazonS3UrlSigner = require('amazon-s3-url-signer');

var _amazonS3UrlSigner2 = _interopRequireDefault(_amazonS3UrlSigner);

var _superagent = require('superagent');

var _superagent2 = _interopRequireDefault(_superagent);

var _url = require('url');

var _url2 = _interopRequireDefault(_url);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/**
 * staticAssetHandler — default handler for serving static assets with during
 * development.
 */

function staticAssetHandler(req) {
  if (req.path.indexOf('/static') !== 0) {
    throw new Error('The base path is not static asset');
  }
  var matchedPrefix = null;
  Object.keys(_registry2.default.staticAsset).forEach(function (prefix) {
    if (req.path.indexOf('/static' + prefix) === 0) {
      matchedPrefix = prefix;
    }
  });
  if (!matchedPrefix) {
    return new _common.SkygearResponse({
      statusCode: 404
    });
  }
  var matchedFunc = _registry2.default.staticAsset[matchedPrefix];
  var absPrefix = matchedFunc();
  var finalPath = req.path.replace('/static' + matchedPrefix, absPrefix);
  if (!_fs2.default.existsSync(finalPath)) {
    return new _common.SkygearResponse({
      statusCode: 404
    });
  }
  var data = _fs2.default.readFileSync(finalPath, {
    flag: 'r'
  });
  var contentType = _mimeTypes2.default.contentType(_path2.default.extname(finalPath));
  return new _common.SkygearResponse({
    headers: {
      'Content-Type': [contentType]
    },
    body: data
  });
}

var Signer = function () {
  function Signer() {
    _classCallCheck(this, Signer);
  }

  _createClass(Signer, [{
    key: 'sign',

    /**
     * @name Signer#sign
     * @return {Promise<string>} A Promise of the url
     */
    value: function sign() {
      throw new Error('Not implemented, subclass should override this method');
    }
  }]);

  return Signer;
}();

/* eslint-disable camelcase */


var FSSigner = exports.FSSigner = function (_Signer) {
  _inherits(FSSigner, _Signer);

  function FSSigner(_settings) {
    _classCallCheck(this, FSSigner);

    var _this = _possibleConstructorReturn(this, (FSSigner.__proto__ || Object.getPrototypeOf(FSSigner)).call(this));

    _this.assetStoreURLPrefix = _settings.assetStoreURLPrefix;
    _this.assetStoreURLExpireDuration = _settings.assetStoreURLExpireDuration;
    _this.assetStoreSecret = _settings.assetStoreSecret;
    return _this;
  }

  _createClass(FSSigner, [{
    key: 'sign',
    value: function sign(name) {
      var prefix = this.assetStoreURLPrefix;
      var duration = this.assetStoreURLExpireDuration;
      var expire = Math.floor(Date.now() / 1000) + duration;
      var secret = this.assetStoreSecret;
      var hash = _crypto2.default.createHmac('sha256', secret).update(name).update(expire.toString()).digest().slice(0, -1);
      var encoded = _urlsafeBase2.default.encode(hash);
      var fullURL = prefix + '/' + name + '?expiredAt=' + expire.toString() + '&signature=' + encoded;
      return Promise.resolve(fullURL);
    }
  }]);

  return FSSigner;
}(Signer);

var CloudSigner = exports.CloudSigner = function (_Signer2) {
  _inherits(CloudSigner, _Signer2);

  function CloudSigner(_settings) {
    _classCallCheck(this, CloudSigner);

    var _this2 = _possibleConstructorReturn(this, (CloudSigner.__proto__ || Object.getPrototypeOf(CloudSigner)).call(this));

    _this2.request = _superagent2.default;
    _this2.appName = _settings.appName;
    _this2.assetStoreURLExpireDuration = _settings.assetStoreURLExpireDuration;
    _this2.cloudAssetToken = _settings.cloudAssetToken;
    _this2.cloudAssetHost = _settings.cloudAssetHost;
    var isPublic = !!_settings.cloudAssetStorePublic;
    _this2.prefix = isPublic ? _settings.cloudAssetPublicPrefix : _settings.cloudAssetPrivatePrefix;
    _this2.signerSecret = null;
    _this2.expiredAt = null;
    _this2.extra = null;
    return _this2;
  }

  _createClass(CloudSigner, [{
    key: 'refreshSignerToken',
    value: function refreshSignerToken() {
      var _this3 = this;

      var appName = this.appName;
      var duration = parseInt(this.assetStoreURLExpireDuration);
      var expire = Math.floor(Date.now() / 1000) + duration;
      var token = this.cloudAssetToken;
      var host = this.cloudAssetHost;
      var url = host + '/token/' + appName;

      return this.request.get(url).accept('application/json').set('Authorization', 'Bearer ' + token).query({ expired_at: expire.toString() }).then(function (response) {
        var body = response.body;
        _this3.signerSecret = body.value;
        _this3.expiredAt = new Date(body.expired_at);
        _this3.extra = body.extra;
      });
    }
  }, {
    key: 'needRefreshSignerToken',
    value: function needRefreshSignerToken() {
      if (this.signerSecret === null) {
        return true;
      }
      if (this.expiredAt < new Date()) {
        return true;
      }
      return false;
    }
  }, {
    key: 'sign',
    value: function sign(name) {
      var _this4 = this;

      if (this.needRefreshSignerToken()) {
        return this.refreshSignerToken().then(function () {
          return _this4.sign(name);
        });
      }
      var appName = this.appName;
      var duration = parseInt(this.assetStoreURLExpireDuration);
      var expired = Math.floor(Date.now() / 1000) + duration;

      var hash = _crypto2.default.createHmac('sha256', this.signerSecret).update(appName).update(name).update(expired.toString()).update(this.extra).digest('base64');
      var signatureAndExtra = encodeURIComponent(hash + '.' + this.extra);

      return Promise.resolve(this.prefix + '/' + appName + '/' + name + ('?expired_at=' + expired + '&signature=' + signatureAndExtra));
    }
  }]);

  return CloudSigner;
}(Signer);

var S3Signer = exports.S3Signer = function (_Signer3) {
  _inherits(S3Signer, _Signer3);

  function S3Signer(_settings) {
    _classCallCheck(this, S3Signer);

    var _this5 = _possibleConstructorReturn(this, (S3Signer.__proto__ || Object.getPrototypeOf(S3Signer)).call(this));

    _this5.assetStoreS3AccessKey = _settings.assetStoreS3AccessKey;
    _this5.assetStoreS3SecretKey = _settings.assetStoreS3SecretKey;
    _this5.assetStoreS3URLPrefix = _settings.assetStoreS3URLPrefix;
    _this5.assetStoreS3Region = _settings.assetStoreS3Region;
    _this5.assetStoreS3Bucket = _settings.assetStoreS3Bucket;
    _this5.assetStoreURLExpireDuration = _settings.assetStoreURLExpireDuration;

    var key = _this5.assetStoreS3AccessKey;
    var secret = _this5.assetStoreS3SecretKey;
    var region = _this5.assetStoreS3Region;
    var host = 's3-' + region + '.amazonaws.com';
    var bucket = _this5.assetStoreS3Bucket;

    _this5.signer = _amazonS3UrlSigner2.default.urlSigner(key, secret, {
      host: host
    });
    _this5.bucket = bucket;
    return _this5;
  }

  _createClass(S3Signer, [{
    key: 'sign',
    value: function sign(name) {
      // assume name is not percent encoded
      // because it should be _asset.id in database
      var encodedName = encodeURIComponent(name);
      var duration = this.assetStoreURLExpireDuration;
      var url = this.signer.getUrl('GET', encodedName, this.bucket, duration);
      var prefix = this.assetStoreS3URLPrefix;
      if (!prefix) {
        return Promise.resolve(url);
      } else if (prefix.length > 1 && prefix.slice(-1) !== '/') {
        // URL.resolve behave differently if trailing slash is not present
        // always append trailing slash such that it works in both cases.
        prefix += '/';
      }

      var plainS3URLObject = _url2.default.parse(url);
      var urlWithoutQuery = _url2.default.resolve(prefix, encodedName);
      var urlObject = _url2.default.parse(urlWithoutQuery);
      urlObject.search = plainS3URLObject.search;
      url = _url2.default.format(urlObject);
      return Promise.resolve(url);
    }
  }]);

  return S3Signer;
}(Signer);

var sharedSigner = null;
/**
 * Return a shared signer for the current configuration.
 *
 * @return {Signer}
 */
function getSigner() {
  if (sharedSigner === null) {
    switch (_settings2.settings.assetStore) {
      case 'fs':
        sharedSigner = new FSSigner(_settings2.settings);
        break;
      case 's3':
        sharedSigner = new S3Signer(_settings2.settings);
        break;
      case 'cloud':
        sharedSigner = new CloudSigner(_settings2.settings);
        break;
      default:
        throw new Error('Unknown asset store type: ' + _settings2.settings.assetStore);
    }
  }
  return sharedSigner;
}