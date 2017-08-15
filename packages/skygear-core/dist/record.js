'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }(); /**
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


var _uuid = require('uuid');

var _uuid2 = _interopRequireDefault(_uuid);

var _lodash = require('lodash');

var _lodash2 = _interopRequireDefault(_lodash);

var _util = require('./util');

var _acl = require('./acl');

var _acl2 = _interopRequireDefault(_acl);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var defaultAttrs = {
  _id: null,
  _type: null
};

var _metaAttrs = {
  _created_at: { //eslint-disable-line
    parser: function parser(v) {
      return new Date(v);
    },
    newKey: 'createdAt'
  },
  _updated_at: { //eslint-disable-line
    parser: function parser(v) {
      return new Date(v);
    },
    newKey: 'updatedAt'
  },
  _ownerID: {
    parser: function parser(v) {
      return v;
    },
    newKey: 'ownerID'
  },
  _created_by: { //eslint-disable-line
    parser: function parser(v) {
      return v;
    },
    newKey: 'createdBy'
  },
  _updated_by: { //eslint-disable-line
    parser: function parser(v) {
      return v;
    },
    newKey: 'updatedBy'
  },
  _access: {
    parser: function parser(v) {
      var acl = v;
      if (v && v.toJSON) {
        acl = v.toJSON();
      }
      return _acl2.default.fromJSON(acl);
    },
    newKey: '_access'
  }
};

var _metaKey = _lodash2.default.map(_metaAttrs, function (obj) {
  return obj.newKey;
});

var Record = function () {
  function Record(recordType) {
    var attrs = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : defaultAttrs;

    _classCallCheck(this, Record);

    if (!Record.validType(recordType)) {
      throw new Error('RecordType is not valid. Please start with alphanumeric string.');
    }
    this._recordType = recordType;
    // Favouring `id`, since `id` will always contains type information if
    // exist.
    var id = attrs.id || attrs._id;
    if (id === null || id === undefined) {
      id = _uuid2.default.v4();
    } else {
      var _Record$parseID = Record.parseID(id),
          _Record$parseID2 = _slicedToArray(_Record$parseID, 2),
          type = _Record$parseID2[0],
          name = _Record$parseID2[1];

      if (type !== this._recordType) {
        throw new Error('_id is not valid. RecordType mismatch.');
      }
      id = name;
    }
    delete attrs.id; // because `id` is a readonly property
    this._id = id;
    this._access = null;
    this.update(attrs);
    this.updateTransient(attrs._transient);
  }

  _createClass(Record, [{
    key: 'setAccess',
    value: function setAccess(acl) {
      this._access = acl;
    }
  }, {
    key: 'update',
    value: function update(attrs) {
      var _this = this;

      _lodash2.default.each(this.attributeKeys, function (key) {
        delete _this[key];
      });

      _lodash2.default.each(attrs, function (value, key) {
        if (key.indexOf('_') !== 0) {
          if (_lodash2.default.isObject(value)) {
            _this[key] = (0, _util.fromJSON)(value);
          } else {
            _this[key] = value;
          }
        } else if (key in _metaAttrs) {
          var meta = _metaAttrs[key];
          _this[meta.newKey] = meta.parser(value);
        }
      });
    }
  }, {
    key: 'setPublicNoAccess',
    value: function setPublicNoAccess() {
      this.access.setPublicNoAccess();
    }
  }, {
    key: 'setPublicReadOnly',
    value: function setPublicReadOnly() {
      this.access.setPublicReadOnly();
    }
  }, {
    key: 'setPublicReadWriteAccess',
    value: function setPublicReadWriteAccess() {
      this.access.setPublicReadWriteAccess();
    }
  }, {
    key: 'setNoAccessForRole',
    value: function setNoAccessForRole(role) {
      this.access.setNoAccessForRole(role);
    }
  }, {
    key: 'setReadOnlyForRole',
    value: function setReadOnlyForRole(role) {
      this.access.setReadOnlyForRole(role);
    }
  }, {
    key: 'setReadWriteAccessForRole',
    value: function setReadWriteAccessForRole(role) {
      this.access.setReadWriteAccessForRole(role);
    }
  }, {
    key: 'setNoAccessForUser',
    value: function setNoAccessForUser(user) {
      this.access.setNoAccessForUser(user);
    }
  }, {
    key: 'setReadOnlyForUser',
    value: function setReadOnlyForUser(user) {
      this.access.setReadOnlyForUser(user);
    }
  }, {
    key: 'setReadWriteAccessForUser',
    value: function setReadWriteAccessForUser(User) {
      this.access.setReadWriteAccessForUser(User);
    }
  }, {
    key: 'hasPublicReadAccess',
    value: function hasPublicReadAccess() {
      this.access.hasPublicReadAccess();
    }
  }, {
    key: 'hasPublicWriteAccess',
    value: function hasPublicWriteAccess() {
      this.access.hasPublicWriteAccess();
    }
  }, {
    key: 'hasReadAccess',
    value: function hasReadAccess(role) {
      this.access.hasReadAccess(role);
    }
  }, {
    key: 'hasWriteAccess',
    value: function hasWriteAccess(role) {
      this.access.hasWriteAccess(role);
    }
  }, {
    key: 'hasReadAccessForRole',
    value: function hasReadAccessForRole(role) {
      this.access.hasReadAccessForRole(role);
    }
  }, {
    key: 'hasWriteAccessForRole',
    value: function hasWriteAccessForRole(role) {
      this.access.hasWriteAccessForRole(role);
    }
  }, {
    key: 'hasReadAccessForUser',
    value: function hasReadAccessForUser(user) {
      this.access.hasReadAccessForUser(user);
    }
  }, {
    key: 'hasWriteAccessForUser',
    value: function hasWriteAccessForUser(user) {
      this.access.hasWriteAccessForUser(user);
    }
  }, {
    key: 'updateTransient',
    value: function updateTransient(transient_) {
      var merge = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;

      var newTransient = merge ? _lodash2.default.clone(this._transient) : {};
      _lodash2.default.each(transient_, function (value, key) {
        // If value is an object and `_id` field exists, assume
        // that it is a record.
        if (_lodash2.default.isObject(value) && '_id' in value) {
          newTransient[key] = recordDictToObj(value);
        } else if (_lodash2.default.isObject(value)) {
          newTransient[key] = (0, _util.fromJSON)(value);
        } else {
          newTransient[key] = value;
        }
      });
      this._transient = newTransient;
    }
  }, {
    key: 'toJSON',
    value: function toJSON() {
      var _this2 = this;

      var payload = {
        _id: this.id,
        _access: this.access && this.access.toJSON()
      };
      _lodash2.default.each(this.attributeKeys, function (key) {
        payload[key] = (0, _util.toJSON)(_this2[key]);
      });

      return payload;
    }
  }, {
    key: 'recordType',
    get: function get() {
      return this._recordType;
    }
  }, {
    key: 'id',
    get: function get() {
      return this._recordType + '/' + this._id;
    }
  }, {
    key: 'access',
    get: function get() {
      return this._access;
    }
  }, {
    key: 'attributeKeys',
    get: function get() {
      var keys = Object.keys(this);
      return _lodash2.default.filter(keys, function (value) {
        return value.indexOf('_') !== 0 && !_lodash2.default.includes(_metaKey, value);
      });
    }
  }, {
    key: '$transient',
    get: function get() {
      return this._transient;
    }
  }], [{
    key: 'validType',
    value: function validType(recordType) {
      return recordType && recordType.indexOf('_') !== 0;
    }
  }, {
    key: 'parseID',
    value: function parseID(id) {
      var tuple = id.split('/');
      if (tuple.length < 2) {
        throw new Error('_id is not valid. _id has to be in the format `type/id`');
      }
      return [tuple[0], tuple.slice(1).join('/')];
    }
  }, {
    key: 'extend',
    value: function extend(recordType, instFunc) {
      if (!Record.validType(recordType)) {
        throw new Error('RecordType is not valid. Please start with alphanumeric string.');
      }
      var RecordProto = {};
      function RecordCls() {
        var attrs = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : defaultAttrs;

        Record.call(this, recordType, attrs);
      }
      _lodash2.default.assign(RecordProto, instFunc, {
        constructor: RecordCls
      });
      RecordCls.prototype = _lodash2.default.create(Record.prototype, RecordProto);
      RecordCls.recordType = recordType;
      return RecordCls;
    }
  }]);

  return Record;
}();

exports.default = Record;


function recordDictToObj(dict) {
  var Cls = Record.extend(dict._id.split('/')[0]);
  return new Cls(dict);
}
module.exports = exports['default'];