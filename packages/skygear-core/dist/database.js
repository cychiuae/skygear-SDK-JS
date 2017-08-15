'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _cache = require('./cache');

var _cache2 = _interopRequireDefault(_cache);

var _asset = require('./asset');

var _asset2 = _interopRequireDefault(_asset);

var _record = require('./record');

var _record2 = _interopRequireDefault(_record);

var _query2 = require('./query');

var _query3 = _interopRequireDefault(_query2);

var _query_result = require('./query_result');

var _query_result2 = _interopRequireDefault(_query_result);

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
var _ = require('lodash');

var Database = function () {
  function Database(dbID, container) {
    _classCallCheck(this, Database);

    if (dbID !== '_public' && dbID !== '_private' && dbID !== '_union') {
      throw new Error('Invalid database_id');
    }
    this.dbID = dbID;
    this.container = container;
    this._cacheStore = new _cache2.default(this.dbID);
    this._cacheResponse = true;
  }

  _createClass(Database, [{
    key: 'getRecordByID',
    value: function getRecordByID(id) {
      var _Record$parseID = _record2.default.parseID(id),
          _Record$parseID2 = _slicedToArray(_Record$parseID, 2),
          recordType = _Record$parseID2[0],
          recordId = _Record$parseID2[1];

      var query = new _query3.default(_record2.default.extend(recordType)).equalTo('_id', recordId);
      return this.query(query).then(function (users) {
        if (users.length === 1) {
          return users[0];
        } else {
          throw new Error(id + ' does not exist');
        }
      });
    }
  }, {
    key: 'query',
    value: function query(_query) {
      var _this = this;

      var cacheCallback = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;

      var remoteReturned = false;
      var cacheStore = this.cacheStore;
      var Cls = _query.recordCls;
      var queryJSON = _query.toJSON();

      if (!queryJSON.offset && queryJSON.page > 0) {
        queryJSON.offset = queryJSON.limit * (queryJSON.page - 1);
      }

      var payload = _.assign({
        database_id: this.dbID //eslint-disable-line
      }, queryJSON);

      if (cacheCallback) {
        cacheStore.get(_query.hash).then(function (body) {
          if (remoteReturned) {
            return;
          }
          var records = _.map(body.result, function (attrs) {
            return new Cls(attrs);
          });
          var result = _query_result2.default.createFromResult(records, body.info);
          cacheCallback(result, true);
        }, function (err) {
          console.log('No cache found', err);
        });
      }
      return this.container.makeRequest('record:query', payload).then(function (body) {
        var records = _.map(body.result, function (attrs) {
          return new Cls(attrs);
        });
        var result = _query_result2.default.createFromResult(records, body.info);
        remoteReturned = true;
        if (_this.cacheResponse) {
          cacheStore.set(_query.hash, body);
        }
        return result;
      });
    }
  }, {
    key: '_presaveAssetTask',
    value: function _presaveAssetTask(key, asset) {
      if (asset.file) {
        return this.container.makeUploadAssetRequest(asset).then(function (a) {
          return [key, a];
        });
      } else {
        return Promise.resolve([key, asset]);
      }
    }
  }, {
    key: '_presave',
    value: function _presave(record) {
      // for every (key, value) pair, process the pair in a Promise
      // the Promise should be resolved by the transformed [key, value] pair
      var tasks = _.map(record, function (value, key) {
        if (value instanceof _asset2.default) {
          return this._presaveAssetTask(key, value);
        } else {
          return Promise.resolve([key, value]);
        }
      });

      return Promise.all(tasks).then(function (keyvalues) {
        _.each(keyvalues, function (_ref) {
          var _ref2 = _slicedToArray(_ref, 2),
              key = _ref2[0],
              value = _ref2[1];

          record[key] = value;
        });
        return record;
      });
    }
  }, {
    key: 'del',
    value: function del(record) {
      return this.delete(record);
    }
  }, {
    key: 'save',
    value: function save(_records) {
      var _this2 = this;

      var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

      var records = _records;
      if (!_.isArray(records)) {
        records = [records];
      }

      if (_.some(records, function (r) {
        return r === undefined || r === null;
      })) {
        return Promise.reject('Invalid input, unable to save undefined and null');
      }

      var presaveTasks = _.map(records, this._presave.bind(this));
      return Promise.all(presaveTasks).then(function (processedRecords) {
        var payload = {
          database_id: _this2.dbID //eslint-disable-line
        };

        if (options.atomic) {
          payload.atomic = true;
        }

        payload.records = _.map(processedRecords, function (perRecord) {
          return perRecord.toJSON();
        });

        return _this2.container.makeRequest('record:save', payload);
      }).then(function (body) {
        var results = body.result;
        var savedRecords = [];
        var errors = [];

        _.forEach(results, function (perResult, idx) {
          if (perResult._type === 'error') {
            savedRecords[idx] = undefined;
            errors[idx] = perResult;
          } else {
            records[idx].update(perResult);
            records[idx].updateTransient(perResult._transient, true);

            savedRecords[idx] = records[idx];
            errors[idx] = undefined;
          }
        });

        if (records.length === 1) {
          if (errors[0]) {
            return Promise.reject(errors[0]);
          }
          return savedRecords[0];
        }
        return { savedRecords: savedRecords, errors: errors };
      });
    }
  }, {
    key: 'delete',
    value: function _delete(_records) {
      var records = _records;
      if (!_.isArray(records)) {
        records = [records];
      }

      var ids = _.map(records, function (perRecord) {
        return perRecord.id;
      });
      var payload = {
        database_id: this.dbID, //eslint-disable-line
        ids: ids
      };

      return this.container.makeRequest('record:delete', payload).then(function (body) {
        var results = body.result;
        var errors = [];

        _.forEach(results, function (perResult, idx) {
          if (perResult._type === 'error') {
            errors[idx] = perResult;
          } else {
            errors[idx] = undefined;
          }
        });

        if (records.length === 1) {
          if (errors[0]) {
            return Promise.reject(errors[0]);
          }
          return;
        }
        return errors;
      });
    }
  }, {
    key: 'cacheStore',
    get: function get() {
      return this._cacheStore;
    }
  }, {
    key: 'cacheResponse',
    get: function get() {
      return this._cacheResponse;
    },
    set: function set(value) {
      var b = !!value;
      this._cacheResponse = b;
    }
  }]);

  return Database;
}();

exports.default = Database;
module.exports = exports['default'];