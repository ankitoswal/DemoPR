//'use strict';
// comment
// var cookieParser = require('cookie-parser');
// var csrf = require('csurf');
var helmet = require('helmet');
var cors = require('cors');
var xss = require("xss");
import bodyParser from 'body-parser';
import express from 'express';
import http from 'http';
import path from 'path';
import https from 'https';
import fs from 'fs';
import Promise from "bluebird";
import _ from 'underscore';
import __ from 'lodash';
import shell from 'shelljs';
import gammaConfig from './config';
import * as db from '../component/db';
import constants from 'constants';
//test comment
//import log from '../utils/logger';
//const log = require('./../license/v1/utils/logging');
import * as log from './../logs/logger';
import passport from 'passport';
var app = express();
var cf = require('../utils/common-functions');
var publicDir = "/public";
const XSS_EXCLUSIONS = ['password', 'userEmail', 'oldPassword', 'newPassword', 'email', 'ldapUsername', 'ldapPassword', 'userName', 'pat', 'email_address', 'email_password', 'includes', 'excludes', 'parser_options', 'username', 'privateKey', 'sshKey'];
if (process.env.NODE_ENV == 'production')
    publicDir = "/dist";
http.globalAgent.maxSockets = 20;
var session_obj;
import {
    getIsAliveStatus
} from './../api/v1/repository/scans/scan.controller';
import {
    getIsPRAliveStatus
} from './../api/views/pullRequest/scan.controller';

import {
    setEmboldSecurityCheck
} from './../api/v1/repository/codeCheckers/codeCheckers.controller';
// XSS - List of api endpoints to apply custom sanitization
const CUSTOM_XSS_API_LIST = [`/api/${gammaConfig.apiVersion}/ldap`, `/api/${gammaConfig.apiVersion}/users/roles`, `/api/${gammaConfig.apiVersion}/tags/tagcategories`, `/api/${gammaConfig.apiVersion}/qualitygateprofiles`, `/api/${gammaConfig.apiVersion}/accesstoken`];
// XSS - List of api endpoints with dynamic url path to apply custom sanitization
const CUSTOM_XSS_API_TAGS_REGEX = /api\/v1\/tags\/tagcategories\/([\w.\-]+)\/tags/g;
// XSS - Define object types
const TYPE_ARRAY = 'Array';
const TYPE_OBJECT = 'Object';
const TYPE_STRING = 'String';
const UPLOADS_DIR = `.${publicDir}/uploads`;
// Create uploads directory if not exist
if (!fs.existsSync(UPLOADS_DIR)) {
    if (_.contains(["true", true], gammaConfig.is_cloud)) {
        log.debug("Cloud :: Upload directory does not exist :: Creating new with 744 permission");
        fs.mkdirSync(UPLOADS_DIR);
        fs.chmodSync(UPLOADS_DIR, 0o744);
    } else {
        log.debug("OnPremise :: Upload directory does not exist :: Creating new with 770 permission");
        fs.mkdirSync(UPLOADS_DIR);
        fs.chmodSync(UPLOADS_DIR, 0o770);
    }
}
function Method1(a: string, b: number) {
  switch (a) {
    case 0:
      switch (b) {  // nested switch voilation
        // ...
      }
    case 1:
      // ...
    default:
      // ...
  }
}
function init() {
    // Avoids DEPTH_ZERO_SELF_SIGNED_CERT error
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    //Promise.promisifyAll(require('async'));
    if (!shell.which('bash')) {
        log.error(`Sorry, this application requires bash.Please add 'bash' to PATH variable.`);
        shell.exit(1);
    }

    if (process.env.GAMMA_ACCOUNT && process.getuid) {
        try {
            process.setuid(process.env.GAMMA_ACCOUNT);
        } catch (err) {
            log.warn(`Failed to set user: ${err}`);
        }
    }
    app.set('port', gammaConfig.port);
    app.set('publicPath', root);
    /* app.use(express.json({
        limit: '1mb'
    }));
    app.use(express.urlencoded({
        limit: '1mb',
        parameterLimit: 5000
    })); */

    // for parsing application/json
    app.use(bodyParser.json({
        limit: '10mb'
    }));

    // for parsing application/xwww-
    app.use(bodyParser.urlencoded({
        extended: true,
        limit: '10mb',
        parameterLimit: 50000
    }));
    app.use(helmet());
    var xssOptions = {
        whiteList: [], // empty, means filter out all tags
        stripIgnoreTag: true, // filter out all HTML not in the whilelist
    };
    xssSanitizer = new xss.FilterXSS(xssOptions);
    app.use(function (req, res, next) {
        if (req.method == 'POST' || req.method == 'PUT') {
            var sanitizeObj = req.body;
            // XSS - Trim last slash from url
            let requestUrl = (!_.isUndefined(req.url)) ? __.trimEnd(__.trim(req.url), '/') : '';
            // XSS - Look up specific endpoint in list
            let doCustomSanitization = _.includes(CUSTOM_XSS_API_LIST, requestUrl);
            if (!doCustomSanitization) {
                doCustomSanitization = (new RegExp(CUSTOM_XSS_API_TAGS_REGEX).test(req.url)) ? true : false;
            }

            _.each(sanitizeObj, (val, key) => {
                if (XSS_EXCLUSIONS.indexOf(key) == -1) {
                    if (doCustomSanitization) {
                        let isObjType = isTypeOf(val);
                        // Applicable on array or json object types
                        if (_.includes([TYPE_OBJECT, TYPE_ARRAY], isObjType)) {
                            req.body[key] = sanitizeIterativeObj(val);
                        } else {
                            req.body[key] = sanitizeData(val);
                        }
                    } else {
                        // Skip sanitization if param is array or json object
                        if (typeof val !== 'undefined' && val !== null && (val.constructor != Array || !_.isArray(val)) && val.constructor != Object) {
                            req.body[key] = sanitizeData(val);
                        }
                    }
                }
            });
        }
        next();
    });

    function sanitizeData(val) {
        val = xssSanitizer.process(val);
        return val;
    }

    function isTypeOf(val) {
        if (_.isArray(val) && val.constructor == Array) {
            return TYPE_ARRAY;
        } else if (_.isObject(val) && val.constructor == Object) {
            return TYPE_OBJECT;
        } else {
            return TYPE_STRING;
        }
    }

    function sanitizeIterativeObj(dataObj) {
        Object.keys(dataObj).forEach(function (k) {
            if (XSS_EXCLUSIONS.indexOf(k) == -1) {
                let isObjType = isTypeOf(dataObj[k]);
                if (!_.isNull(dataObj[k]) && _.includes([TYPE_OBJECT, TYPE_ARRAY], isObjType)) {
                    sanitizeIterativeObj(dataObj[k]);
                    return;
                }
                if (isObjType === TYPE_STRING) {
                    dataObj[k] = sanitizeData(dataObj[k]);
                }
            }
        });
        return dataObj;
    }
    if (_.contains(["true", true], gammaConfig.is_cloud)) {
        // Access-Control-Allow-Origin: Configure Options
        let corsMethodsList = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];
        let corsHeadersList = ["Origin", "Content-Type", "Accept", "X-Requested-With", "authorization", "x_referral"];
        let corsOptions = {
            methods: corsMethodsList,
            allowedHeaders: corsHeadersList,
            origin: function (origin, callback) {
                if (!_.isUndefined(origin) && !_.isNull(origin) && !_.isEmpty(origin)) {
                    if (isDomainAllowed(origin)) {
                        log.info(`Access-Control-Allow-Origin: ${origin} allowed by CORS.`);
                        callback(null, true);
                    } else {
                        callback(new Error(`Access-Control-Allow-Origin: ${origin} disallowed by CORS.`));
                    }
                } else {
                    callback(null, true);
                }
            },
            preflightContinue: false,
            optionsSuccessStatus: 204
        }
        app.use(function (req, res, next) {
            // Access-Control-Allow-Origin: Apply CORS Middleware
            if (!_.isUndefined(req.headers.origin) && !_.isNull(req.headers.origin) && !_.isEmpty(req.headers.origin)) {
                app.use(cors(corsOptions));
            }
            // Applies CORS only if request comes through API docs
            if (req.method === "OPTIONS" || (req.method !== "OPTIONS" && typeof req.headers.x_referral != 'undefined' && req.headers.x_referral == 'embold-try-it')) {
                app.use(cors());
                // predefined domains
                let allowedDomains = ['api.embold.io', 'api.gamma-staging.com', 'api.gamma-test.com'];
                let allowedMethods = ["GET", "OPTIONS"];
                let allowedHeaders = corsHeadersList;
                let additionalDomains = [];
                let additionalMethods = [];
                let additionalHeaders = [];
                // example value of environment variable additional_cors_domain : ["api.localtest.me:3000", "api.localtest.me:3002"]
                if (typeof gammaConfig.additional_cors_domains != 'undefined') {
                    additionalDomains = gammaConfig.additional_cors_domains;
                }
                let allDomains = _.uniq(_.union(allowedDomains, additionalDomains));
                let allAllowedDomains = [];
                _.each(allDomains, function (v, k) {
                    allAllowedDomains.push(v);
                    allAllowedDomains.push('http://' + v);
                    allAllowedDomains.push('https://' + v);
                })

                // example value of environment variable additional_cors_method : ["POST", "PUT", "DELETE"]
                if (typeof gammaConfig.additional_cors_method != 'undefined') {
                    additionalMethods = gammaConfig.additional_cors_method;
                }
                let allMethods = _.uniq(_.union(allowedMethods, additionalMethods)).join();


                // example value of environment variable additional_cors_headers : ["X-Origin"]
                if (typeof gammaConfig.additional_cors_headers != 'undefined') {
                    additionalHeaders = gammaConfig.additional_cors_headers;
                }
                let allHeaders = _.uniq(_.union(allowedHeaders, additionalHeaders)).join();

                let origin = typeof req.headers.origin != 'undefined' ? req.headers.origin : req.get('host');
                let hasNginxOrigin = typeof gammaConfig.has_nginx_origin != 'undefined' ? gammaConfig.has_nginx_origin : false;
                if (allAllowedDomains.indexOf(origin) > -1 && _.contains(["true", true], hasNginxOrigin)) {
                    res.setHeader('Access-Control-Allow-Origin', origin);
                }
                // Request methods you wish to allow
                res.setHeader('Access-Control-Allow-Methods', allMethods);

                // Request headers you wish to allow
                res.setHeader('Access-Control-Allow-Headers', allHeaders);

                if (req.method === "OPTIONS") res.send(200);
                else next();
            } else next();
        });
    }

    //Csrf
    /*app.use(cors());
    app.use(cookieParser());
    app.use(csrf({ cookie: true }));
    app.use(function(err, req, res, next) {
        var token = req.csrfToken();
        res.cookie('X-CSRF-Token', token);
        res.locals.csrfToken = token;
        next();
    });*/

    // for parsing multipart/form-data
    /* app.use(upload.array());
    app.use(express.static('public/uploads')); */

    require('./passport')(app, passport);
    app.use(passport.initialize());

    //app.use(passport.session());
    require('./master-routes')(app);
    require('./../license/v1/routes').licenseRoutes(app);

    startServer();
    initAnalysisService();
    setEmboldSecurityCheck();
}

function startServer() {
    try {
        if (gammaConfig.clusterEnabled && cluster.isMaster) {
            var numCPUs = require('os').cpus().length;

            for (var i = 0; i < numCPUs; i++) {
                cluster.fork();
            }
            Object.keys(cluster.workers).forEach(function (id) {
                log.print(log.level.DEBUG, cluster.workers[id].process.pid);
            });

            cluster.on('exit', function (worker, code, signal) {
                log.warn(`worker ${worker.process.pid} died`);
            });
        } else {
            var server = http.createServer(app);
            server.listen(app.get('port'), '0.0.0.0', function (server1) {
                let productVersion = gammaConfig.version;
                if (gammaConfig.productVersion) {
                    productVersion = gammaConfig.productVersion
                } else {
                    log.info("UI version set as Product version");
                }

                log.info(`Embold server (Product Version-${productVersion}) (UI Version-${gammaConfig.version}) listening on port ${app.get('port')}`);
            });
            var io = require('socket.io')();
            io.attach(server);

            var keyPath = cf.actualPath(gammaConfig.ssl.key);
            var certPath = cf.actualPath(gammaConfig.ssl.cert);
            fs.exists(certPath, function (exists) {
                if (exists) {
                    var options = {
                        key: fs.readFileSync(keyPath),
                        cert: fs.readFileSync(certPath),
                        passphrase: gammaConfig.ssl.passphrase
                    };
                    if (_.contains(["true", true], gammaConfig.is_cloud)) {
                        options.secureOptions = constants.SSL_OP_NO_SSLv2 | constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_TLSv1 | constants.SSL_OP_NO_TLSv1_1
                    }
                    var httpsServer = https.createServer(options, app)

                    httpsServer.listen(gammaConfig.ssl.port, function (server1) {
                        log.info(`Express (https) server listening on port ${gammaConfig.ssl.port}`);
                    });
                    io.attach(httpsServer);
                } else {
                    log.warn(`SSL certificate does not exist`);
                }
            });

            /* io.use(function (socket, next) {
                session_obj(socket.request, socket.request.res, next);
            }); */

            //require('admin/analysis').initialiseSocket(io);
            module.exports.socket = require('./../component/socket').init(io);

            //creating gamma db connection pool
            db.initGammaDB();
            require('./../component/email').setEmailConfig();
        }

        if (gammaConfig.cacheEnabled) {
            // cache.del('*',function(){
            //     log.info('----cache cleared----');
            // });
        }
    } catch (err) {
        log.error(err);
    }
}

var start_analysis, get_analysis_status;

function initAnalysisService() {
    get_analysis_status = setInterval(function () {
        getIsAliveStatus();
        if (_.contains(["true", true], gammaConfig.enablePRScan) && gammaConfig.polling_pr_cron_time) {
            getIsPRAliveStatus();
        }
    }, 30000);
}
// Access-Control-Allow-Origin: Validate Origin with wildcard domains - For Cloud Usage Only
function isDomainAllowed(originHeader) {
    if (gammaConfig.gamma_ui_env == 'live' && (originHeader.match(/^(?:https?:\/\/)?(?:[a-zA-Z0-9]{0,40}\.)?(?:os\.)?embold\.io|gamma-staging\.com|gamma-test\.com|embold-uat\.com|mygamma-copy\.com/))) {
        return true;
    } else if (gammaConfig.gamma_ui_env == 'local' && originHeader.match(/^(?:https?:\/\/)?(?:[a-zA-Z0-9]{0,40}\.)?(?:os\.)?embold\.io|gamma-staging\.com|gamma-test\.com|embold-uat\.com|mygamma-copy\.com|localtest\.me|localhost(?:[:0-9]{1,6})?/)) {
        return true;
    } else {
        return false;
    }
}

process.on('SIGINT', function () {
    log.warn(`Cleaning node data before exit`);
    log.shutDownLogger();
    process.exit();
});

process.on('uncaughtException', function (err) {
    log.fatal(`${(new Date).toUTCString()} uncaughtException: ${err.message}`);
    log.error(err.stack);
});

/* process.on('unhandledRejection', error => {
    // Won't execute
    log.debug(error);
}); */

module.exports.beta = "7279546f";
module.exports.alpha = "70536563";
module.exports.init = init;
module.exports.publicDir = publicDir;
module.exports.emptyPromise = new Promise(function (resolve, reject) {
    resolve([])
});
module.exports.i18next = require('../core/i18next')(app);
module.exports.deletedRepositories = {};
export default app;
