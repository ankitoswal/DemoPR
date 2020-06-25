import pathMod from 'path';
import passport from 'passport';
import express from 'express';
import * as log from './../logs/logger';
import expressApiVersioning from 'express-api-versioning';
import * as db from './../component/db';
import gammaConfig from '../core/config';
import * as authUser from './../api/v1/auth/auth.controller';
import {
    ENABLE_CAPTCHA
} from './../services/authService';
const errors = require('throw.js');
import {
    handleError
} from './../errors/error';
import {
    getLatestNodeSnapshotForRepositoryUid,
    validateRepositoryUid
} from '../services/repository';
import {
    getTenantDetailsForRepo
} from '../services/tenant';
import {
    catchError
} from './../errors/error';
import _ from 'underscore';
import moment from 'moment';
import * as licenseService from './../services/license';
import * as cf from './../utils/common-functions';
import * as auth from './../services/authService';
import lodash from 'lodash';
var gamma = require('./gamma');
import {
    URL
} from 'url';
const SECRET_HEADERS = ['Server', 'server', 'Date', 'date'];

module.exports = function (app) {
    app.use(logRequestStart);
    app.use(removeResponseHeader);

    app.get(['/docs', '/gamma/docs'], function (req, res, next) {
        // Enable docs for onpremise, paid and trial. Hide for opensource
        if (cf.isAPIEnabled(req.subdomains)) {
            if (_.contains(["true", true], gammaConfig.is_cloud) && !_.contains(req.subdomains, 'api')) {
                var host = req.get('host');
                var substring = host.substring(0, 12);
                log.trace("Docs accessing through host : " + host);
                // Replace host if host is not localtest.me else move to next
                if (substring !== 'localtest.me') {
                    var apiHost = host.replace(/^[^.]*/, 'api');
                    return res.redirect(req.protocol + '://' + apiHost + '/docs/');
                }
                return next();
            } else {
                return next();
            }
        } else {
            return res.redirect('/');
        }
    });

    app.get('/', function (req, res) {
        var fragment = "";

        if (req.query.redirect)
            fragment = '#' + req.query.redirect;
        //if (req.isAuthenticated())
        res.redirect(`${gammaConfig.root}${fragment}`);
        /* else
            res.redirect(`/login${fragment}`); */
    });

    app.get('/login', function (req, res, next) {
            log.trace("Login with host : " + req.host);
            if (cf.isAPIEnabled(req.subdomains)) {
                if (_.contains(["true", true], gammaConfig.is_cloud) && _.contains(req.subdomains, 'api')) {
                    return res.redirect('/docs');
                } else {
                    return next();
                }
            }
            return next();
        }, function (req, res, next) {
            return next();
        }, licenseService.licenseMiddleware,
        async function (req, res, next) {
            if ((_.contains(["true", true], gammaConfig.is_cloud)) && (_.contains(["true", true], ENABLE_CAPTCHA))) {
                // set headers
                auth.setCaptchaHeaders(res);
                let clientIp = cf.getClientIp(req);
                let isFailedLogin = await authUser.getLoginAttempts(clientIp);
                res.setHeader('maxLoginAttempts', isFailedLogin);
                res.sendFile(pathMod.resolve('./' + gamma.publicDir + '/login.html'));
            } else {
                res.sendFile(pathMod.resolve('./' + gamma.publicDir + '/login.html'));
            }

        });

    app.get('/authorize/:type',
        function (req, res, next) {
            let requestUrl = cf.getRequestUrl(req);
            let requestUrlDetails = getRequestUrlDetails(requestUrl);
            res.render('verification-code.pug', {
                'verificationCode': req.query.code,
                'basePath': `${requestUrlDetails.serverProtocol}://${requestUrlDetails.serverHost}:${requestUrlDetails.serverPort}`
            });
        }
    );

    function getRequestUrlDetails(hostUrl) {
        let serverUrl = new URL(lodash.trim(hostUrl, '/'));
        let serverDetails = {
            "serverUrl": new URL(lodash.trim(hostUrl, '/')),
            "serverProtocol": lodash.trim(serverUrl.protocol, ':'),
            "serverHost": serverUrl.hostname,
            "serverPort": serverUrl.port
        }
        return serverDetails;
    }

    app.get('/license-summary', function (req, res, next) {
        return next();
    }, licenseService.licenseMiddleware, function (req, res) {
        if (gammaConfig.is_cloud === false || gammaConfig.is_cloud === "false") {
            res.sendFile(pathMod.resolve('./' + gamma.publicDir + '/license-summary.html'));
        } else {
            res.sendFile(pathMod.resolve('./' + gamma.publicDir + '/license.html'));
            // res.redirect('/login');
        }
    });

    app.get('/license-deactivated', function (req, res, next) {
        return next();
    }, licenseService.licenseMiddleware, function (req, res) {
        if (gammaConfig.is_cloud === false || gammaConfig.is_cloud === "false") {
            res.sendFile(pathMod.resolve('./' + gamma.publicDir + '/license-reactivate.html'));
        } else {
            res.redirect('/login');
        }
    });

    app.get('/setup', function (req, res, next) {
        return next();
    }, licenseService.licenseMiddleware, function (req, res) {
        res.sendFile(pathMod.resolve('./' + gamma.publicDir + '/setup.html'));
    });

    app.get('/deactivate', function (req, res, next) {
        return next();
    }, licenseService.licenseMiddleware, function (req, res) {
        res.sendFile(pathMod.resolve('./' + gamma.publicDir + '/deactivate.html'));
    });

    app.get('/account-deactivated', function (req, res, next) {
        return next();
    }, licenseService.licenseMiddleware, function (req, res) {
        res.sendFile(pathMod.resolve('./' + gamma.publicDir + '/account-deactivated.html'));
    });

    app.get('/migrate', function (req, res, next) {
            return next();
        }, licenseService.licenseMiddleware,
        function (req, res) {
            if (req.session) {
                auth.logout(req.session.tokenId, next);
                req.logout();
            }
            res.sendFile(pathMod.resolve('./' + gamma.publicDir + '/migrate.html'));
        });

    app.get('/reset_password/:url', function (req, res) {
        req.logout();
        // set headers
        if ((_.contains(["true", true], gammaConfig.is_cloud)) && (_.contains(["true", true], ENABLE_CAPTCHA))) {
            auth.setCaptchaHeaders(res);
            validateResetURL(app, req, req.params.url, res);
        } else {
            validateResetURL(app, req, req.params.url, res);
        }
    });
    app.get('/backlink', function (req, res, next) {
        return createBackLink(req, next)
            .then((backlinkData) => {
                if (!_.isObject(backlinkData)) {
                    res.redirect(backlinkData);
                } else {
                    return next(new errors.NotFound(backlinkData.statusMessage, backlinkData.statusCode));
                }

            })
    });


    // add default route after login
    app.get(gammaConfig.root, function (req, res) {
        res.sendFile(pathMod.resolve('./' + gamma.publicDir + '/gamma.html'));
    });

    // add static file routes
    var oneWeek = 604800000;
    app.use(gammaConfig.root, express.static(pathMod.join(global.rootDir, gamma.publicDir), {
        maxAge: oneWeek
    }));
    if (!process.env.IGNORE_STATIC)
        app.use('/', express.static(pathMod.join(global.rootDir, gamma.publicDir), {
            maxAge: oneWeek
        }));
    app.use('/locales', express.static(pathMod.join(global.rootDir, '/locales'), {
        maxAge: oneWeek
    }));
    app.set('views', pathMod.join(__dirname, '/../', '/component/views'));
    app.set('view engine', 'pug');

    // add dynamic routes
    // add authentication for each api route starting with gamma/api
    app.use('/api', catchError(authenticateToken));
    //app.use('/api', authenticateToken);

    async function authenticateToken(req, res, next) {
        let matchUrl = (req.url).match(/\/(v[0-9]+)/i);
        let apiVersion = '';
        if (matchUrl) {
            apiVersion = matchUrl[0];
        }
        let apiSubRoute = (req.url).split(apiVersion + "/")[1].toLowerCase();
        let isAppConsumer = cf.isAppConsumer(req, res, apiSubRoute);
        let isLicenseAgentConsumer = cf.isLicenseAgentConsumer(req, res);
        //Applicable for non-auth api group set - skip
        if (!cf.isAuthRequired(req.url) || !cf.isAuthRequired((req.url).split(apiVersion + "/")[1].toLowerCase())) {
            next();
        }
        //Applicable for license agent routes
        else if (isLicenseAgentConsumer) {
            next();
        }
        //Applicable for consumer type app - use oauth strategy
        else if (isAppConsumer.consumer_type === 'APP' && isAppConsumer.consumer_route_allowed) {
            //Store copy
            let rb = req.body;
            passport.authenticate('bearer', {
                session: false
            }, function (err, data, req) {
                if (data) {
                    //Session dependency object
                    req.session = {};
                    req.session.tenant_uid = (typeof rb.tenantUid != 'undefined') ? rb.tenantUid : '';
                    next();
                } else {
                    return next(new errors.Unauthorized(null, 1001));
                }
            })(req, res, next);
        }
        //Applicable otherwise - use jwt strategy
        else {
            passport.authenticate('jwt', {
                session: false
            }, function (err, data) {
                if (data)
                    next();
                else {
                    return next(new errors.Unauthorized(null, 1001));
                }
            })(req, res, next);
        }
    }

    // middleware inject db details in request object
    app.use(catchError(db.injectDb));

    // require('./../license/v1/routes').licenseRoutes(app);
    //add routes for all rest apis
    const versionConfig = {
        apiPath: pathMod.join(__dirname, '../api'),
        test: /\/api\/(v[0-9]+).*/,
        entryPoint: 'route.js',
        instance: app
    };
    app.use(expressApiVersioning(versionConfig, (error, req, res, next) => {
        next();
    }));

    //add routes for all views
    require('./../api/views/route').default(app);
    //require('./../api/admin/route').default(app);

    /* app.use(function (req, res, next) {
        return next(new errors.NotFound(null, 1008));
    }); */
    //handle all errors here
    app.use(handleError);
}

function createBackLink(req, next) {
    let timestamp = moment.utc();
    timestamp.format();
    let mode = 'explorer';
    let pluginOptions = {
        searchTerm: req.query.searchTerm
    };
    let context = req.query.context ? req.query.context : "subsystems";
    let pluginName = req.query.pluginName ? req.query.pluginName : 'repository_overview';
    let repositoryUid = req.query.repoUid ? req.query.repoUid : '';
    let searchTerm = req.query.searchTerm ? req.query.searchTerm : '';
    let requestData;

    return validateRepositoryUid(repositoryUid, next)
        .then((repoUidData) => {
            if (repoUidData) {
                return getTenantDetailsForRepo(req, next, repositoryUid)
                    .then(tenantData => {

                        let tenantUid = tenantData.tenant_uid;
                        let tenantId = tenantData.id;
                        return getLatestNodeSnapshotForRepositoryUid(repositoryUid, tenantUid, tenantId, true)
                            .then(data => {
                                let breadcrumbData = {
                                    'node_id': data.nodeId,
                                    'node_name': data.repositoryName
                                };
                                requestData = {
                                    repository_id: data.repositoryId,
                                    node_id: data.nodeId,
                                    snapshot_id: data.snapshotId,
                                    project_id: data.repositoryId
                                };
                                let historyObj = {
                                    'id': timestamp.valueOf(),
                                    'plugin_id': pluginName,
                                    'old_plugin_id': pluginName,
                                    'subsystem_id': data.repositoryId,
                                    'subsystem_uid': repositoryUid,
                                    'subsystem_name': data.repositoryName,
                                    'project_name': data.projectName,
                                    'project_id': data.projectId,
                                    'breadcrumb': breadcrumbData,
                                    'request_data': requestData,
                                    'plugin_options': pluginOptions,
                                    'context': context,
                                    'mode': mode,
                                    'searchTerm': searchTerm
                                };
                                let historyObjStr = JSON.stringify(historyObj);
                                let encodedData = Buffer.from(historyObjStr).toString('base64');
                                let backLink = encodedData;
                                return cf.getDomainURL(tenantUid, "tenant_uid", req).then(function (domainURL) {
                                    let baseURL = domainURL + '/gamma#';
                                    backLink = baseURL + backLink;
                                    return backLink;
                                })
                            });
                    });
            } else {
                return {
                    statusCode: 1008,
                    statusMessage: `Repository UID '${repositoryUid}' not found.`
                };

            }

        })


}

function validateResetURL(app, req, decodeURL, res) {
    var decryptedURL = cf.decryptURL(decodeURL);
    var linkTimeout = 86400000;
    try {
        decryptedURL = JSON.parse(decryptedURL);
    } catch (catchErr) {
        log.error(catchErr);
        res.sendFile(pathMod.resolve('./' + gamma.publicDir + '/404.html'));
    }
    if (decryptedURL.newuser) {
        res.sendFile(pathMod.resolve('./' + gamma.publicDir + '/reset_password.html'));
    } else {
        sql_query = `select * from forgot_password where email_id = $1 and close_at IS NULL ORDER BY request_timestamp DESC LIMIT 1`;
        db.gammaDbPool.query(sql_query, [decryptedURL.emailid])
            .then(forgot_password => {
                if ((!forgot_password || forgot_password.length != 0) && forgot_password[0].url == decodeURL) {
                    try {
                        var linkTimeStamp = forgot_password[0].request_timestamp;
                        var currentTimestamp = Date.now();
                        var expTimestamp = currentTimestamp - linkTimeout;
                        if (linkTimeStamp < expTimestamp || forgot_password[0].close_at) {

                            res.sendFile(pathMod.resolve('./' + gamma.publicDir + '/link_expired.html'));
                        } else {
                            res.sendFile(pathMod.resolve('./' + gamma.publicDir + '/reset_password.html'));
                        }
                    } catch (err) {
                        log.error(err);
                    }
                } else {
                    res.sendFile(pathMod.resolve('./' + gamma.publicDir + '/link_expired.html'));
                }
            });
    }

}

function logRequestStart(req, res, next) {
    let logUrl = cf.getRequestUrl(req);
    log.trace(cf.getClientIp(req) + ` : ${req.method} : ${logUrl}`);
    next();
}

function removeResponseHeader(req, res, next) {
    res.removeHeader('server');
    next();
}