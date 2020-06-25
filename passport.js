import * as log from './../logs/logger';
import gammaConfig from './../core/config';
import _ from 'underscore';
import {
    Strategy as LocalStrategy
} from 'passport-local';
import {
    Strategy as JWTStrategy
} from 'passport-jwt';
import {
    ExtractJwt as ExtractJWT
} from 'passport-jwt';
import {
    Strategy as ClientPasswordStrategy
} from 'passport-oauth2-client-password';
import {
    Strategy as BearerStrategy
} from 'passport-http-bearer';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import * as db from './../component/db';
import * as cf from './../utils/common-functions';
import * as apigroup from './../permissions/apigroup';
import md5 from 'md5';
const errors = require('throw.js');
import * as licenseService from './../services/license';
var ldapAuth = require('ldapauth-fork');
import async from 'async';
const appTokenWhitelist = (typeof apigroup.appTokenWhitelist !== 'undefined') ? apigroup.appTokenWhitelist : [];
const tokenExpiryTime = 86400; // time in seconds (1 day)
var sqlQuery, trialFlag;

const JWT_ALGORITHM = `ES256`;
const JWT_SECRET = '$2a$08$SgigBM6fMotp6.t7Qjh76eQQfHZ1yuJrnU6GX1yxns3QwqUVb/pke';
const PRIVATE_KEY = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIE55jrJU5BjD+OoUsxwffT7S8KQQLi+aHunvf1ENy0eFoAoGCCqGSM49
AwEHoUQDQgAEsRzHg+TTaS/fjVsAmI2AhifrgRiP058E8KHhccI2L5wKpJXdjWVt
+lP7GYO6MRtk9D74izf611i/fLj4BrFUgg==
-----END EC PRIVATE KEY-----`;

const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsRzHg+TTaS/fjVsAmI2AhifrgRiP
058E8KHhccI2L5wKpJXdjWVt+lP7GYO6MRtk9D74izf611i/fLj4BrFUgg==
-----END PUBLIC KEY-----`;

const CORONA_MIGRATION_STATUS_CHECK_TIMER = 15000;
const timeLimit = process.env.EMBOLD_REQUESTS_TIME_LIMIT || (5 * 60 * 1000);
const requestLimit = process.env.EMBOLD_REQUESTS_LIMIT || 5000000;

const rateLimitConfig = rateLimit({
    windowMs: parseInt(timeLimit), // 5 minutes
    max: parseInt(requestLimit), // limit each IP to 5000 requests per windowMs
    keyGenerator: function (req) {
        let ip = cf.getClientIp(req);
        let logUrl = cf.getRequestUrl(req);
        let authHeader = (typeof req.headers.authorization !== 'undefined') ? req.headers.authorization : '';
        let key = md5(ip + authHeader);
        log.trace("Rate limiter : key " + key + ` : ${ip} : ${req.method} : ${logUrl}`);
        return key;
    },
    handler: function (req, res, /*next*/ ) {
        let ip = cf.getClientIp(req);
        log.info("Too many requests from IP " + ip + ". Request limit is " + requestLimit + ". Time window is " + timeLimit + " ms");
        res.json(429, {
            "error": {
                "statusCode": 429,
                "name": "TooManyRequests",
                "message": "Too many requests from this IP, please try again after some time."
            }
        });
    }

});

module.exports = function (app, passport) {

    // used to serialize the user for the session
    passport.serializeUser(function (user, done) {
        done(null, user);
    });

    // used to deserialize the user
    passport.deserializeUser(function (user, done) {
        done(null, user);
    });

    passport.use('local-login', new LocalStrategy({
            // by default, local strategy uses username and password, we will override with email
            usernameField: 'username',
            passwordField: 'password',
            passReqToCallback: true // allows us to pass back the entire request to the callback
        },
        function (req, username, password, next) {
            if (_.contains(req.subdomains, gammaConfig.gamma_os_postfix)) {
                trialFlag = true;
            } else {
                trialFlag = false;
            }
            req.subdomain = licenseService.getSubdomain(req.subdomains);

            sqlQuery = `select users.*, tenant.tenant_uid as tenant_uid,tenant.is_trial as is_trial, tenant.subdomain,tenant_directory.directory_type from users,tenant, tenant_directory where email=$1 and users.tenant_id=tenant.id and users.directory_id = tenant_directory.id and tenant_directory.directory_type = $4 and tenant.subdomain = $2 and tenant.is_trial=$3`;
            db.gammaDbPool.query(sqlQuery, [(cf.parseString(username)).toLowerCase(), req.subdomain, trialFlag, 'internal'], next)
                .then(user => {
                    if (!user || user.length == 0 || cf.encryptPassword(password, user[0].salt) != user[0].password) {
                        if (cf.isDirectoryEnabled(req.subdomains)) {
                            //Enabled user directory - info with directory user
                            log.info('Directory user login', {
                                'tenantUid': user.tenant_uid,
                                'userId': user.id
                            });
                            ldapLogin(req, next).then(function () {
                                // userLogin(req.subdomains, user, next);
                            }).catch((err) => {
                                if (typeof err !== 'undefined' && err && (err.code === 'ECONNREFUSED' || err.code === 'EHOSTUNREACH')) {
                                    log.error(err.message, {
                                        'tenantUid': user.tenant_uid,
                                        'userId': user.id
                                    });
                                    return next(new errors.CustomError('connectionRefuse', "Connection refused due to host unreachable.", 400, 2004));
                                } else {
                                    return next(null, false, new errors.Unauthorized(null, 1001));
                                }
                            });
                        } else {
                            return next(null, false, new errors.Unauthorized(null, 1001));
                        }
                    } else if (user[0].status == 2) {
                        return next(new errors.Unauthorized("Inactive User", 1002));
                    } else if (user[0].status == 0 && user[0].is_primary == true) {
                        return next(new errors.Unauthorized("Unverified User", 1003));
                    } else {
                        log.info('Embold user login', {
                            'tenantUid': user.tenant_uid,
                            'userId': user.id
                        });
                        userLogin(req.subdomains, user, next);
                    }
                }).catch((err) => {
                    log.error(err.message, {
                        'tenantUid': null,
                        'userId': null
                    });
                    return next(null, false, new errors.Unauthorized(null, 1001));
                });
        }
    ));

    // LDAP login which will checks for all kind of external connector
    function ldapLogin(req, next) {
        return new Promise(function (resolve, reject) {
            let username = cf.parseString(req.body.username);
            let password = req.body.password;
            let subdomains = req.subdomains;

            subdomain = licenseService.getSubdomain(subdomains);
            sqlQuery = `select tenant_directory.*, tenant.id as tenant_id, tenant.tenant_uid as tenant_uid, tenant.subdomain from tenant_directory, tenant where tenant_directory.tenant_uid=tenant.tenant_uid and tenant.subdomain = $1 and tenant_directory.directory_type = $2 and tenant_directory.status=1 `;
            req.gamma.query(sqlQuery, [subdomain, 'external'])
                .then(directories => {
                    if (directories.length) {
                        let directoryIndex = 1;
                        async.forEachSeries(directories, function (directory, callback) {
                                let url = `${directory.metadata.protocol}://${directory.metadata.hostname}:${directory.metadata.port}`;

                                // Filtering by users and groups prepend group and user DN to baseDN
                                let ldapBaseDn = directory.metadata.baseDn;
                                if (directory.metadata.groupDn !== '' && directory.metadata.userDn !== '') {
                                    ldapBaseDn = `${directory.metadata.userDn},${directory.metadata.groupDn},${ldapBaseDn}`;
                                } else if (directory.metadata.groupDn !== '') {
                                    ldapBaseDn = `${directory.metadata.groupDn},${ldapBaseDn}`;
                                } else if (directory.metadata.userDn !== '') {
                                    ldapBaseDn = `${directory.metadata.userDn},${ldapBaseDn}`;
                                }

                                var options = {
                                    url: url + '/' + new Date().getTime(),
                                    bindDN: directory.metadata.readerUsername,
                                    bindCredentials: cf.decryptStringWithAES(directory.metadata.readerPassword),
                                    searchBase: ldapBaseDn,
                                    tlsOptions: {
                                        rejectUnauthorized: false,
                                        ecdhCurve: 'secp384r1'
                                    },
                                    timeout: 10000,
                                    connectTimeout: 10000,
                                    searchFilter: `(&(objectClass=${directory.metadata.userSchema.ldapUserObjectclass})${directory.metadata.userSchema.ldapUserFilter}(mail={{username}}))`,
                                    searchAttributes: ['cn', 'givenName', 'sn', 'uid', 'objectClass', 'creatorsname', 'createtimestamp', 'modifiersname', 'structuralObjectClass', 'entryUUID', 'modifytimestamp', 'mail', 'objectGUID', 'objectSid', 'subschemaSubentry', 'hasSubordinates', 'member', 'groupOfNames', '+']
                                };

                                var auth = new ldapAuth(options);

                                auth.once('error', function (err) {
                                    auth.close();
                                    if (parseInt(directoryIndex) >= directories.length) {
                                        directoryIndex += 1;
                                        log.error('LDAP connection reject error : ', JSON.stringify(err) + ' for conection details :' + JSON.stringify(_.omit(options, ['bindCredentials', 'searchAttributes', 'timeout', 'connectTimeout', 'tlsOptions'])), {
                                            'tenantUid': directory.tenant_uid,
                                            'userId': directory.id
                                        });
                                        reject(err);
                                    } else {
                                        directoryIndex += 1;
                                        log.error('LDAP connection callback error : ', JSON.stringify(err) + ' for connection details :' + JSON.stringify(_.omit(options, ['bindCredentials', 'searchAttributes', 'timeout', 'connectTimeout', 'tlsOptions'])), {
                                            'tenantUid': directory.tenant_uid,
                                            'userId': directory.id
                                        });
                                        return callback();
                                    }
                                });

                                // Register a LDAP client connection "connectTimeout" handler
                                // The ldap connection attempt has been timed out...
                                auth.once('connectTimeout', function (err) {
                                    auth.close();
                                    if (parseInt(directoryIndex) >= directories.length) {
                                        directoryIndex += 1;
                                        log.error('LDAP connection timeout reject error : ', JSON.stringify(err) + ' for connection details :' + JSON.stringify(_.omit(options, ['bindCredentials', 'searchAttributes', 'timeout', 'connectTimeout', 'tlsOptions'])), {
                                            'tenantUid': directory.tenant_uid,
                                            'userId': directory.id
                                        });
                                        reject(err);
                                    } else {
                                        directoryIndex += 1;
                                        log.error('LDAP connection timeout callback error : ', JSON.stringify(err) + ' for connection details :' + JSON.stringify(_.omit(options, ['bindCredentials', 'searchAttributes', 'timeout', 'connectTimeout', 'tlsOptions'])));
                                        return callback();
                                    }
                                });

                                auth.authenticate(username, password, function (err, ldapUser) {
                                    auth.close();
                                    if (ldapUser) {
                                        // get external user details if available
                                        externalUserDetails(username, subdomain, next, directory.id)
                                            .then(existingUser => {

                                                let ldapFirstName = ldapUser[directory.metadata.userSchema.ldapUserFirstname]; //ldapUser.givenName;
                                                let ldapLastName = ldapUser[directory.metadata.userSchema.ldapUserLastname]; //ldapUser.sn;
                                                let ldapEmail = ldapUser.mail;
                                                let ldapDirectoryId = directory.id;
                                                let ldapExternalId = '';
                                                if (ldapUser.hasOwnProperty('objectGUID')) {
                                                    ldapExternalId = formatGUID(ldapUser.objectGUID);
                                                } else if (ldapUser.hasOwnProperty('entryUUID')) {
                                                    ldapExternalId = ldapUser.entryUUID;
                                                }

                                                // if already exist direct login
                                                if (existingUser.length) {
                                                    if (existingUser[0].user_status === 1 || existingUser[0].user_status === '1') {
                                                        let updateUserObject = {
                                                            ldapFirstName: ldapFirstName,
                                                            ldapLastName: ldapLastName,
                                                            externalId: existingUser[0].external_id,
                                                            ldapEmail: ldapEmail
                                                        };
                                                        updateUserData(updateUserObject, next);
                                                        userLogin(subdomains, existingUser, next);
                                                    } else {
                                                        return next(new errors.Unauthorized("Inactive User", 1002));
                                                    }
                                                } else {
                                                    // check user limit with license
                                                    licenseService.checkUserLimit(directory.tenant_uid, directory.tenant_id, next)
                                                        .then(() => {
                                                            // insert new record in users for new external user
                                                            insertExternalUserDetails(directory.tenant_id, username, ldapFirstName, ldapLastName, ldapDirectoryId, ldapExternalId, next)
                                                                .then(function () {
                                                                    // get entered user details for login
                                                                    externalUserDetails(username, subdomain, next)
                                                                        .then(newUser => {
                                                                            if (newUser.length) {
                                                                                // login external user
                                                                                userLogin(subdomains, newUser, next);
                                                                            } else {
                                                                                return next(null, false, new errors.Unauthorized(null, 1001));
                                                                            }
                                                                        });
                                                                });
                                                        })
                                                        .catch(licenseError => {
                                                            // return any licensing error like limit exceded
                                                            log.error(licenseError.message, {
                                                                'tenantUid': directory.tenant_uid,
                                                                'userId': directory.id
                                                            });
                                                            next(licenseError);
                                                        });
                                                }
                                            });
                                    } else {
                                        if (parseInt(directoryIndex) >= directories.length) {
                                            directoryIndex += 1;
                                            log.info('LDAP reject error : ', JSON.stringify(err) + ' for conection details :' + JSON.stringify(_.omit(options, ['bindCredentials', 'searchAttributes', 'timeout', 'connectTimeout', 'tlsOptions'])), {
                                                'tenantUid': directory.tenant_uid,
                                                'userId': directory.id
                                            });
                                            reject(err);
                                        } else {
                                            directoryIndex += 1;
                                            log.info('LDAP callback error : ', JSON.stringify(err) + ' for conection details :' + JSON.stringify(_.omit(options, ['bindCredentials', 'searchAttributes', 'timeout', 'connectTimeout', 'tlsOptions'])), {
                                                'tenantUid': directory.tenant_uid,
                                                'userId': directory.id
                                            });
                                            return callback();
                                        }
                                    }
                                });
                            },
                            function (err) {
                                if (err) {
                                    reject();
                                }
                                reject();
                            });
                    } else {
                        return next(null, false, new errors.Unauthorized(null, 1001));
                    }
                });
        });
    }

    passport.use(new JWTStrategy({
            jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
            algorithms: [JWT_ALGORITHM, 'HS256'],
            //secretOrKey: PUBLIC_KEY,
            secretOrKeyProvider: function (req, rawJwtToken, done) {
                // Decode token to identify which algorithm is used for signing the token.(Only required in case of old EAT as a fallback option, which are sign using single secretkey)
                var decoded = jwt.decode(rawJwtToken, {
                    complete: true
                });
                if (decoded && decoded.header) {
                    let secretKey = '';
                    if (decoded.header.alg == 'ES256') { // for this algorithm we have public & private key pair
                        secretKey = PUBLIC_KEY;
                    } else if (decoded.header.alg == 'HS256') { // for this algorithm we have single secret Key(for old EAT fallback)
                        secretKey = JWT_SECRET;
                    }
                    let bearerToken = (req.headers.authorization).split('Bearer ');
                    if (bearerToken.length && bearerToken.length > 1) {
                        jwt.verify(bearerToken[1], secretKey, {
                            algorithms: [JWT_ALGORITHM, 'HS256'],
                            ignoreExpiration: true
                        }, function (err, verified) {
                            if (err) {
                                log.error(`Error while verifying JWT Token with algorithm ${decoded.header.alg} : ${err.message}`, {
                                    'tenantUid': req.host
                                });
                                done(err, null);
                            } else {
                                done(null, secretKey);
                            }
                        });
                    } else {
                        log.error("Error while extracting JWT Bearer Token from headers", {
                            'tenantUid': req.host
                        });
                        let error = new errors.Unauthorized(null, 1001);
                        done(error, null);
                    }
                } else {
                    log.error("Error while decoding JWT Token", {
                        'tenantUid': req.host
                    });
                    let error = new errors.Unauthorized(null, 1001);
                    done(error, null);
                }
            },
            ignoreExpiration: true,
            passReqToCallback: true // allows us to pass back the entire request to the callback
        },
        function (req, jwtPayload, next) {
            var currentTime = Math.floor(new Date().getTime() / 1000); // get current time in seconds
            if (currentTime > jwtPayload.exp) {
                // delete entry from db if token is expired
                db.gammaDbPool.query(`delete from token where id=$1`, [jwtPayload.id], next)
                    .then(() => {
                        return next(new errors.Unauthorized("Embold Token Expired", 1005));
                    });
            } else {
                sqlQuery = `select metadata, token_type from token where id=$1`;
                db.gammaDbPool.query(sqlQuery, [jwtPayload.id], next)
                    .then(data => {
                        //Apply rate limiter on exposed REST API or GAT consumers
                        //if (data.length && data[0].token_type === 'private') {
                        app.set('trust proxy', 1);
                        app.use("/api/", rateLimitConfig);
                        //}
                        if (data.length) {

                            // getting subdomain for a given request
                            let subdomain = '';
                            subdomain = licenseService.getSubdomain(req.subdomains);
                            if (data[0].metadata.subdomain == subdomain) {
                                req.session = {};
                                req.session = data[0].metadata;
                                req.session.has_scanned = (typeof req.session.has_scanned !== 'undefined') ? req.session.has_scanned : false;
                                req.session.tokenId = jwtPayload.id;
                                req.session.tokenType = data[0].token_type;

                                if (data[0].token_type == 'private') {
                                    let sqlQueryUpdate = 'UPDATE token SET updated_on = now() where id=$1;'
                                    db.gammaDbPool.query(sqlQueryUpdate, [jwtPayload.id], next)
                                        .then(function () {
                                            return getUserListData(req, next)
                                                .then(userListData => {
                                                    if (userListData[0].status != 1) {
                                                        return next(new errors.Unauthorized("Inactive User", 1002));
                                                    } else {
                                                        return next(null, jwtPayload.id);
                                                    }
                                                });
                                        });
                                } else {
                                    if (req.headers.x_referral != undefined && req.headers.x_referral == 'embold-try-it') {
                                        return next(new errors.Unauthorized("User token is not supported. Use 'Embold Access Token'", 1002));
                                    } else {
                                        return next(null, jwtPayload.id);
                                    }
                                }
                            } else {
                                return next(new errors.Forbidden(null, 1007));
                            }
                        } else {
                            return next(null, false);
                        }
                    });
            }
        }
    ));

    function getUserListData(req, next) {
        let userListQuery = `select status from users where id = $1`;
        return db.gammaDbPool.query(userListQuery, [req.session.user_id], next)
            .then(data => {
                return data;
            });
    }

    function userLogin(subdomain, user, next) {
        var currentUser = [];

        if (subdomain.includes(gammaConfig.gamma_os_postfix)) {
            _.each(user, d => {
                if (d.is_trial)
                    currentUser.push(d);
            });
        } else {
            _.each(user, d => {
                if (!d.is_trial)
                    currentUser.push(d);
            });
        }

        if (currentUser.length > 0) {
            // store all the required data in payload instead of storing it in session
            var metadata = {
                user_id: currentUser[0].id,
                user_email: currentUser[0].email,
                tenant_id: currentUser[0].tenant_id,
                tenant_uid: currentUser[0].tenant_uid,
                tenant_name: currentUser[0].tenant_name,
                first_name: currentUser[0].first_name,
                last_name: currentUser[0].last_name,
                user_name: `${currentUser[0].first_name} ${currentUser[0].last_name}`,
                user_image: currentUser[0].image,
                is_primary: currentUser[0].is_primary,
                subdomain: currentUser[0].subdomain,
                is_trial: currentUser[0].is_trial
            };

            if (currentUser[0].first_login === null) {
                metadata.first_login = new Date();
                metadata.last_login = new Date();
            } else {
                metadata.first_login = new Date(currentUser[0].first_login);
                metadata.last_login = new Date();
            }

            var payload = {
                'id': new Date().getTime()
            };

            // storing user roles in payload
            sqlQuery = `(select identifier, role_id from role, users_role where role.id = users_role.role_id and users_role.user_id=$1)UNION
                                    (select identifier, role_id from role, user_project where role.id = user_project.role_id and user_project.user_id = $1)
                                    `;
            db.gammaDbPool.query(sqlQuery, [currentUser[0].id], next)
                .then(data => {
                    metadata.user_roles = _.pluck(data, 'identifier');
                    // storing user permissions in payload
                    sqlQuery = `select
                            distinct(p.identifier)
                            from role_permission rp inner join
                            ((select identifier, role_id from role, users_role where role.id = users_role.role_id and users_role.user_id = $1) UNION
                            (select identifier, role_id from role, user_project where role.id = user_project.role_id and user_project.user_id = $1)) a
                            on rp.role_id=a.role_id
                            inner join permissions p
                            on p.id=rp.permission_id`;
                    db.gammaDbPool.query(sqlQuery, [currentUser[0].id], next)
                        .then(data => {
                            metadata.user_permissions = _.pluck(data, 'identifier');

                            // storing user roles repository in payload
                            sqlQuery = `select sub.subsystem_uid as repository_uid, r.identifier as role_identifier, up.project_id , array_agg(p.identifier) as permissions
                                from user_project up , project_subsystem ps, subsystems sub,role r, role_permission rp, permissions p
                                where up.project_id = ps.project_id
                                and r.id = rp.role_id
                                and rp.permission_id = p.id
                                and ps.subsystem_id = sub.subsystem_id
                                and up.role_id = r.id
                                and up.user_id= $1
                                and up.tenant_id = $2
                                group by 1,2,3`;
                            db.gammaDbPool.query(sqlQuery, [currentUser[0].id, currentUser[0].tenant_id], next)
                                .then(data1 => {
                                    metadata.user_subsystem_roles = data1;
                                    // creating jwt token for further authentication
                                    var jwttoken = jwt.sign(payload, PRIVATE_KEY, {
                                        algorithm: JWT_ALGORITHM,
                                        expiresIn: tokenExpiryTime //(seconds) expires in 24 hours
                                    });

                                    //store jwttoken in token table for further authentication
                                    sqlQuery = `insert into token(id,token,tenant_uid,token_type,metadata,created_on,updated_on) values($1,$2,$3,$4,$5,now(),now())`;
                                    db.gammaDbPool.query(sqlQuery, [payload.id, jwttoken, currentUser[0].tenant_uid, 'user', metadata], next)
                                        .then(data => {
                                            runCoronaMigration(currentUser[0]).then(() => {
                                                updateLoginDetails(currentUser[0], next);
                                                return next(null, {
                                                    'token': jwttoken
                                                });
                                            });

                                        });
                                });
                        });
                });
        } else {
            return next(new errors.Unauthorized("Invalid Subdomain", 1004));
        }
    }

    // Configure the Bearer strategy for use by Passport.
    passport.use(new BearerStrategy(
        function (token, done) {
            //Check token is present in app whitelist
            let isAppToken = _.find(appTokenWhitelist, function (x) {
                return x.access_token == token;
            });
            if (typeof isAppToken !== 'undefined') {
                //Apply rate limiter on exposed REST API or GAT consumers
                // app.use("/api/v1/", rateLimitConfig);
                return done(null, token, {
                    scope: 'all'
                });
            } else {
                return done(null, false);
            }
        }));

    passport.use(new ClientPasswordStrategy(
        function (clientId, clientSecret, done) {
            console.log('clientId, clientSecret======', clientId, clientSecret);
            Clients.findOne({
                clientId: clientId
            }, function (err, client) {
                if (err) {
                    console.log('error=========', err);
                    return done(err);
                }
                if (!client) {
                    console.log('client=====', client);
                    return done(null, false);
                }
                if (client.clientSecret != clientSecret) {
                    console.log('client=====', client);
                    console.log(client.clientSecret);
                    console.log(clientSecret);
                    return done(null, false);
                }
                return done(null, client);
            });
        }
    ));


    // License agent strategy
    passport.use(new BearerStrategy(
        function (token, done) {
            return done(null, token, {
                scope: 'all'
            });
        }));

    function runCoronaMigration(userData) {
        log.info('Checking for corona migration', {
            'tenantUid': userData.tenant_uid,
            'userId': userData.id
        });
        sqlQuery = `select corona_migration_status from tenant where tenant_uid=$1`;
        let migrationData = {
            currentStatus: 0,
            additionalDetails: {
                updated_on: '',
                info: ''
            }
        }
        return db.gammaDbPool.query(sqlQuery, [userData.tenant_uid])
            .then(response => {
                if (response[0].corona_migration_status == 0) {
                    log.info('Starting corona migration', {
                        'tenantUid': userData.tenant_uid,
                        'userId': userData.id
                    });
                    migrationData.currentStatus = 1;
                    migrationData.additionalDetails.info = "Corona schema migration inprogress";
                    migrationData.additionalDetails.updated_on = new Date();
                    return updateCoronaMigrationStatus(userData.tenant_uid, migrationData).then(() => {
                        let req = {
                            gamma: null,
                            tenant_uid: userData.tenant_uid
                        }
                        return db.runCoronaMigration(req).then(() => {
                            log.info('Corona migration successfully completed', {
                                'tenantUid': userData.tenant_uid,
                                'userId': userData.id
                            });
                            migrationData.currentStatus = 2;
                            migrationData.additionalDetails.info = "Corona schema migrated successfully";
                            migrationData.additionalDetails.updated_on = new Date();
                            return updateCoronaMigrationStatus(userData.tenant_uid, migrationData);
                        }).catch(error => {
                            log.error('Corona migration failed', {
                                'tenantUid': userData.tenant_uid,
                                'userId': userData.id
                            });
                            migrationData.currentStatus = 0;
                            migrationData.additionalDetails.updated_on = new Date();
                            migrationData.additionalDetails.info = error;
                            return updateCoronaMigrationStatus(userData.tenant_uid, migrationData);
                        });
                    });
                } else if (response[0].corona_migration_status == 1) {
                    log.info('Corona migration is inprogress', {
                        'tenantUid': userData.tenant_uid,
                        'userId': userData.id
                    });
                    return new Promise((resolve) => {
                        setTimeout(resolve, CORONA_MIGRATION_STATUS_CHECK_TIMER);
                    }).then(() => {
                        return runCoronaMigration(userData);
                    });
                }
            });
    }

    var updateCoronaMigrationStatus = function (tenant_uid, data) {
        return db.gammaDbPool.query(`
        update tenant set corona_migration_status=$1,
        corona_migration_additional_details=$2 where tenant_uid=$3`,
            [data.currentStatus, data.additionalDetails, tenant_uid]).then({})
    }

    function updateLoginDetails(userData, next) {
        // Update license with +1 user only once when first login empty or null
        if (userData.first_login === null) {

            if (!userData.is_primary && userData.directory_type == 'external') {
                let requestBody = {
                    tenant_uid: userData.tenant_uid,
                    log: "1 user added with email: " + (cf.parseString(userData.email)).toLowerCase(),
                    metrics: [{
                        metric: "users",
                        value: 1
                    }]
                };
                licenseService.updateUsage(requestBody);
            }

            sqlQuery = `update users set first_login=now(), last_login=now(), status=1 where id=$1`;

        } else {
            sqlQuery = `update users set last_login=now() where id=$1`;
        }
        db.gammaDbPool.query(sqlQuery, [userData.id], next)
            .then(response => {
                return response;
            });
    }

    //get external user details with username and specific directory
    function externalUserDetails(username, subdomain, next, directoryId = 0) {
        let directoryCheckQuery = '';
        let defaultparams = [(cf.parseString(username)).toLowerCase(), subdomain, 'external'];
        if (directoryId !== 0) {
            directoryCheckQuery = 'and tenant_directory.id= $4';
            defaultparams.push(directoryId);
        }
        sqlQuery = `select users.*,users.status as user_status, tenant.tenant_uid as tenant_uid, tenant.subdomain,tenant_directory.directory_type from users,tenant,tenant_directory where users.tenant_id=tenant.id and users.directory_id=tenant_directory.id and email=$1 and tenant.subdomain = $2 and tenant_directory.directory_type = $3 ${directoryCheckQuery}`;

        return db.gammaDbPool.query(sqlQuery, defaultparams, next);
    }

    function insertExternalUserDetails(tenantId, username, ldapFirstName, ldapLastName, ldapDirectoryId, ldapExternalId, next) {
        sqlQuery = `do $$
            begin
            insert into users (tenant_id, email, first_name,last_name,image,updated_dt,created_dt,directory_id,status,external_id) values
            (${tenantId},'${cf.parseString(username)}','${cf.parseString(ldapFirstName)}','${cf.parseString(ldapLastName)}','',now(),now(),'${ldapDirectoryId}',1,'${ldapExternalId}');
            insert into users_role(user_id, role_id) values((select id from users where email = '${cf.parseString(username)}' AND directory_id= '${ldapDirectoryId}' ), 6);
            end;
            $$;`;
        return db.gammaDbPool.query(sqlQuery, [], next);
    }

    // update external user details
    function updateUserData(updateUserObject, next) {
        let firstName = (updateUserObject.ldapFirstName !== null && updateUserObject.ldapFirstName !== undefined) ? updateUserObject.ldapFirstName : '';
        let lastName = (updateUserObject.ldapLastName !== null && updateUserObject.ldapLastName !== undefined) ? updateUserObject.ldapLastName : '';
        let ldapEmail = (updateUserObject.ldapEmail !== null && updateUserObject.ldapEmail !== undefined) ? updateUserObject.ldapEmail : '';
        let externalId = (updateUserObject.externalId !== null && updateUserObject.externalId !== undefined) ? updateUserObject.externalId : '';
        sqlQuery = "update users set first_name =$1, last_name=$2,email=$3, updated_dt = now() where external_id = $4";
        return db.gammaDbPool.query(sqlQuery, [firstName, lastName, ldapEmail, externalId], next);
    }

    function formatGUID(objectGUID) {
        var data = new Buffer(objectGUID, 'binary');
        // GUID_FORMAT_D
        var template = '{3}{2}{1}{0}-{5}{4}-{7}{6}-{8}{9}-{10}{11}{12}{13}{14}{15}';

        // check each byte
        for (var i = 0; i < data.length; i++) {
            // get the current character from that byte
            var dataStr = data[i].toString(16);
            dataStr = data[i] >= 16 ? dataStr : '0' + dataStr;
            // insert that character into the template
            template = template.replace(new RegExp('\\{' + i + '\\}', 'g'), dataStr);
        }

        return template;
    }
};
module.exports.PRIVATE_KEY = PRIVATE_KEY;
module.exports.PUBLIC_KEY = PUBLIC_KEY;
module.exports.JWT_ALGORITHM = JWT_ALGORITHM;