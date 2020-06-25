var gammaConfig = require(process.cwd() + '/config/gamma-config');
var ip = require('ip');
var _ = require('underscore');
var __ = require('lodash');

var config = _.extend(gammaConfig);


// if(process.env.NODE_ENV=='production')
_.extend(config, process.env);

gammaConfig.port = gammaConfig.gamma_port;

if (process.env.dbPort) {
    config.dbPort = process.env.dbPort;
}

if (process.env.analysisDBDetails_dbPort) {
    config.analysisDBDetails.dbPort = process.env.analysisDBDetails_dbPort;
}

if (process.env.analysisDBDetails_dbName) {
    config.analysisDBDetails.dbName = process.env.analysisDBDetails_dbName;
}
if (process.env.analysisDBDetails_dbUsername) {
    config.analysisDBDetails.dbUsername = process.env.analysisDBDetails_dbUsername;
}
if (process.env.analysisDBDetails_dbPassword) {
    config.analysisDBDetails.dbPassword = process.env.analysisDBDetails_dbPassword;
}
if (process.env.analysisDBDetails_dbHostname) {
    config.analysisDBDetails.dbHostname = process.env.analysisDBDetails_dbHostname;
}

if (process.env.gamma_website_db_port) {
    config.websiteDBDetails.dbPort = process.env.gamma_website_db_port;
}
if (process.env.gamma_website_db_dbname) {
    config.websiteDBDetails.dbName = process.env.gamma_website_db_dbname;
}
if (process.env.gamma_website_db_username) {
    config.websiteDBDetails.dbUsername = process.env.gamma_website_db_username;
}
if (process.env.gamma_website_db_password) {
    config.websiteDBDetails.dbPassword = process.env.gamma_website_db_password;
}
if (process.env.gamma_website_db_hostname) {
    config.websiteDBDetails.dbHostname = process.env.gamma_website_db_hostname;
}
if (process.env.analysisDBDetails_analysisHost) {
    config.analysisDBDetails.analysisHost = process.env.analysisDBDetails_analysisHost;
}
if (process.env.analysisDBDetails_lpsHost) {
    config.analysisDBDetails.lpsHost = process.env.analysisDBDetails_lpsHost;
}
if (process.env.analysisDBDetails_data_dir) {
    config.analysisDBDetails.data_dir = process.env.analysisDBDetails_data_dir;
}
if (!config.selfHost) {
    config.selfHost = ip.address();
}
if (process.env.gamma_website_host) {
    config.gamma_website_host = process.env.gamma_website_host;
}
if (process.env.helpHost) {
    config.helpHost = process.env.helpHost;
}
if (process.env.languages) {
    var env_languages = process.env.languages
    config.languages = env_languages.split(',');
}
if (process.env.ssl_key) {
    config.ssl.key = process.env.ssl_key;
}
if (process.env.ssl_cert) {
    config.ssl.cert = process.env.ssl_cert;
}
if (process.env.ssl_port) {
    config.ssl.port = process.env.ssl_port;
}
if (process.env.ssl_passphrase) {
    config.ssl.passphrase = process.env.ssl_passphrase;
}
if (process.env.EMB_USE_NATIVE_PYPARSER == true || __.lowerCase(process.env.EMB_USE_NATIVE_PYPARSER) == 'true') {
    config.partial_languages = _.without(config.partial_languages, 'python');
}
/*if (process.env.license_host)
    config.license_host = process.env.license_host;*/

module.exports = config;