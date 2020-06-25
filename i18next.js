var logger = require('../utils/logger');
var log = logger.LOG;

module.exports = function (app) {

    var i18next = require('i18next');
    var middleware = require('i18next-express-middleware');
    var FilesystemBackend = require('i18next-node-fs-backend');
    var sprintf = require('i18next-sprintf-postprocessor');

    i18next
        .use(middleware.LanguageDetector)
        .use(FilesystemBackend)
        .use(sprintf)
        .init({
            // debug: true,
            'lng': 'en',
            'fallbackLng': 'en',
            backend: {
                loadPath: 'locales/' + '{{lng}}/translation.json'
            }
        });

    app.use(middleware.handle(i18next, {
        // ignoreRoutes: ["/foo"],
        removeLngFromUrl: false
    }));


    return i18next


};

// gamma.t("server.admin.")