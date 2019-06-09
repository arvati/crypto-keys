// https://github.com/mochajs/mocha/wiki/Third-party-reporters
// https://github.com/mochajs/mocha/blob/master/lib/reporters/markdown.js

/**
@module mocha2md
*/
/**
Module dependencies.
*/

const fs = require('fs');
const path = require('path');
const mocha = require('mocha');
const Base = mocha.reporters.Base;
const utils = mocha.utils;
const color = Base.color;


/**
Constants
*/
const SUITE_PREFIX = '$';
const constants = mocha.Runner.constants;
const EVENT_RUN_END = constants.EVENT_RUN_END;
const EVENT_SUITE_BEGIN = constants.EVENT_SUITE_BEGIN;
const EVENT_SUITE_END = constants.EVENT_SUITE_END;
const EVENT_TEST_PASS = constants.EVENT_TEST_PASS;
const EVENT_TEST_FAIL = constants.EVENT_TEST_FAIL;
const EVENT_TEST_PENDING = constants.EVENT_TEST_PENDING;
const EVENT_HOOK_BEGIN = constants.EVENT_HOOK_BEGIN;


/**
Constructs a new `mocha2md` reporter instance.
@public
@class
@memberof Mocha.reporters
@extends Mocha.reporters.Base
@param {Runner} runner - Instance triggers reporter actions.
@param {Object} [options] - runner options
*/
class mocha2md extends Base {
    constructor (runner, options) {

        // Set the config options
        const config = conf(options);

        // Reporter options
        const reporterOptions = Object.assign({}, (options.reporterOptions || {}),{
            title: config.title,
            filename: config.filename,
            path: config.path,
            quiet: config.quiet,
            level: config.level
        });
        
        super(runner, options);
        var self = this;

        var buf = ''
        var level = reporterOptions.level

        const title = (str, level) => Array(level).join('#') + ' ' + str + '\n';
        const mapTOC = (suite, obj) => {
            var ret = obj;
            var key = SUITE_PREFIX + suite.title;
            obj = obj[key] = obj[key] || { suite: suite };
            suite.suites.forEach((suite) => {mapTOC(suite, obj)});
            return ret;
        }
        const stringifyTOC = (obj, level) => {
            ++level;
            var buf = '';
            var link;
            for (var key in obj) {
            if (key === 'suite') {
                continue;
            }
            if (key !== SUITE_PREFIX) {
                link = ' - [' + key.substring(1) + ']';
                link += '(#' + utils.slug(obj[key].suite.fullTitle()) + ')\n';
                buf += Array(level).join('  ') + link;
            }
            buf += stringifyTOC(obj[key], level);
            }
            return buf;
        }
        const generateTOC = (suite) => {
            var obj = mapTOC(suite, {});
            return stringifyTOC(obj, reporterOptions.level) + '\n';
        }
        //generateTOC(runner.suite);
        runner.on(EVENT_SUITE_BEGIN, (suite) => {
            ++level;
            var slug = utils.slug(suite.fullTitle());
            buf += '<a name="' + slug + '"></a>' + '\n';
            buf += suite.root ? title(suite.title, level+1) :  title(suite.title, level);
        });
        runner.on(EVENT_TEST_PASS, (test) => {
            if (test.duration > 1000) {
                test.time = test.duration / 1000 + 's';
            } else {
                test.time = test.duration + 'ms'
            }
            const code = utils.clean(test.body);
            buf += test.title + ' ' + Base.symbols.ok + '.\n';
            buf += test.time + '.\n';
            buf += '\n```js\n';
            buf += code + '\n';
            buf += '```\n\n';
        });

        runner.on(EVENT_TEST_FAIL, (test, err) => {
            if (test.duration > 1000) {
                test.time = test.duration / 1000 + 's';
            } else {
                test.time = test.duration + 'ms'
            }
            const code = utils.clean(test.body);
            buf += test.title + ' ' + Base.symbols.err + '.\n';
            buf += test.time + '.\n';
            buf += '\n```js\n';
            buf += code + '\n';
            buf += '```\n\n';
        });

        runner.on(EVENT_TEST_PENDING, (test) => {
            const code = utils.clean(test.body);
            buf += test.title + '   - skipped' + '.\n';
            buf += test.time + '.\n';
            buf += '\n```js\n';
            buf += code + '\n';
            buf += '```\n\n';
        });

        runner.on(EVENT_SUITE_END, () => {
            --level;
        });
        runner.once(EVENT_RUN_END, () => {
            console.log(`mocha2md reporter options :`)
            console.log(` path: ${reporterOptions.path}`)
            console.log(` filename: ${reporterOptions.filename}`)
            console.log(` title: ${reporterOptions.title}`)
            console.log(` quiet: ${reporterOptions.quiet}`)
            console.log(` level: ${reporterOptions.level}`)
            const markdown = title(reporterOptions.title,reporterOptions.level+1) + generateTOC(runner.suite) + buf + '<hr>\n >';
            runner.markdown = markdown
            if (!reporterOptions.quiet) process.stdout.write(markdown) 
                else super.epilogue();
            if (reporterOptions.filename) fs.writeFile(path.join(reporterOptions.path,reporterOptions.filename),markdown, (err) => {if (err) throw err})
        });
    }
    //static get description() { return 'Markdown Report with super powers';}
}


/**
 * Retrieve the value of a user supplied option.
 * Falls back to `defaultValue`
 * Order of precedence
 *  1. User-supplied option
 *  2. Environment variable
 *  3. Default value
 *
 * @param {string} optToGet  Option name
 * @param {object} options  User supplied options object
 * @param {boolean} isBool  Treat option as Boolean
 * @param {string|boolean} defaultValue  Fallback value
 *
 * @return {string|boolean}  Option value
 */
const _getOption = (optToGet, options, isBool, defaultValue) => {
    const envVar = `MOCHA_${optToGet.toUpperCase()}`;
    if (options && typeof options[optToGet] !== 'undefined') {
        return (isBool && typeof options[optToGet] === 'string')
        ? options[optToGet] === 'true'
        : options[optToGet];
    }
    if (typeof process.env[envVar] !== 'undefined') {
        return isBool
        ? process.env[envVar] === 'true'
        : process.env[envVar];
    }
    return defaultValue;
}

const conf = function (opts) {
    // this comes from mocha test.js --reporter-options path=./,filename=report.md,level=0,quiet=true
    const reporterOpts = (opts && opts.reporterOptions) || {};
    // this comes from mocha test.js --report-path=./report.md --level 0 --quiet
    for (var i=0; i<process.argv.length; i++) {
        if (process.argv[i] == '--report-path' || process.argv[i] == '-p') {
            var list = process.argv[i+1].split('/');
            var temp_path = '';
            for (var i2=0; i2<list.length-1; i2++) {
                temp_path += list[i2] + '/';
            }
            if (!reporterOpts.filename) reporterOpts.filename = list[list.length-1];
            if (!reporterOpts.path) reporterOpts.path = temp_path;
        }
        if (process.argv[i] == '--quiet' || process.argv[i] == '-q') {
            if (!reporterOpts.quiet) reporterOpts.quiet = true;
        }
        if (process.argv[i] == '--level' || process.argv[i] == '-l') {
            if (!reporterOpts.level) reporterOpts.level = process.argv[i+1];
        }
        if (process.argv[i] == '--title' || process.argv[i] == '-t') {
            if (!reporterOpts.title) reporterOpts.title = process.argv[i+1];
        }
    }
    // Check environmental variables as 'export MOCHA_FILENAME=customReportFilename'
    return {
      quiet: _getOption('quiet', reporterOpts, true, false),
      path: _getOption('path', reporterOpts, false, './'),
      filename: _getOption('filename', reporterOpts, false, null),
      title: _getOption('title', reporterOpts, false, 'Unit Tests Results'),
      level: parseInt(_getOption('level', reporterOpts, false, '1'))
    };
};

/**
Expose `mocha2md`.
*/
exports = module.exports = mocha2md;