require('dotenv').config({path: './test/.env'});
const Mocha = require('mocha');
const jsdoc2md = require('jsdoc-to-markdown')
const mocha2md = require('./mocha2md')
const fs = require('fs');
const path = require('path');


// link = https://github.com/mochajs/mocha/wiki/Third-party-reporters

var mocha = new Mocha({
    reporter: mocha2md,
    reporterOptions: {filename:'tests.md', path:'./docs/', quiet:true}
});


var testDir = "./test/"
fs.readdirSync(testDir)
    .filter((file) => path.extname(file) === '.js')
    .forEach( (file) => {
        if (path.basename(__filename) !== file) mocha.addFile(path.join(testDir, file));
    });


var suiteRun = mocha.run((failures) => {
    process.exitCode = failures ? 1 : 0;  // exit with non-zero status if there were failures
})

process.on('exit', (code) => {
    // Non-zero exit indicates errors.
    // link = https://github.com/jsdoc2md/jsdoc-to-markdown/blob/master/docs/API.md#jsdoc2mdrenderoptions--promise
    jsdoc2md.render({files: 'lib/*.js'})
    .then((rendered) => {
        // link = https://nodejs.org/api/fs.html#fs_fs_writefile_file_data_options_callback
        fs.writeFile('./docs/docs.md',rendered.concat('\n', suiteRun.markdown), (err) => {if (err) throw err})
    })
})



