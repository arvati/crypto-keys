require('dotenv').config({path: './test/.env'});
const Mocha = require('mocha');
const jsdoc2md = require('jsdoc-to-markdown')
const fs = require('fs');
const path = require('path');

var originalWrite;
const stdout = [];
const output = [];
originalWrite = process.stdout.write;

process.stdout.write = function(str) {
    stdout.push(str);
};

echo = (msg, newline = true) => {
    if (newline) msg += '\n'
    output.push(msg)
}

// link = https://github.com/mochajs/mocha/wiki/Third-party-reporters
//Mocha.utils.inherits(MyReporter, Mocha.reporters.Markdown)

var mocha = new Mocha({
    reporter: 'Markdown'
});


var testDir = "./test/"
fs.readdirSync(testDir)
    .filter((file) => path.extname(file) === '.js')
    .forEach( (file) => {
        if (path.basename(__filename) !== file) mocha.addFile(path.join(testDir, file));
    });

mocha.run((failures) => {
        process.stdout.write = originalWrite
        echo('Failures: ' + failures)
        console.log(output.join(''))
        process.exitCode = failures ? 1 : 0;
    })
    .on('test', (test) => {
        echo('Test: '+test.title, false);
    })
    .on('test end', (test) => {
        echo(' !');
    })
    .on('pass', (test) => {
        echo(' : passed', false);
        //console.log(test);
    })
    .on('fail', (test, err) => {
        echo(' : failled', false);
        //console.log(test);
        //console.log(err);
    })
    .on('end', () => {
        echo('All done');
    });



// link = https://github.com/jsdoc2md/jsdoc-to-markdown/blob/master/docs/API.md#jsdoc2mdrenderoptions--promise
jsdoc2md.render({files: 'lib/*.js'})
    .then((rendered) => {
        // link = https://nodejs.org/api/fs.html#fs_fs_writefile_file_data_options_callback
        fs.writeFile('./docs/readme.md',rendered.concat('<hr>\n', stdout.join('')), (err) => {if (err) throw err})
    })

