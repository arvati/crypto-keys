require('dotenv').config({path: './test/.env'});
const Mocha = require('mocha');
const fsp = require('fs').promises;
const path = require('path');

// link = https://github.com/mochajs/mocha/wiki/Third-party-reporters
var mocha = new Mocha({reporter:'Spec'});
var testDir = "./test/"
fsp.readdir(testDir)
.then((files) => {
    files.filter((file) => path.extname(file) === '.js')
    .forEach( (file) => {
        mocha.addFile(path.join(testDir, file));
    })
    mocha.run((failures) => {})
})
