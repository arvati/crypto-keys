require('dotenv').config({path: './test/.env'});
const Mocha = require('mocha');
const jsdoc2md = require('jsdoc-to-markdown')
const mocha2md = require('./mocha2md')
const fsp = require('fs').promises;
const path = require('path');


// link = https://github.com/mochajs/mocha/wiki/Third-party-reporters
var mocha = new Mocha({
    reporter: mocha2md,
    reporterOptions: {quiet:true, title:"Unit Test Results", toc:'kramdown', filename:'tests.md'}
});

const docFile = './docs/readme.md'
const testDir = "./test/"
const withTests = false
fsp.readdir(testDir)
.then((files) => files.filter((file) => path.extname(file) === '.js')
    .forEach( (file) => mocha.addFile(path.join(testDir, file)))
)
.then( () => {
    const test = new Promise((resolve,reject)=>{
        var suiteRun = mocha.run( (failures) => {
            resolve(suiteRun.markdown)
        })
    })
    const doc = jsdoc2md.render({files: './lib/*.js'})
    return Promise.all([doc,test])
})
.then((values) => {
    const data = (withTests) ? values.join('\n') : values[0]
    return fsp.writeFile(docFile, data)
    .then(console.info('doc file created at ' + docFile))
})
