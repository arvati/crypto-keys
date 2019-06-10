require('dotenv').config({path: './test/.env'});
const Mocha = require('mocha');
const mocha2md = require('./mocha2md')
const fsp = require('fs').promises;
const path = require('path');

const frontmatter = 
`---
layout: default
title: Example Tests
nav_order: 4
permalink: /example-tests
---
`
var mocha = new Mocha({
    reporter: mocha2md,
    reporterOptions: {
        quiet:true, 
        title:"Example Test Results", 
        toc:'kramdown', 
        filename:'tests2.md',
        prepend: frontmatter
    }
});

const testDir = "./test/"
fsp.readdir(testDir)
.then((files) => files.filter((file) => path.extname(file) === '.js_')
    .forEach( (file) => mocha.addFile(path.join(testDir, file)))
)
.then( () => new Promise((resolve,reject) => {
    var suiteRun = mocha.run( (failures) => resolve(failures,suiteRun.markdown))
}))
.then((markdown) => console.log('Resulted markdown could be used here'))
.catch((err) => console.log)
