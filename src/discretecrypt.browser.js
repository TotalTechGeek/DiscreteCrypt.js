const scrypt = require('scrypt-async')
const bigInt = require('jsbn').BigInteger
const aesjs = require('aes-js')
const jsSHA = require('jssha')
const Buffer = require('buffer').Buffer

// Export everything.
global.Buffer = Buffer
global.jsSHA = jsSHA
global.bigInt = bigInt
global.aesjs = aesjs
global.DiscreteCrypt = require('./discretecrypt.js')(scrypt, bigInt, aesjs, jsSHA, Buffer)
