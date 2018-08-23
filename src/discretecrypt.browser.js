const scrypt = require('scrypt-async')
const bigInt = require('jsbn').BigInteger
const aesjs = require('aes-js')
const jsSHA = require('jssha')
const Buffer = require('buffer').Buffer

function bufferFunc(a, b)
{
    return Buffer.from(a, b)

}

global.DiscreteCrypt = require('./discretecrypt.js')(scrypt, bigInt, aesjs, jsSHA, bufferFunc)
