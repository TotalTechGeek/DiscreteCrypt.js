const scrypt = require('scrypt-async')
const bigInt = require('jsbn').BigInteger
const aesjs = require('aes-js')
const jsSHA = require('jssha')

const crypto = require('crypto')
function randomBytes(n) 
{
    return crypto.randomBytes(n)
}

let DiscreteCrypt = require('./discretecrypt.js')(scrypt, bigInt, aesjs, jsSHA, Buffer, randomBytes)
module.exports = DiscreteCrypt