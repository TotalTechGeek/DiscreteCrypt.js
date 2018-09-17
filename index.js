let DiscreteCrypt = require('./src/discretecrypt.js')


const crypto = require('crypto')
DiscreteCrypt.randomBytes = function(n)
{
    return crypto.randomBytes(n)
}

/*
// Efficient Native Implementation -- Need to write tests prior to adding it.
// The next step would be to add a new solution for more efficient big ints for Node 8.x
const scrypt = require('scrypt')
const DEFAULT_SCRYPT_CONFIG = DiscreteCrypt.defaults.scrypt()
DiscreteCrypt.utils.scryptPromise = function(key, salt, N, r, p, len)
{
    if (typeof key === "string")
    {
        key = Buffer.from(key.normalize('NFKC'))
    } 
    
    if (typeof salt === "string") salt = Buffer.from(salt, 'hex')

    N = N || DEFAULT_SCRYPT_CONFIG.N
    r = r || DEFAULT_SCRYPT_CONFIG.r
    p = p || DEFAULT_SCRYPT_CONFIG.p
    len = len || DEFAULT_SCRYPT_CONFIG.len

    return scrypt.hash(key, { N: N, r: r, p: p }, len, salt)
}
*/

module.exports = DiscreteCrypt