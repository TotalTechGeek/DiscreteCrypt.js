// Node 10.x seems to run the tests ~4x quicker.

let DiscreteCrypt = require('./src/discretecrypt.js')

const crypto = require('crypto')
DiscreteCrypt.randomBytes = function(n)
{
    return crypto.randomBytes(n)
}

const DEFAULT_SCRYPT_CONFIG = DiscreteCrypt.defaults.scrypt()

// Efficient Native Implementation -- Need to write tests prior to adding it.
/* istanbul ignore if: this code actually has been tested, but I need to develop toggles */
if(crypto.scrypt)
{
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
    
        if(!Number.isInteger(len)) 
            return Promise.reject('Length is not a number.')    

        return new Promise((resolve, reject) =>
        {
            crypto.scrypt(key, salt, len, {
                N: N,
                r: r,
                p: p
            }, (err, derived) =>
            {
                if(err) return reject(err)
                return resolve(derived)
            })
        })
    }
}
module.exports = DiscreteCrypt