let DiscreteCrypt = require('./src/discretecrypt.js')

const crypto = require('crypto')
DiscreteCrypt.randomBytes = function(n)
{
    return crypto.randomBytes(n)
}
module.exports = DiscreteCrypt