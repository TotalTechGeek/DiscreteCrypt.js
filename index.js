let DiscreteCrypt = require('./src/discretecrypt.node.js')

// The scrypt tuned down due to the random 256 bit key space.

// These are far, far less than the default parameters.
// There is little need for the Scrypt step when standard brute-force is less expensive. 
// The scrypt step is still somewhat valuable, due to the HMAC (used as salt) making it difficult
// to change anything.   
const scryptConfig = {
    N: 1 << 10,
    r: 4,
    p: 1,
    len: 32
}

Promise.all([
    DiscreteCrypt.Contact.create(null, null, scryptConfig),
    DiscreteCrypt.Contact.create(null, null, scryptConfig)
]).then(([
    jesse,
    jerry
]) =>
{
    DiscreteCrypt.exchange(jesse, jerry, { master: '12345678901234567890123456789012', organization_id: '1'}).then(data =>
    {
        console.log(JSON.stringify(data))
        DiscreteCrypt.open(jerry, data).then(console.log).catch(console.log)
    })
})