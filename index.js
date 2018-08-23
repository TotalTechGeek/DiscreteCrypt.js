const bigInt = require('big-integer')
let DiscreteCrypt = require('./src/discretecrypt.node.js')

let params = {
    prime : new bigInt("1236027852723267358067496240415081192016632901798652377386974104662393263762300791015297301419782476103015366958792837873764932552461292791165884073898812814414137342163134112441573878695866548152604326906481241134560091096795607547486746060322717834549300353793656273878542405925895784382400028374603183267116520399667622873636417533621785188753096887486165751218947390793886174932206305484313257628695734926449809428884085464402485504798782585345665225579018127843073619788513405272670558284073983759985451287742892999484270521626583252756445695489268987027078838378407733148367649564107237496006094048593708959670063677802988307113944522310326616125731276572628521088574537964296697257866765026848588469121515995674723869067535040253689232576404893685613618463095967906841853447414047313021676108205138971649482561844148237707440562831931089544088821151806962538015278155763187487878945694840272084274212918033049841007502061", 10),
    gen : new bigInt(2)
}

// This is tuned down due to the random 256 bit key space.
const scryptConfig = {
    N: 1 << 10,
    r: 5,
    p: 1,
    len: 32
}


Promise.all([
    DiscreteCrypt.Contact.create(null, null, scryptConfig, params),
    DiscreteCrypt.Contact.create(null, null, scryptConfig, params)
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