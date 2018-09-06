# DiscreteCrypt.js


[![Coverage Status](https://coveralls.io/repos/github/TotalTechGeek/DiscreteCrypt.js/badge.svg?branch=master)](https://coveralls.io/github/TotalTechGeek/DiscreteCrypt.js?branch=master) [![GitHub license](https://img.shields.io/github/license/TotalTechGeek/DiscreteCrypt.js.svg)](https://github.com/TotalTechGeek/DiscreteCrypt.js/blob/master/LICENSE)

A project for simple & secure data transmission.

## To Build (for browser)

Run the following commands:
```
npm i
npm run build
```

This will produce the necessary output.


## Dependencies

The following libraries were used:
- aes-js
- bn.js 
- buffer
- jsSHA
- scrypt-async

## Notes

This library can leverage the new proposal for [native BigInts](https://github.com/tc39/proposal-bigint) in JavaScript, achieving far greater performance.

At the time of writing, Chrome is the only browser with support for this proposal.
