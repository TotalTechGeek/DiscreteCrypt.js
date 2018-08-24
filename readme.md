# DiscreteCrypt.js

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