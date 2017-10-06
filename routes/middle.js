const cryptico = require("cryptico")
const b64 = require("js-base64").Base64
const rsaKey =exports.rsaKey = cryptico.generateRSAKey("k:psfg8@t90qu@gj:ojbi@sodoivcierw",512)
const pubKey =exports.pubKey = cryptico.publicKeyString(rsaKey)
const keys = exports.keys={}
exports.decrypter = (req,res,next)=>{
  const pk=keys[req.get("X-Publickey")];
  if(pk){
    req.userId=req.get("X-Publickey")
    req.decryptedBody=JSON.parse(b64.decode(cryptico.decryptAESCBC(req.body,pk)))
    res.encrypt=(json)=>{
      res.send(cryptico.encryptAESCBC(b64.encode(JSON.stringify(json)),pk))
    }
    next()
  }else{
    res.sendStatus(403).send({success:false})
  }
}
