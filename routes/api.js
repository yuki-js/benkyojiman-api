var express = require('express');
var router = express.Router();
const sqlite=require("sqlite3").verbose()
const cryptico = require("cryptico")
const middle=require("./middle.js")
const b64 = require("js-base64").Base64

const db=new sqlite.Database("./sqlite.db")

const rsaKey = middle.rsaKey
const pubKey = middle.pubKey
const keys = middle.keys

router.get('/', function(req, res, next) {
  res.send({message:"Benkyo Jiman API Server",pubKey})
});

router.post("/user/login",(req,res)=>{
  const decRes=cryptico.decrypt(req.body.cipher,rsaKey)
  if(decRes.status=="success"&&decRes.signature=="verified"){
    let keyAr=[]
    for(let i=0;i<decRes.plaintext.length;i+=2){
	    keyAr.push(parseInt(decRes.plaintext[i]+decRes.plaintext[i+1],16))
    }
    db.get("SELECT * FROM user WHERE userId=?",[decRes.publicKeyString],(err,row)=>{
      const aesEncrypted=(cryptico.encryptAESCBC(b64.encode(JSON.stringify({
        pubKey:decRes.publicKeyString,
        success:!err,
        name:(row&&row.name)?row.name:null,
        school:(row&&row.school)?row.school:null
      })),keyAr))

      keys[decRes.publicKeyString]=keyAr
      
      return res.send({cipher:aesEncrypted})
    })
  }else{
    res.send(403)
  }
})

router.post("/user/register",middle.decrypter,(req,res)=>{
  db.run("REPLACE INTO user VALUES(?,?,?)",[req.userId,req.decryptedBody.name,req.decryptedBody.school],(err)=>{
    if(err){throw err};
    res.encrypt({
      userId:req.userId,
      name:req.decryptedBody.name,
      school:req.decryptedBody.school,
      success:true
    })
  })
})

router.post("/user/info",middle.decrypter,(req,res)=>{//post is to encryption
  db.get("SELECT * FROM user where userId=?",[req.decryptedBody.userId],(err,rows)=>{
    if(err){
      return res.encrypt({success:false})
    }
    res.encrypt(rows||null)
  })
})
router.post("/user/info/test",middle.decrypter,(req,res)=>{//post is to encryption
  db.all("SELECT score.score,score.subject,score.testName FROM score where score.userId=?",[req.decryptedBody.userId],(err,rows)=>{
    if(err){
      return res.encrypt({success:false})
    }
    res.encrypt(rows||[])
  })
})

router.get("/test/:school",(req,res)=>{
  db.all("SELECT testName,deadline,subjects FROM tests WHERE school=? AND deadline > ?",[req.params.school,req.query.now|0],(err,rows)=>{
    if(err){
      return res.send({success:false})
    }
    res.send(rows||[])
  })
})
router.post("/test",middle.decrypter,(req,res)=>{
 
  db.run("REPLACE INTO tests (school,testName,deadline,subjects) SELECT school ,$testName,$deadline,$subjects FROM user WHERE userId=$userId",{
    $userId:req.userId,
    $testName:req.decryptedBody.testName,
    $subjects:req.decryptedBody.subjects,
    $deadline:req.decryptedBody.deadline|0
  },(err)=>{
    if(err){throw err};
    res.encrypt({
      success:true
    })
  
  })
})
router.post("/score",middle.decrypter,(req,res)=>{
  //  db.run("REPLACE INTO score VALUES($userId,(SELECT school FROM user WHERE userId=$userId),$testName,$subject,0)",{
  console.log(req.decryptedBody)
  db.run("REPLACE INTO score (userId,school,testName,score,subject,like) SELECT $userId,school ,$testName,$score,$subject,0 FROM user WHERE userId=$userId",{
    $userId:req.userId,$testName:req.decryptedBody.testName,$subject:req.decryptedBody.subject,$score:req.decryptedBody.score|0
  },(err)=>{
    if(err){throw err};
    res.encrypt({
      success:true
    })
  
  })
})
router.get("/score/:school/:testName",(req,res)=>{
  db.all("SELECT score.userId,user.name,score.score,score.subject,score.like from score inner join user on score.userId=user.userId where score.school=? and score.testName=? order by score DESC",[req.params.school,req.params.testName],(err,rows)=>{
    if(err){
      throw err
      return res.send({success:false})
    }
    res.send(rows||[])
  })
})

router.get("/bbs/:school",(req,res)=>{
  db.all("SELECT bbs.resId,bbs.sender,user.name,bbs.date,bbs.text,bbs.recipient FROM bbs INNER JOIN user on bbs.sender=user.userId WHERE bbs.school = ?",[req.params.school|0],(err,rows)=>{
    if(err){
      return res.send({success:false})
    }
    res.send(rows||[])
  })
})
router.post("/bbs/write",middle.decrypter,(req,res)=>{
  db.run("INSERT INTO bbs (sender,date,text,school,recipient) SELECT $sender,datetime('now'),$text,school,$recipient FROM user WHERE user.userId=$sender",{
    $sender:req.userId,
    $text:req.decryptedBody.text,
    $recipient:req.decryptedBody.recipient||""
  },(err)=>{
    if(err){throw err};
    res.encrypt({
      success:true
    })
  })
})

let telemetryData=[];
router.get("/telemetry",(req,res)=>{
  telemetryData.push(req.query.d);
  res.jsonp({ok:true,d:req.query.d})
})
router.get("/teleget",(req,res)=>{
  res.send(telemetryData)
})

module.exports = router;

db.serialize(()=>{
  db.exec(`
CREATE TABLE IF NOT EXISTS user(userId text PRIMARY KEY NOT NULL,name text not null,school int not null);
CREATE TABLE IF NOT EXISTS score(userId text not null,school int not null,
                                 testName text not null,score int not null,subject text not null,
                                 like int,
                                Primary key(userId,testName,school,subject));
create table if not exists tests(school int not null,testName text not null,deadline int not null,subjects text not null,primary key (school,testName));
CREATE TABLE IF NOT EXISTS bbs(sender TEXT NOT NULL, date DATETIME NOT NULL, text TEXT NOT NULL, school INT not null, recipient TEXT,resId INTEGER not null,PRIMARY KEY(school,resId));
`)
  
})

