const http=require('http'),fs=require('fs'),path=require('path'),https=require('https');
const SUPA='ftxttdagpioieyzaijdc.supabase.co';
const KEY='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZ0eHR0ZGFncGlvaWV5emFpamRjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzQ1MTc1MTAsImV4cCI6MjA5MDA5MzUxMH0.QQwoyo370gaDi-5I0DRJuHJtSa6FG6EFbJ1_QdR9u1g';
const DIR='C:\\Users\\Admin\\Desktop\\PARTENAIRE-Dozie.  Files';
http.createServer((req,res)=>{
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization,apikey,Prefer,Accept');
  if(req.method==='OPTIONS'){res.writeHead(200);res.end();return;}
  if(req.url.startsWith('/api/')){
    const p='/rest/v1/'+req.url.slice(5);
    let body='';
    req.on('data',c=>body+=c);
    req.on('end',()=>{
      const o={hostname:SUPA,path:p,method:req.method,headers:{apikey:KEY,'Authorization':'Bearer '+KEY,'Content-Type':'application/json','Prefer':req.headers['prefer']||'return=representation'}};
      const pr=https.request(o,r=>{res.writeHead(r.statusCode,{'Content-Type':'application/json','Access-Control-Allow-Origin':'*'});r.pipe(res);});
      pr.on('error',e=>{res.writeHead(500);res.end(JSON.stringify({error:e.message}));});
      if(body)pr.write(body);
      pr.end();
    });
    return;
  }
  let url=req.url.split('?')[0];
  if(url==='/'||url==='/admin')url='/PARTENAIRE_Admin (1).html';
  if(url==='/seller')url='/PARTENAIRE_Seller.html';
  if(url==='/buyer')url='/PARTENAIRE_Buyer.html';
  const f=path.join(DIR,url);
  fs.readFile(f,(e,d)=>{
    if(e){res.writeHead(404);res.end('Not found: '+url);return;}
    const mime={'.html':'text/html','.js':'text/javascript','.css':'text/css'};
    res.writeHead(200,{'Content-Type':mime[path.extname(f)]||'text/plain'});
    res.end(d);
  });
}).listen(8080,()=>{
  console.log('');
  console.log('=== PARTENAIRE SERVER READY ===');
  console.log('Admin:  http://localhost:8080/admin');
  console.log('Seller: http://localhost:8080/seller');
  console.log('Buyer:  http://localhost:8080/buyer');
  console.log('================================');
  console.log('');
});
