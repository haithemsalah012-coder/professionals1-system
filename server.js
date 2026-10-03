const express=require('express');
const path=require('path');
const fs=require('fs');
const crypto=require('crypto');
const bcrypt=require('bcryptjs');
const Database=require('better-sqlite3');
const session=require('express-session');
const rateLimit=require('express-rate-limit');
const helmet=require('helmet');

const app=express();
const PORT=process.env.PORT||3000;
const DATA_DIR=process.env.DATA_DIR||path.join(__dirname,'data');
fs.mkdirSync(DATA_DIR,{recursive:true});
const db=new Database(path.join(DATA_DIR,'professional.db'));
db.pragma('journal_mode=WAL');
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,role TEXT NOT NULL,technician_name TEXT,code_hash TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY,name TEXT NOT NULL,phone TEXT,phone2 TEXT,gov TEXT,area TEXT,address TEXT,registrationDate TEXT,executionDate TEXT,service TEXT,units TEXT,price TEXT,tech TEXT,status TEXT NOT NULL,notes TEXT);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,action TEXT,order_id INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP);`);

const seed=[
 ['هيثم صلاح','المدير',null,'2601'],['احمد رشاد','خدمة العملاء',null,'2602'],['هيثم صلاح','خدمة العملاء',null,'2603'],
 ['هيثم صلاح','فني','هيثم صلاح','2604'],['سامح صلاح','فني','سامح صلاح','2605'],['احمد رشاد','فني','احمد رشاد','2606'],['اسلام رشاد','فني','اسلام رشاد','2607'],['مجدي محمد','فني','مجدي محمد','2608']
];
const ins=db.prepare('INSERT OR IGNORE INTO users(name,role,technician_name,code_hash) VALUES(?,?,?,?)');
for(const [name,role,tech,code] of seed){const exists=db.prepare('SELECT id FROM users WHERE name=? AND role=? AND COALESCE(technician_name,\'\')=COALESCE(?,\'\')').get(name,role,tech);if(!exists)ins.run(name,role,tech,bcrypt.hashSync(code,12));}

app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'200kb'}));
app.use(express.urlencoded({extended:false}));
app.use(session({secret:process.env.SESSION_SECRET||crypto.randomBytes(32).toString('hex'),resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:1000*60*60*12}}));
app.use('/api/login',rateLimit({windowMs:15*60*1000,max:30,standardHeaders:true,legacyHeaders:false}));

function auth(req,res,next){if(!req.session.user)return res.status(401).json({error:'غير مسجل الدخول'});next();}
function canStatus(u){return ['المدير','خدمة العملاء','فني'].includes(u.role)}
function canManageTech(u){return ['المدير','خدمة العملاء'].includes(u.role)}
function canDelete(u){return u.role==='المدير'}
function audit(u,action,orderId){db.prepare('INSERT INTO audit_log(user_id,action,order_id) VALUES(?,?,?)').run(u.id,action,orderId||null)}

app.post('/api/login',async(req,res)=>{const code=String(req.body.code||'').trim();if(!/^\d{4,20}$/.test(code))return res.status(400).json({error:'الكود غير صحيح'});const users=db.prepare('SELECT * FROM users').all();let found=null;for(const u of users){if(bcrypt.compareSync(code,u.code_hash)){found=u;break}}if(!found)return res.status(401).json({error:'الكود غير صحيح. حاول مرة أخرى.'});req.session.user={id:found.id,name:found.name,role:found.role,tech:found.technician_name};res.json(req.session.user)});
app.post('/api/logout',auth,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/me',auth,(req,res)=>res.json(req.session.user));

app.get('/api/orders',auth,(req,res)=>{let rows=db.prepare('SELECT * FROM orders ORDER BY id DESC').all();if(req.session.user.role==='فني')rows=rows.filter(o=>o.tech===req.session.user.tech);res.json(rows)});
app.post('/api/orders',auth,(req,res)=>{if(req.session.user.role==='فني')return res.status(403).json({error:'الفني لا يمكنه تسجيل أوردر جديد'});const b=req.body;const required=['name','phone','gov','area','address','executionDate','service','units','price'];for(const k of required)if(!String(b[k]??'').trim())return res.status(400).json({error:'يرجى استكمال البيانات المطلوبة'});const realId=db.prepare('SELECT COALESCE(MAX(id),999)+1 id FROM orders').get().id;const o={id:realId,name:String(b.name).trim(),phone:String(b.phone||''),phone2:String(b.phone2||''),gov:String(b.gov||''),area:String(b.area||''),address:String(b.address||''),registrationDate:new Date().toLocaleString('ar-EG'),executionDate:String(b.executionDate||''),service:String(b.service||''),units:String(b.units||''),price:String(b.price||''),tech:String(b.tech||''),status:'جديدة',notes:String(b.notes||'')};db.prepare(`INSERT INTO orders(id,name,phone,phone2,gov,area,address,registrationDate,executionDate,service,units,price,tech,status,notes) VALUES(@id,@name,@phone,@phone2,@gov,@area,@address,@registrationDate,@executionDate,@service,@units,@price,@tech,@status,@notes)`).run(o);audit(req.session.user,'create',o.id);res.json(o)});

app.patch('/api/orders/:id/status',auth,(req,res)=>{if(!canStatus(req.session.user))return res.status(403).json({error:'غير مسموح'});const id=Number(req.params.id),status=String(req.body.status||'');if(!['جديدة','تمت','مأجله','ملغي'].includes(status))return res.status(400).json({error:'حالة غير صحيحة'});const o=db.prepare('SELECT * FROM orders WHERE id=?').get(id);if(!o)return res.status(404).json({error:'الأوردر غير موجود'});if(req.session.user.role==='فني'&&o.tech!==req.session.user.tech)return res.status(403).json({error:'هذا الأوردر غير مسند إليك'});db.prepare('UPDATE orders SET status=? WHERE id=?').run(status,id);audit(req.session.user,'status:'+status,id);res.json({ok:true})});
app.patch('/api/orders/:id/technician',auth,(req,res)=>{if(!canManageTech(req.session.user))return res.status(403).json({error:'غير مسموح'});const id=Number(req.params.id),tech=String(req.body.tech||'');const allowed=['','هيثم صلاح','سامح صلاح','احمد رشاد','اسلام رشاد','مجدي محمد'];if(!allowed.includes(tech))return res.status(400).json({error:'فني غير صحيح'});if(!db.prepare('SELECT id FROM orders WHERE id=?').get(id))return res.status(404).json({error:'الأوردر غير موجود'});db.prepare('UPDATE orders SET tech=? WHERE id=?').run(tech,id);audit(req.session.user,'technician:'+tech,id);res.json({ok:true})});
app.delete('/api/orders/:id',auth,(req,res)=>{if(!canDelete(req.session.user))return res.status(403).json({error:'الحذف متاح للمدير فقط'});const id=Number(req.params.id);if(!db.prepare('SELECT id FROM orders WHERE id=?').get(id))return res.status(404).json({error:'الأوردر غير موجود'});db.prepare('DELETE FROM orders WHERE id=?').run(id);audit(req.session.user,'delete',id);res.json({ok:true})});

app.use(express.static(path.join(__dirname,'public')));
app.get(/.*/,(req,res)=>res.sendFile(path.join(__dirname,'index.html')));
app.listen(PORT,()=>console.log('Professional system running on port '+PORT));
