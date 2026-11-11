require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const sql = require('mssql'); 
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); 
const nodemailer = require('nodemailer'); // 📧 ADDED FOR EMAIL NOTIFICATIONS
const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================================
// ⚠️ AUTH BYPASS SWITCH (FOR LOCAL TESTING ONLY)
// true  = no login needed (JWT check skipped, SSO check skipped)
// false = normal production authentication
// Controlled by .env:  DISABLE_AUTH=true   (defaults to true if not set)
// Optional .env:       DEV_EMP_ID=12345    (log in as a real user from tbl_Users)
// ⚠️ SET DISABLE_AUTH=false BEFORE GOING LIVE ⚠️
// ============================================================================
const DISABLE_AUTH = process.env.DISABLE_AUTH ? process.env.DISABLE_AUTH === 'true' : true;
const JWT_SECRET = process.env.JWT_SECRET || 'LNT_PRODUCTION_SECRET_KEY_REPLACE_ME_!@#';

const DEV_USER = {
    emp_id: process.env.DEV_EMP_ID || 'LOCAL_DEV_999',
    fname: 'Local',
    lname: 'Developer',
    email: 'local.dev@example.com',
    dob: null,
    plant: null,
    department: null,
    is_admin: true,
    is_hod: true,
    is_committee: true,
    is_coordinator: true,
    is_hok: true
};

if (DISABLE_AUTH) console.warn('⚠️⚠️  AUTH IS DISABLED (DISABLE_AUTH=true). Do NOT use this in production! ⚠️⚠️');

// 🔒 SECURITY FIX: Limit payload size to 5MB to prevent Denial of Service (DoS) memory crashes
app.use(express.json({ limit: '5mb' })); 

// 🔒 SECURITY FIX: Configured CORS
const corsOptions = {
    origin: process.env.ALLOWED_ORIGIN || '*', 
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

// --- FOLDERS ---
const UPLOADS_DIR = path.join(__dirname, 'public', 'uploads');
const GALLERY_DIR = path.join(__dirname, 'public', 'homePageImage');

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);
if (!fs.existsSync(GALLERY_DIR)) fs.mkdirSync(GALLERY_DIR);

// --- SQL DATABASE CONFIGURATION ---
const dbConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER, 
    database: process.env.DB_NAME,
    options: {
        encrypt: false, 
        trustServerCertificate: true, 
        enableArithAbort: true
    },
    port: 1433 
};

// --- ESTABLISH SQL CONNECTION & AUTO-BUILD MISSING TABLES ---
const poolPromise = new sql.ConnectionPool(dbConfig)
    .connect()
    .then(async pool => {
        console.log('✅ Connected to SQL Server (SSMS) successfully! (Secured for Production)');
        await pool.request().query(`
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='tbl_KaizenCategories' and xtype='U')
            CREATE TABLE tbl_KaizenCategories (KaizenID INT, CategoryName VARCHAR(255))
        `);
        return pool;
    })
    .catch(err => {
        console.error('❌ Database Connection Failed! Error: ', err.message);
    });

app.locals.db = poolPromise;

// ============================================================================
// 🧼 HTML ESCAPE HELPER (used in email templates)
// ============================================================================
const escapeHtml = (s) => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ============================================================================
// 📧 SMTP EMAIL CONFIGURATION & HELPERS
// ============================================================================
const transporter = nodemailer.createTransport({
    host: 'appmail.larsentoubro.com',
    port: 25,
    secure: false, // Internal IP relay does not use SSL on port 25
    tls: { rejectUnauthorized: false }
});

async function sendKaizenMail(toArr, ccArr, subject, htmlBody) {
    try {
        // Clean arrays and remove null/empty values
        const to = [...new Set((toArr || []).filter(e => e))];
        const cc = [...new Set((ccArr || []).filter(e => e))];

        if (to.length === 0) {
            console.log(`⚠️ Email skipped for [${subject}] - No 'TO' recipients found.`);
            return;
        }

        await transporter.sendMail({
            from: '"L&T Valves Kaizen Portal" <no-reply@larsentoubro.com>',
            to: to.join(','),
            cc: cc.join(','),
            subject: subject,
            html: `<div style="font-family: Arial, sans-serif; color: #1e293b; line-height: 1.6;">${htmlBody}</div>`
        });
        console.log(`✉️ Email sent successfully: ${subject}`);
    } catch (err) {
        console.error(`❌ Email Failed [${subject}]:`, err.message);
    }
}

// Fetches all relevant email addresses for a specific Kaizen
async function getKaizenEmails(pool, kaizenId) {
    const result = { theme: '', team: [], hod: [], comm: [], coord: [], hok: [] };
    try {
        const kRes = await pool.request().input('kID', sql.Int, kaizenId).query(`SELECT Theme, OnlineLeaderEmpID, OnlineCreatorEmpID, PlantID, DepartmentID FROM tbl_Kaizens WHERE KaizenID = @kID`);
        if(kRes.recordset.length === 0) return result;
        const k = kRes.recordset[0];
        result.theme = k.Theme;

        const tmRes = await pool.request().input('kID', sql.Int, kaizenId).query(`SELECT u.Email FROM tbl_KaizenTeamMembers tm JOIN tbl_Users u ON tm.OnlineEmpID = u.EmpID WHERE tm.KaizenID = @kID AND u.IsDeleted = 0 AND u.Email IS NOT NULL`);
        const clRes = await pool.request().input('lID', sql.VarChar, k.OnlineLeaderEmpID).input('cID', sql.VarChar, k.OnlineCreatorEmpID).query(`SELECT Email FROM tbl_Users WHERE EmpID IN (@lID, @cID) AND IsDeleted = 0 AND Email IS NOT NULL`);
        result.team = [...tmRes.recordset.map(r=>r.Email), ...clRes.recordset.map(r=>r.Email)];

        const hodRes = await pool.request().input('pID', sql.Int, k.PlantID).input('dID', sql.Int, k.DepartmentID).query(`SELECT Email FROM tbl_Users WHERE IsHOD = 1 AND PlantID = @pID AND DepartmentID = @dID AND IsDeleted = 0 AND Email IS NOT NULL`);
        result.hod = hodRes.recordset.map(r=>r.Email);

        const commRes = await pool.request().query(`SELECT Email FROM tbl_Users WHERE IsCommittee = 1 AND IsDeleted = 0 AND Email IS NOT NULL`);
        result.comm = commRes.recordset.map(r=>r.Email);

        const coordRes = await pool.request().query(`SELECT Email FROM tbl_Users WHERE IsCoordinator = 1 AND IsDeleted = 0 AND Email IS NOT NULL`);
        result.coord = coordRes.recordset.map(r=>r.Email);

        const hokRes = await pool.request().query(`SELECT Email FROM tbl_Users WHERE IsHOK = 1 AND IsDeleted = 0 AND Email IS NOT NULL`);
        result.hok = hokRes.recordset.map(r=>r.Email);

        return result;
    } catch(e) { console.error("Error fetching emails:", e); return result; }
}

// ============================================================================
// 🔒 SECURITY MIDDLEWARE (JWT GATEKEEPER)
// ============================================================================
function authenticateToken(req, res, next) {

    // ⚠️ LOCAL DEVELOPMENT BYPASS (controlled by DISABLE_AUTH at the top) ⚠️
    if (DISABLE_AUTH) {
        req.user = { ...DEV_USER };
        return next();
    }

    // --- PRODUCTION CODE ---
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    
    if (token == null) return res.status(401).json({ success: false, message: 'Unauthorized: Missing Security Token' });

    jwt.verify(token, JWT_SECRET, (err, userPayload) => {
        if (err) return res.status(403).json({ success: false, message: 'Forbidden: Invalid or Expired Token' });
        req.user = userPayload; 
        next(); 
    });
}

function requireAdmin(req, res, next) {
    if (DISABLE_AUTH) return next();
    if (!req.user || req.user.is_admin !== true) {
        return res.status(403).json({ success: false, message: 'Security Block: Administrator Privileges Required.' });
    }
    next();
}

// ============================================================================
// 🔒 SESSION VERIFICATION ENDPOINT
// ============================================================================
app.get('/verify-session', authenticateToken, (req, res) => {
    res.json({ success: true });
});

// --- HELPER FUNCTIONS ---
function saveFile(base64String, fileName, targetDir = UPLOADS_DIR) {
    if (!base64String) return null;
    const matches = base64String.match(/^data:([A-Za-z-+\/]+);base64,(.+)$/);
    if (!matches || matches.length !== 3) return null;

    const mimeType = matches[1];
    const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'application/pdf'];
    
    if (!allowedMimeTypes.includes(mimeType)) {
        console.error(`Blocked malicious file upload attempt. Invalid MIME Type: ${mimeType}`);
        return null;
    }

    const buffer = Buffer.from(matches[2], 'base64');
    const sanitizedFileName = fileName.replace(/[^a-zA-Z0-9.\-_]/g, '');
    const uniqueName = Date.now() + '_' + crypto.randomBytes(4).toString('hex') + '_' + sanitizedFileName;
    
    fs.writeFileSync(path.join(targetDir, uniqueName), buffer);
    return uniqueName;
}

function formatDateOnly(dateObj) {
    if (!dateObj) return null;
    const d = new Date(dateObj);
    if (isNaN(d.getTime())) return null; 
    const day = String(d.getDate()).padStart(2, '0');
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const year = d.getFullYear();
    return `${year}-${month}-${day}`;
}

function formatDateTime(dateObj) {
    if (!dateObj) return null;
    const d = new Date(dateObj);
    if (isNaN(d.getTime())) return null; 
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const day = String(d.getDate()).padStart(2, '0');
    const month = months[d.getMonth()];
    const year = d.getFullYear();
    let hours = d.getHours();
    const minutes = String(d.getMinutes()).padStart(2, '0');
    const ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12;
    hours = hours ? hours : 12; 
    return `${day} ${month} ${year}, ${hours}:${minutes} ${ampm}`;
}

function formatDateTable(dateObj) {
    if (!dateObj) return null;
    const d = new Date(dateObj);
    if (isNaN(d.getTime())) return null; 
    const day = String(d.getDate()).padStart(2, '0');
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const year = d.getFullYear(); 
    return `${year}-${month}-${day}`; 
}

const cleanNum = (val) => {
    if (val === null || val === undefined || val === '') return 0;
    if (typeof val === 'number') return val;
    const cleaned = val.toString().replace(/[^0-9.-]+/g, '');
    return parseFloat(cleaned) || 0;
};

const extractId = (str) => {
    if (!str) return null;
    const match = str.match(/\(([^)]+)\)/); 
    return match ? match[1].trim() : str.trim(); 
};

const formatName = (fname, lname, empId, offlineName) => {
    if (offlineName) return offlineName;
    if (!empId) return 'Unknown';
    return `${fname || ''} ${lname || ''}`.trim() + ` (${empId})`;
};

async function getFkId(pool, table, colName, idCol, value) {
    if (!value) return null;
    const res = await pool.request().input('val', sql.VarChar, value).query(`SELECT ${idCol} FROM ${table} WHERE ${colName} = @val AND IsDeleted = 0`);
    return res.recordset.length ? res.recordset[0][idCol] : null;
}

async function logAudit(action, module_name, record_id, action_by) {
    try {
        const pool = await app.locals.db;
        await pool.request()
            .input('action', sql.VarChar, action)
            .input('module', sql.VarChar, module_name)
            .input('record_id', sql.VarChar, String(record_id))
            .input('action_by', sql.VarChar, action_by || 'System')
            .query(`INSERT INTO tbl_AuditLogs (ActionType, ModuleName, RecordID, ActionByEmpID) VALUES (@action, @module, @record_id, @action_by)`);
    } catch (err) {}
}

// ============================================================================
// 1. MASTER SETTINGS 
// ============================================================================
app.get('/get-settings', authenticateToken, async (req, res) => {
    try {
        const pool = await app.locals.db;
        const plants = await pool.request().query('SELECT PlantName as name, Latitude as lat, Longitude as lng FROM tbl_Plants WHERE IsDeleted = 0');
        const depts = await pool.request().query('SELECT DepartmentName as name FROM tbl_Departments WHERE IsDeleted = 0');
        const groups = await pool.request().query('SELECT GroupName as name FROM tbl_ProductGroups WHERE IsDeleted = 0');
        const cats = await pool.request().query('SELECT CategoryName as name FROM tbl_Categories WHERE IsDeleted = 0');
        const focus = await pool.request().query('SELECT FocusName as name, Multiplier as mult FROM tbl_FocusAreas WHERE IsDeleted = 0');
        const processes = await pool.request().query('SELECT ProcessName as name FROM tbl_Processes WHERE IsDeleted = 0');

        res.json([
            { type: 'plant', values: plants.recordset },
            { type: 'dept', values: depts.recordset.map(r => r.name) },
            { type: 'group', values: groups.recordset.map(r => r.name) },
            { type: 'category', values: cats.recordset.map(r => r.name) },
            { type: 'focus', values: focus.recordset },
            { type: 'process', values: processes.recordset.map(r => r.name) }
        ]);
    } catch (err) { res.status(500).json([]); }
});

app.post('/add-setting', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { type, value, action_by } = req.body;
        const pool = await app.locals.db;
        const reqSql = pool.request().input('createdBy', sql.VarChar, action_by || 'System');
        let query = ''; let valName = typeof value === 'object' ? value.name : value;
        let table = '', col = '', idCol = '';

        if (type === 'plant') { table = 'tbl_Plants'; col = 'PlantName'; idCol = 'PlantID'; }
        else if (type === 'focus') { table = 'tbl_FocusAreas'; col = 'FocusName'; idCol = 'FocusID'; }
        else if (type === 'dept') { table = 'tbl_Departments'; col = 'DepartmentName'; idCol = 'DepartmentID'; }
        else if (type === 'group') { table = 'tbl_ProductGroups'; col = 'GroupName'; idCol = 'GroupID'; }
        else if (type === 'category') { table = 'tbl_Categories'; col = 'CategoryName'; idCol = 'CategoryID'; }
        else if (type === 'process') { table = 'tbl_Processes'; col = 'ProcessName'; idCol = 'ProcessID'; }

        const check = await pool.request().input('name', sql.VarChar, valName).query(`SELECT IsDeleted FROM ${table} WHERE ${col} = @name`);
        if (check.recordset.length > 0) {
            if (check.recordset[0].IsDeleted == 0 || check.recordset[0].IsDeleted === false) {
                return res.json({ success: false, message: 'This item already exists and is active.' });
            } else {
                let restoreQuery = `UPDATE ${table} SET IsDeleted = 0, UpdatedBy = @createdBy, UpdatedOn = GETDATE()`;
                if (type === 'plant') {
                    restoreQuery += `, Latitude = @lat, Longitude = @lng`;
                    reqSql.input('lat', sql.Decimal(10,6), value.lat).input('lng', sql.Decimal(10,6), value.lng);
                } else if (type === 'focus') {
                    restoreQuery += `, Multiplier = @mult`;
                    reqSql.input('mult', sql.Decimal(4,2), value.mult);
                }
                restoreQuery += ` WHERE ${col} = @name`;
                
                reqSql.input('name', sql.VarChar, valName);
                await reqSql.query(restoreQuery);
                logAudit('RESTORE', `SETTING_${type}`, valName, action_by);
                return res.json({ success: true });
            }
        }

        reqSql.input('name', sql.VarChar, valName);
        if (type === 'plant') {
            query = `INSERT INTO tbl_Plants (PlantName, Latitude, Longitude, CreatedBy) VALUES (@name, @lat, @lng, @createdBy)`;
            reqSql.input('lat', sql.Decimal(10,6), value.lat).input('lng', sql.Decimal(10,6), value.lng);
        } else if (type === 'focus') {
            query = `INSERT INTO tbl_FocusAreas (FocusName, Multiplier, CreatedBy) VALUES (@name, @mult, @createdBy)`;
            reqSql.input('mult', sql.Decimal(4,2), value.mult);
        } else if (type === 'dept') {
            query = `INSERT INTO tbl_Departments (DepartmentName, CreatedBy) VALUES (@name, @createdBy)`; 
        } else if (type === 'group') {
            query = `INSERT INTO tbl_ProductGroups (GroupName, CreatedBy) VALUES (@name, @createdBy)`; 
        } else if (type === 'category') {
            query = `INSERT INTO tbl_Categories (CategoryName, CreatedBy) VALUES (@name, @createdBy)`; 
        } else if (type === 'process') {
            query = `INSERT INTO tbl_Processes (ProcessName, CreatedBy) VALUES (@name, @createdBy)`; 
        }
        await reqSql.query(query);
        logAudit('CREATE', `SETTING_${type}`, valName, action_by);
        res.json({ success: true });
    } catch (err) { 
        let friendlyMsg = "Database error occurred.";
        if(err.number === 2627) friendlyMsg = 'An item with this name already exists.';
        res.json({ success: false, message: friendlyMsg }); 
    }
});

app.post('/delete-setting', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { type, value, action_by } = req.body;
        const pool = await app.locals.db;
        let valName = typeof value === 'object' ? (value.name || value) : value;
        let table = '', col = '';
        if (type === 'plant') { table = 'tbl_Plants'; col = 'PlantName'; }
        else if (type === 'focus') { table = 'tbl_FocusAreas'; col = 'FocusName'; }
        else if (type === 'dept') { table = 'tbl_Departments'; col = 'DepartmentName'; }
        else if (type === 'group') { table = 'tbl_ProductGroups'; col = 'GroupName'; }
        else if (type === 'category') { table = 'tbl_Categories'; col = 'CategoryName'; }
        else if (type === 'process') { table = 'tbl_Processes'; col = 'ProcessName'; }
        await pool.request().input('name', sql.VarChar, valName).input('updatedBy', sql.VarChar, action_by || 'System').query(`UPDATE ${table} SET IsDeleted = 1, UpdatedBy = @updatedBy, UpdatedOn = GETDATE() WHERE ${col} = @name`);
        logAudit('DELETE', `SETTING_${type}`, valName, action_by);
        res.json({ success: true });
    } catch (err) { res.json({ success: false, message: err.message }); }
});

// ============================================================================
// 2. USERS
// ============================================================================
app.get('/get-users', authenticateToken, async (req, res) => {
    try {
        const pool = await app.locals.db;
        const result = await pool.request().query(`
            SELECT u.EmpID as emp_id, u.FirstName as fname, u.LastName as lname, u.Email as email, u.DOB as dob,
                   u.IsAdmin as is_admin, u.IsHOD as is_hod, 
                   u.IsCommittee as is_committee, u.IsCoordinator as is_coordinator, u.IsHOK as is_hok,
                   p.PlantName as plant, d.DepartmentName as department
            FROM tbl_Users u
            LEFT JOIN tbl_Plants p ON u.PlantID = p.PlantID
            LEFT JOIN tbl_Departments d ON u.DepartmentID = d.DepartmentID
            WHERE u.IsDeleted = 0
        `);
        const users = result.recordset.map(u => ({ ...u, dob: formatDateOnly(u.dob) }));
        res.json(users);
    } catch (err) { res.status(500).json([]); }
});

app.post('/api/sso-verify', async (req, res) => {
    try {
        // ⚠️ LOCAL DEVELOPMENT BYPASS: skip the company SSO check entirely ⚠️
        if (DISABLE_AUTH) {
            let devUser = { ...DEV_USER };

            // If DEV_EMP_ID is set in .env and exists in tbl_Users, log in as that real user
            if (process.env.DEV_EMP_ID) {
                try {
                    const pool = await app.locals.db;
                    const r = await pool.request()
                        .input('emp_id', sql.VarChar, process.env.DEV_EMP_ID)
                        .query(`
                            SELECT u.EmpID as emp_id, u.FirstName as fname, u.LastName as lname, u.Email as email, u.DOB as dob, u.IsAdmin as is_admin, u.IsHOD as is_hod, u.IsCommittee as is_committee, u.IsCoordinator as is_coordinator, u.IsHOK as is_hok, p.PlantName as plant, d.DepartmentName as department
                            FROM tbl_Users u LEFT JOIN tbl_Plants p ON u.PlantID = p.PlantID LEFT JOIN tbl_Departments d ON u.DepartmentID = d.DepartmentID
                            WHERE u.EmpID = @emp_id AND u.IsDeleted = 0
                        `);
                    if (r.recordset.length > 0) {
                        devUser = r.recordset[0];
                        devUser.dob = formatDateOnly(devUser.dob);
                    }
                } catch (e) { console.error('Dev user lookup failed, using fake user:', e.message); }
            }

            const devToken = jwt.sign({
                emp_id: devUser.emp_id,
                is_admin: devUser.is_admin,
                is_hod: devUser.is_hod,
                is_committee: devUser.is_committee,
                is_coordinator: devUser.is_coordinator,
                is_hok: devUser.is_hok
            }, JWT_SECRET, { expiresIn: '12h' });

            return res.json({ success: true, user: devUser, token: devToken, message: "DEV Login (auth bypass)" });
        }

        // --- PRODUCTION SSO FLOW ---
        const { user, time, hash } = req.body;
        
        if (!user || !time || !hash) {
            return res.status(400).json({ success: false, message: "Missing SSO data. Please access via the company network." });
        }

        const currentTime = Math.floor(Date.now() / 1000);
        if (currentTime - parseInt(time) > 300) {
            return res.status(401).json({ success: false, message: "SSO login expired. Please refresh the page." });
        }

        const secret = process.env.LNT_KAIZEN_SECRET_KEY || "LNT_KAIZEN_SECRET_KEY_FALLBACK_PRODUCTION"; 
        const raw = user + time + secret;
        const calculatedHash = crypto.createHash('sha256').update(raw).digest('hex');

        if (hash !== calculatedHash) {
            return res.status(403).json({ success: false, message: "Invalid SSO signature! Access Denied." });
        }

        const psNumber = user.includes('\\') ? user.split('\\')[1] : user;

        const pool = await app.locals.db;
        const result = await pool.request()
            .input('emp_id', sql.VarChar, psNumber)
            .query(`
                SELECT u.EmpID as emp_id, u.FirstName as fname, u.LastName as lname, u.Email as email, u.DOB as dob, u.PasswordHash as password, u.IsAdmin as is_admin, u.IsHOD as is_hod, u.IsCommittee as is_committee, u.IsCoordinator as is_coordinator, u.IsHOK as is_hok, p.PlantName as plant, d.DepartmentName as department
                FROM tbl_Users u LEFT JOIN tbl_Plants p ON u.PlantID = p.PlantID LEFT JOIN tbl_Departments d ON u.DepartmentID = d.DepartmentID
                WHERE u.EmpID = @emp_id AND u.IsDeleted = 0
            `);

        if (result.recordset.length > 0) {
            const dbUser = result.recordset[0];
            if (typeof formatDateOnly === 'function' && dbUser.dob) dbUser.dob = formatDateOnly(dbUser.dob);
            delete dbUser.password; 

            const tokenPayload = { 
                emp_id: dbUser.emp_id, 
                is_admin: dbUser.is_admin, 
                is_hod: dbUser.is_hod, 
                is_committee: dbUser.is_committee,
                is_coordinator: dbUser.is_coordinator,
                is_hok: dbUser.is_hok
            };
            const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '30m' });

            res.json({ success: true, user: dbUser, token: token, message: "SSO Login Successful" });
        } 
        else {
            res.json({ 
                success: false, 
                message: `Your Employee ID (${psNumber}) is not registered in the Kaizen System. Please contact the administrator for access.` 
            });
        }
    } catch (error) {
        console.error("SSO Verify Error:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});

app.post('/add-user', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { emp_id, fname, lname, email, dob, plant, department, is_admin, is_hod, is_committee, is_coordinator, is_hok, action_by } = req.body;
        const pool = await app.locals.db;
        
        const check = await pool.request().input('emp_id', sql.VarChar, emp_id).query('SELECT IsDeleted FROM tbl_Users WHERE EmpID = @emp_id');
        const plantID = await getFkId(pool, 'tbl_Plants', 'PlantName', 'PlantID', plant);
        const deptID = await getFkId(pool, 'tbl_Departments', 'DepartmentName', 'DepartmentID', department);

        const plainPassword = req.body.password || crypto.randomBytes(8).toString('hex');
        const hashedPassword = await bcrypt.hash(plainPassword, 10);

        const reqSql = pool.request()
            .input('emp_id', sql.VarChar, emp_id).input('fname', sql.VarChar, fname).input('lname', sql.VarChar, lname || '')
            .input('email', sql.VarChar, email).input('dob', sql.Date, dob || null).input('plant_id', sql.Int, plantID)
            .input('dept_id', sql.Int, deptID).input('pass', sql.VarChar, hashedPassword) 
            .input('admin', sql.Bit, is_admin ? 1 : 0).input('hod', sql.Bit, is_hod ? 1 : 0).input('comm', sql.Bit, is_committee ? 1 : 0).input('coord', sql.Bit, is_coordinator ? 1 : 0).input('hok', sql.Bit, is_hok ? 1 : 0)
            .input('createdBy', sql.VarChar, action_by || 'System');

        if (check.recordset.length > 0) {
            if (check.recordset[0].IsDeleted == 0) {
                return res.json({ success: false, message: 'Employee ID already exists' });
            } else {
                await reqSql.query(`UPDATE tbl_Users SET FirstName=@fname, LastName=@lname, Email=@email, DOB=@dob, PlantID=@plant_id, DepartmentID=@dept_id, PasswordHash=@pass, IsAdmin=@admin, IsHOD=@hod, IsCommittee=@comm, IsCoordinator=@coord, IsHOK=@hok, IsDeleted=0, UpdatedBy=@createdBy, UpdatedOn=GETDATE() WHERE EmpID=@emp_id`);
                logAudit('RESTORE', 'USER', emp_id, action_by);
                return res.json({ success: true });
            }
        }

        await reqSql.query(`INSERT INTO tbl_Users (EmpID, FirstName, LastName, Email, DOB, PlantID, DepartmentID, PasswordHash, IsAdmin, IsHOD, IsCommittee, IsCoordinator, IsHOK, CreatedBy) VALUES (@emp_id, @fname, @lname, @email, @dob, @plant_id, @dept_id, @pass, @admin, @hod, @comm, @coord, @hok, @createdBy)`);

        logAudit('CREATE', 'USER', emp_id, action_by);
        res.json({ success: true });
    } catch (err) { 
        let friendlyMsg = "Database error occurred.";
        if(err.number === 2627) friendlyMsg = 'An employee with this Email already exists.';
        res.json({ success: false, message: friendlyMsg }); 
    }
});

app.post('/update-user', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { emp_id, fname, lname, email, dob, plant, department, is_admin, is_hod, is_committee, is_coordinator, is_hok, action_by } = req.body;
        const pool = await app.locals.db;
        const plantID = await getFkId(pool, 'tbl_Plants', 'PlantName', 'PlantID', plant);
        const deptID = await getFkId(pool, 'tbl_Departments', 'DepartmentName', 'DepartmentID', department);

        await pool.request()
            .input('emp_id', sql.VarChar, emp_id).input('fname', sql.VarChar, fname).input('lname', sql.VarChar, lname || '')
            .input('email', sql.VarChar, email).input('dob', sql.Date, dob || null).input('plant_id', sql.Int, plantID)
            .input('dept_id', sql.Int, deptID).input('admin', sql.Bit, is_admin ? 1 : 0).input('hod', sql.Bit, is_hod ? 1 : 0).input('comm', sql.Bit, is_committee ? 1 : 0).input('coord', sql.Bit, is_coordinator ? 1 : 0).input('hok', sql.Bit, is_hok ? 1 : 0)
            .input('updatedBy', sql.VarChar, action_by || 'System')
            .query(`UPDATE tbl_Users SET FirstName = @fname, LastName = @lname, Email = @email, DOB = @dob, PlantID = @plant_id, DepartmentID = @dept_id, IsAdmin = @admin, IsHOD = @hod, IsCommittee = @comm, IsCoordinator = @coord, IsHOK = @hok, UpdatedBy = @updatedBy, UpdatedOn = GETDATE() WHERE EmpID = @emp_id`);

        logAudit('UPDATE', 'USER', emp_id, action_by);
        res.json({ success: true });
    } catch (err) { 
        let friendlyMsg = "Database error occurred.";
        if(err.number === 2627) friendlyMsg = 'Another employee is already using this Email.';
        res.json({ success: false, message: friendlyMsg }); 
    }
});

app.post('/delete-user', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { emp_id, action_by } = req.body; const pool = await app.locals.db;
        await pool.request().input('emp_id', sql.VarChar, emp_id).input('updatedBy', sql.VarChar, action_by || 'System')
            .query('UPDATE tbl_Users SET IsDeleted = 1, UpdatedBy = @updatedBy, UpdatedOn = GETDATE() WHERE EmpID = @emp_id');
        logAudit('DELETE', 'USER', emp_id, action_by); res.json({ success: true });
    } catch (err) { res.json({ success: false, message: err.message }); }
});

app.post('/bulk-users', authenticateToken, requireAdmin, async (req, res) => {
    const { users, action_by } = req.body; 
    if (!Array.isArray(users)) return res.json({ success: false, message: 'Invalid data format' });
    
    let count = 0; let failed = [];
    const pool = await app.locals.db;
    const bulkHashedPassword = await bcrypt.hash(crypto.randomBytes(8).toString('hex'), 10);

    for (let nu of users) {
        try {
            const check = await pool.request().input('emp_id', sql.VarChar, nu.emp_id).query('SELECT IsDeleted FROM tbl_Users WHERE EmpID = @emp_id');
            if (check.recordset.length > 0 && !check.recordset[0].IsDeleted) {
                failed.push({...nu, reason: 'Employee ID already exists'});
                continue;
            }

            const plantRes = await pool.request().input('plant', sql.VarChar, nu.plant).query('SELECT PlantID FROM tbl_Plants WHERE PlantName = @plant AND IsDeleted = 0');
            if (plantRes.recordset.length === 0) { failed.push({...nu, reason: `Plant '${nu.plant}' not found in Master Data`}); continue; }
            const plantID = plantRes.recordset[0].PlantID;

            const deptRes = await pool.request().input('dept', sql.VarChar, nu.department).query('SELECT DepartmentID FROM tbl_Departments WHERE DepartmentName = @dept AND IsDeleted = 0');
            if (deptRes.recordset.length === 0) { failed.push({...nu, reason: `Department '${nu.department}' not found in Master Data`}); continue; }
            const deptID = deptRes.recordset[0].DepartmentID;

            const reqSql = pool.request()
                .input('emp_id', sql.VarChar, nu.emp_id).input('fname', sql.VarChar, nu.fname).input('lname', sql.VarChar, nu.lname || '')
                .input('email', sql.VarChar, nu.email).input('dob', sql.Date, nu.dob || null).input('plant_id', sql.Int, plantID)
                .input('dept_id', sql.Int, deptID).input('pass', sql.VarChar, bulkHashedPassword)
                .input('admin', sql.Bit, nu.is_admin ? 1 : 0).input('hod', sql.Bit, nu.is_hod ? 1 : 0)
                .input('comm', sql.Bit, nu.is_committee ? 1 : 0).input('coord', sql.Bit, nu.is_coordinator ? 1 : 0).input('hok', sql.Bit, nu.is_hok ? 1 : 0)
                .input('cb', sql.VarChar, action_by || 'System');

            if (check.recordset.length > 0 && check.recordset[0].IsDeleted) {
                await reqSql.query(`UPDATE tbl_Users SET FirstName=@fname, LastName=@lname, Email=@email, DOB=@dob, PlantID=@plant_id, DepartmentID=@dept_id, PasswordHash=@pass, IsAdmin=@admin, IsHOD=@hod, IsCommittee=@comm, IsCoordinator=@coord, IsHOK=@hok, IsDeleted=0, UpdatedBy=@cb, UpdatedOn=GETDATE() WHERE EmpID=@emp_id`);
            } else {
                await reqSql.query(`INSERT INTO tbl_Users (EmpID, FirstName, LastName, Email, DOB, PlantID, DepartmentID, PasswordHash, IsAdmin, IsHOD, IsCommittee, IsCoordinator, IsHOK, CreatedBy) VALUES (@emp_id, @fname, @lname, @email, @dob, @plant_id, @dept_id, @pass, @admin, @hod, @comm, @coord, @hok, @cb)`);
            }
            count++;
        } catch(e) {
            let friendlyReason = "Database Validation Error";
            if (e.number === 2627) friendlyReason = "Email already in use by another active user";
            failed.push({...nu, reason: friendlyReason});
        }
    }
    if (count > 0) logAudit('CREATE_BULK', 'USER', `${count} users imported`, action_by);
    res.json({ success: true, count: count, failed: failed });
});

// ============================================================================
// 3. KAIZENS 
// ============================================================================
app.get('/get-kaizens', authenticateToken, async (req, res) => {
    try {
        const pool = await app.locals.db;
        
        const kRes = await pool.request().query(`
            SELECT k.*, 
                   p.PlantName, d.DepartmentName, g.GroupName, f.FocusName, f.Multiplier, pr.ProcessName,
                   uL.FirstName as LFName, uL.LastName as LLName,
                   uC.FirstName as CFName, uC.LastName as CLName
            FROM tbl_Kaizens k
            LEFT JOIN tbl_Plants p ON k.PlantID = p.PlantID
            LEFT JOIN tbl_Departments d ON k.DepartmentID = d.DepartmentID
            LEFT JOIN tbl_ProductGroups g ON k.GroupID = g.GroupID
            LEFT JOIN tbl_FocusAreas f ON k.FocusID = f.FocusID
            LEFT JOIN tbl_Processes pr ON k.ProcessID = pr.ProcessID
            LEFT JOIN tbl_Users uL ON k.OnlineLeaderEmpID = uL.EmpID
            LEFT JOIN tbl_Users uC ON k.OnlineCreatorEmpID = uC.EmpID
            WHERE k.IsDeleted = 0
        `);

        const catRes = await pool.request().query(`SELECT KaizenID, CategoryName FROM tbl_KaizenCategories`);

        const tRes = await pool.request().query(`
            SELECT t.*, u.FirstName, u.LastName 
            FROM tbl_KaizenTeamMembers t 
            LEFT JOIN tbl_Users u ON t.OnlineEmpID = u.EmpID
        `);
        
        const vRes = await pool.request().query(`SELECT v.*, u.FirstName, u.LastName FROM tbl_CommitteeVotes v LEFT JOIN tbl_Users u ON v.EvaluatorEmpID = u.EmpID`);
        const scoresRes = await pool.request().query(`SELECT KaizenID, EvalStage, QuestionKey, PointsAwarded FROM tbl_KaizenScores`);
        const commScoresRes = await pool.request().query(`SELECT VoteID, QuestionKey, PointsAwarded FROM tbl_CommitteeVoteScores`);

        const kaizens = kRes.recordset.map(row => {
            let mappedCategories = catRes.recordset.filter(c => c.KaizenID === row.KaizenID).map(c => c.CategoryName);
            let catStr = mappedCategories.length > 0 ? mappedCategories.join(', ') : "";

            let teamMembersStr = tRes.recordset.filter(t => t.KaizenID === row.KaizenID).map(t => {
                if (t.OfflineMemberName) return t.OfflineMemberName;
                return `${t.FirstName || ''} ${t.LastName || ''}`.trim() + ` (${t.OnlineEmpID})`;
            }).join(', ');
            
            let selfScoresMap = {};
            scoresRes.recordset.filter(s => s.KaizenID === row.KaizenID && s.EvalStage === 'Self').forEach(s => selfScoresMap[s.QuestionKey] = s.PointsAwarded);
            
            let hodScoresMap = {};
            scoresRes.recordset.filter(s => s.KaizenID === row.KaizenID && s.EvalStage === 'HOD').forEach(s => hodScoresMap[s.QuestionKey] = s.PointsAwarded);

            let committeeVotes = vRes.recordset.filter(v => v.KaizenID === row.KaizenID).map(v => {
                let cvMap = {};
                commScoresRes.recordset.filter(cs => cs.VoteID === v.VoteID).forEach(cs => cvMap[cs.QuestionKey] = cs.PointsAwarded);
                
                return {
                    evaluator: formatName(v.FirstName, v.LastName, v.EvaluatorEmpID, null),
                    evaluator_id: v.EvaluatorEmpID,
                    scores: cvMap,
                    multiplier: v.Multiplier,
                    final_score: v.FinalScore,
                    comments: v.Comments,
                    date: formatDateTime(v.VoteDate),
                    
                    assessment: {
                        impact: v.Comm_Impact || '',
                        innovativeness: v.Comm_Innovativeness || '',
                        sustainment: v.Comm_Sustainment || '',
                        replicability: v.Comm_Replicability || '',
                        costBenefit: v.Comm_CostBenefit || '',
                        categoryMatch: v.Comm_CatMatch || '',
                        docComplete: v.Comm_DocComplete || '',
                        conflict: v.Comm_Conflict || '',
                        annualSaving: v.Comm_AnnSav || '0',
                        oneTimeSaving: v.Comm_OneTimeSav || '0',
                        award: v.Comm_AwardCat || ''
                    }
                };
            });

            return {
                id: row.KaizenID,
                theme: row.Theme,
                leader_name: formatName(row.LFName, row.LLName, row.OnlineLeaderEmpID, row.OfflineLeaderName),
                created_by: formatName(row.CFName, row.CLName, row.OnlineCreatorEmpID, row.OfflineCreatorName),
                plant: row.PlantName, department: row.DepartmentName,
                product_group: row.GroupName, category: catStr, focus_area: row.FocusName, focusMultiplier: row.Multiplier,
                process_name: row.ProcessName, kaizen_type: row.KaizenType,
                isOffline: row.IsOffline, team_members: teamMembersStr,
                before_description: row.BeforeDescription, after_description: row.AfterDescription,
                before_file_path: row.BeforeFilePath, after_file_path: row.AfterFilePath,
                
                implStatus: row.ImplStatus || row.implstatus || row.implStatus || '',
                implDate: formatDateOnly(row.ImplDate || row.impldate || row.implDate),
                workArea: row.WorkArea || row.workarea || row.workArea || '',
                supervisorSignoff: row.SupervisorSignoff || row.supervisorsignoff || row.supervisorSignoff || '',
                benefitType: row.BenefitType || row.benefittype || row.benefitType || '',
                monetaryCategory: row.MonetaryCategory || row.monetarycategory || row.monetaryCategory || '',
                quantMethod: row.QuantMethod || row.quantmethod || row.quantMethod || '',
                quantMethodOther: row.QuantMethodOther || row.quantmethodother || row.quantMethodOther || '',
                baseMetric: row.BaseMetric || row.basemetric || row.baseMetric || '0',
                afterMetric: row.AfterMetric || row.aftermetric || row.afterMetric || '0',
                volume: row.Volume || row.volume || '0',
                unitCost: row.UnitCost || row.unitcost || row.unitCost || '0',
                implementationCost: row.ImplementationCost || row.implementationcost || row.implementationCost || '0',
                calcAnnualSaving: row.CalcAnnualSaving || row.calcannualsaving || row.calcAnnualSaving || '0',
                calcPayback: row.CalcPayback || row.calcpayback || row.calcPayback || '0',
                nmImpact: row.NonMonetaryImpact || row.nonmonetaryimpact || row.nonMonetaryImpact || '',
                nmSeverity: row.NonMonetarySeverity || row.nonmonetaryseverity || row.nonMonetarySeverity || '',
                pqcdsm: row.PQCDSM || row.pqcdsm || '',
                sustainability: row.Sustainability || row.sustainability || '',
                sustainabilityOther: row.SustainabilityOther || row.sustainabilityother || row.sustainabilityOther || '',
                sopUpdated: row.SOPUpdated || row.sopupdated || row.sopUpdated || '',
                replicability: row.Replicability || row.replicability || '',
                replicabilityReason: row.ReplicabilityReason || row.replicabilityreason || row.replicabilityReason || '',
                
                hodVerifiedBy: row.HOD_VerifiedBy || row.hod_verifiedby || row.HOD_VERIFIEDBY || '',
                hodDocComplete: row.HOD_DocComplete || row.hod_doccomplete || row.HOD_DOCCOMPLETE || '',
                hodBenTypeConf: row.HOD_BenTypeConf || row.hod_bentypeconf || row.HOD_BENTYPECONF || '',
                hodMonCat: row.HOD_MonCat || row.hod_moncat || row.HOD_MONCAT || '',
                hodValAnnSav: row.HOD_ValAnnSav || row.hod_valannsav || row.HOD_VALANNSAV || '',
                hodValOneTimeSav: row.HOD_ValOneTimeSav || row.hod_valonetimesav || row.HOD_VALONETIMESAV || '',
                hodValImplCost: row.HOD_ValImplCost || row.hod_valimplcost || row.HOD_VALIMPLCOST || '',
                hodTechCorrect: row.HOD_TechCorrect || row.hod_techcorrect || row.HOD_TECHCORRECT || '',
                hodKRAAlign: row.HOD_KRAAlign || row.hod_kraalign || row.HOD_KRAALIGN || '',
                hodPQCDSM: row.HOD_PQCDSM || row.hod_pqcdsm || '',
                hodSustainability: row.HOD_Sustainability || row.hod_sustainability || '',
                hodSustainOther: row.HOD_SustainOther || row.hod_sustainother || row.HOD_SUSTAINOTHER || '',
                
                expenditure: row.ExpenditureCost, expenditure_cost: row.ExpenditureCost, expenditure_amount: row.ExpenditureCost, expenditure_details: row.ExpenditureDetails,
                direct_savings: row.DirectSavings, direct_savings_amount: row.DirectSavings, direct_savings_details: row.DirectSavingsDetails,
                indirect_savings: row.IndirectSavings, indirect_savings_amount: row.IndirectSavings, indirect_savings_details: row.IndirectSavingsDetails,
                
                status: row.Status, subStatus: row.SubStatus, reward_amount: row.RewardAmount,
                coordinator_message: row.CoordMessage, coordinator_action_date: formatDateTime(row.CoordActionDate),
                hok_message: row.HOKMessage, hok_action_date: formatDateTime(row.HOKActionDate), final_user_message: row.FinalUserMessage,
                
                date: formatDateTable(row.CreatedOn), 
                
                current_total_score: row.CurrentTotalScore,
                evaluation_scores: { final_total_score: row.SelfTotalScore, scores: selfScoresMap },
                hod_evaluation: row.HODEvalDate ? { final_score: row.HODTotalScore, comments: row.HODRemarks, date: formatDateTime(row.HODEvalDate), scores: hodScoresMap } : null,
                
                committee_votes: committeeVotes,
                committee_evaluation: { final_score: row.CommitteeAvgScore }
            };
        });

        res.json(kaizens);
    } catch (err) { console.error(err); res.status(500).json([]); }
});

app.post('/save-kaizen', authenticateToken, async (req, res) => {
    try {
        const data = req.body; 
        const pool = await app.locals.db;

        const focusA = data.focus_area || data.focusArea;
        const cleanFocus = focusA ? focusA.split(' x')[0].trim() : null; 
        const prodGroup = data.product_group || data.group;

        let catArray = [];
        if (Array.isArray(data.category)) catArray = data.category;
        else if (typeof data.category === 'string') catArray = data.category.split(',').map(c => c.trim());

        const plantID = await getFkId(pool, 'tbl_Plants', 'PlantName', 'PlantID', data.plant);
        const deptID = await getFkId(pool, 'tbl_Departments', 'DepartmentName', 'DepartmentID', data.department);
        const groupID = await getFkId(pool, 'tbl_ProductGroups', 'GroupName', 'GroupID', prodGroup);
        const focusID = await getFkId(pool, 'tbl_FocusAreas', 'FocusName', 'FocusID', cleanFocus);
        const procID = await getFkId(pool, 'tbl_Processes', 'ProcessName', 'ProcessID', data.process_name);

        const beforeFile = saveFile(data.before_file_data, data.before_file_name, UPLOADS_DIR) || "No File"; 
        const afterFile = saveFile(data.after_file_data, data.after_file_name, UPLOADS_DIR) || "No File";

        let evalScores = data.evaluation_scores || {};
        if (typeof evalScores === 'string') { try { evalScores = JSON.parse(evalScores); } catch(e) { evalScores = {}; } }

        const isOffline = (data.isOffline === true || data.isOffline === 'true');
        
        const selfScore = parseInt(evalScores.final_total_score) || 0;

        const onlineLeader = isOffline ? null : extractId(data.leader_name);
        const offlineLeader = isOffline ? data.leader_name : null;
        const onlineCreator = extractId(data.created_by || data.action_by); 

        if (onlineCreator) {
            const cCheck = await pool.request().input('emp', sql.VarChar, onlineCreator).query('SELECT EmpID FROM tbl_Users WHERE EmpID = @emp AND IsDeleted = 0');
            if (cCheck.recordset.length === 0) return res.json({ success: false, message: `Creator ID '${onlineCreator}' not found.` });
        }
        if (onlineLeader) {
            const lCheck = await pool.request().input('emp', sql.VarChar, onlineLeader).query('SELECT EmpID FROM tbl_Users WHERE EmpID = @emp AND IsDeleted = 0');
            if (lCheck.recordset.length === 0) return res.json({ success: false, message: `Leader ID '${onlineLeader}' not found.` });
        }

        const insertReq = pool.request()
            .input('theme', sql.NVarChar, data.theme || '')
            .input('oLeader', sql.VarChar, onlineLeader).input('offLeader', sql.VarChar, offlineLeader).input('oCreator', sql.VarChar, onlineCreator)
            .input('plant', sql.Int, plantID).input('dept', sql.Int, deptID).input('grp', sql.Int, groupID)
            .input('focus', sql.Int, focusID).input('proc', sql.Int, procID)
            .input('type', sql.VarChar, data.kaizen_type || 'Individual').input('offline', sql.Bit, isOffline ? 1 : 0)
            .input('bDesc', sql.NVarChar, data.before_description || '').input('aDesc', sql.NVarChar, data.after_description || '')
            .input('bFile', sql.VarChar, beforeFile).input('aFile', sql.VarChar, afterFile)
            .input('sScore', sql.Int, selfScore).input('createdBy', sql.VarChar, onlineCreator || 'System')
            
            .input('implStatus', sql.VarChar, data.implStatus || '')
            .input('implDate', sql.Date, data.implDate || null)
            .input('workArea', sql.VarChar, data.workArea || '')
            .input('supSignoff', sql.VarChar, data.supervisorSignoff || '')
            .input('benType', sql.VarChar, data.benefitType || '')
            .input('monCat', sql.VarChar, data.monetaryCategory || '')
            .input('qMethod', sql.VarChar, data.quantMethod || '')
            .input('qMethodOther', sql.VarChar, data.quantMethodOther || '')
            .input('bMetric', sql.Decimal(18,2), cleanNum(data.baseMetric))
            .input('aMetric', sql.Decimal(18,2), cleanNum(data.afterMetric))
            .input('vol', sql.Decimal(18,2), cleanNum(data.volume))
            .input('uCost', sql.Decimal(18,2), cleanNum(data.unitCost))
            .input('impCost', sql.Decimal(18,2), cleanNum(data.impCost))
            .input('cSaving', sql.Decimal(18,2), cleanNum(data.calcAnnualSaving))
            .input('cPayback', sql.Decimal(18,2), cleanNum(data.calcPayback))
            .input('nmImpact', sql.VarChar, data.nmImpact || '')
            .input('nmSeverity', sql.VarChar, data.nmSeverity || '')
            .input('pqcdsm', sql.VarChar, data.pqcdsm || '')
            .input('sustain', sql.VarChar, data.sustainability || '')
            .input('sustainOther', sql.VarChar, data.sustainabilityOther || '')
            .input('sopUpd', sql.VarChar, data.sopUpdated || '')
            .input('rep', sql.VarChar, data.replicability || '')
            .input('repReason', sql.VarChar, data.replicabilityReason || '');

        const result = await insertReq.query(`
            INSERT INTO tbl_Kaizens (
                Theme, OnlineLeaderEmpID, OfflineLeaderName, OnlineCreatorEmpID, PlantID, DepartmentID, GroupID, FocusID, ProcessID, 
                KaizenType, IsOffline, BeforeDescription, AfterDescription, BeforeFilePath, AfterFilePath, SelfTotalScore, CurrentTotalScore, CreatedBy,
                ImplStatus, ImplDate, WorkArea, SupervisorSignoff, BenefitType, MonetaryCategory, QuantMethod, QuantMethodOther, 
                BaseMetric, AfterMetric, Volume, UnitCost, ImplementationCost, CalcAnnualSaving, CalcPayback, 
                NonMonetaryImpact, NonMonetarySeverity, PQCDSM, Sustainability, SustainabilityOther, SOPUpdated, Replicability, ReplicabilityReason
            )
            OUTPUT INSERTED.KaizenID
            VALUES (
                @theme, @oLeader, @offLeader, @oCreator, @plant, @dept, @grp, @focus, @proc, 
                @type, @offline, @bDesc, @aDesc, @bFile, @aFile, @sScore, @sScore, @createdBy,
                @implStatus, @implDate, @workArea, @supSignoff, @benType, @monCat, @qMethod, @qMethodOther,
                @bMetric, @aMetric, @vol, @uCost, @impCost, @cSaving, @cPayback,
                @nmImpact, @nmSeverity, @pqcdsm, @sustain, @sustainOther, @sopUpd, @rep, @repReason
            )
        `);

        const newId = result.recordset[0].KaizenID;

        for (let c of catArray) {
            if (c) await pool.request().input('kID', sql.Int, newId).input('cat', sql.VarChar, c).query('INSERT INTO tbl_KaizenCategories (KaizenID, CategoryName) VALUES (@kID, @cat)');
        }

        if (evalScores.scores) {
            for (const [key, points] of Object.entries(evalScores.scores)) {
                await pool.request().input('kID', sql.Int, newId).input('stage', sql.VarChar, 'Self').input('qKey', sql.VarChar, key).input('pts', sql.Int, parseInt(points) || 0)
                    .query('INSERT INTO tbl_KaizenScores (KaizenID, EvalStage, QuestionKey, PointsAwarded) VALUES (@kID, @stage, @qKey, @pts)');
            }
        }

        if (data.team_members) {
            const members = data.team_members.split(',');
            for (let m of members) {
                const memberName = m.trim();
                if (!memberName) continue;
                const memberId = extractId(memberName);
                const checkUser = await pool.request().input('emp', sql.VarChar, memberId).query('SELECT EmpID FROM tbl_Users WHERE EmpID = @emp AND IsDeleted = 0');
                if (checkUser.recordset.length > 0) {
                    await pool.request().input('kID', sql.Int, newId).input('emp', sql.VarChar, memberId).query('INSERT INTO tbl_KaizenTeamMembers (KaizenID, OnlineEmpID) VALUES (@kID, @emp)');
                } else {
                    await pool.request().input('kID', sql.Int, newId).input('name', sql.VarChar, memberName).query('INSERT INTO tbl_KaizenTeamMembers (KaizenID, OfflineMemberName) VALUES (@kID, @name)');
                }
            }
        }

        logAudit('CREATE', 'KAIZEN', newId, onlineCreator);
        
        // 📧 EMAIL TRIGGER 1: Kaizen Creation
        const eData = await getKaizenEmails(pool, newId);
        sendKaizenMail(
            eData.hod, 
            [...eData.team], 
            `New Kaizen Submitted: KZN-${newId}`, 
            `<h3>New Kaizen Notification</h3>
             <p>A new Kaizen has been submitted for your department.</p>
             <ul>
                <li><b>Kaizen ID:</b> KZN-${newId}</li>
                <li><b>Theme:</b> ${escapeHtml(data.theme)}</li>
                <li><b>Submitted By:</b> ${escapeHtml(onlineCreator || 'System')}</li>
             </ul>
             <p>Please review and evaluate it in the Kaizen Portal.</p>`
        );

        res.json({ success: true, newId: newId });
    } catch (err) { 
        console.error("Save Kaizen Error:", err.message); 
        res.json({ success: false, message: err.message }); 
    }
});

app.post('/update-kaizen', authenticateToken, async (req, res) => {
    try {
        const { id, status, hod_evaluation, committee_evaluation, action_by } = req.body;
        const pool = await app.locals.db;
        
        const kRecord = await pool.request().input('kID', sql.Int, id).query('SELECT SelfTotalScore, HODTotalScore, CommitteeAvgScore, PlantID, DepartmentID, Status, SubStatus, OnlineCreatorEmpID, OnlineLeaderEmpID, IsOffline FROM tbl_Kaizens WHERE KaizenID = @kID');
        if (kRecord.recordset.length === 0) return res.status(404).json({ success: false, message: "Kaizen not found." });
        
        const kaizen = kRecord.recordset[0];
        let selfScore = kaizen.SelfTotalScore || 0;
        let hodScore = kaizen.HODTotalScore || 0;
        let commScore = kaizen.CommitteeAvgScore || 0;
        let newStatus = status;

        const reqSql = pool.request().input('id', sql.Int, id).input('updatedBy', sql.VarChar, action_by || 'System');

        if (hod_evaluation) {
            if (!req.user.is_hod && !req.user.is_admin) {
                return res.status(403).json({ success: false, message: "Security Block: You do not have HOD privileges." });
            }

            hodScore = parseInt(hod_evaluation.final_score) || 0;
            const assess = hod_evaluation.assessment || {}; 

            reqSql.input('hScore', sql.Int, hodScore)
                  .input('hRem', sql.NVarChar, hod_evaluation.comments)
                  .input('hVer', sql.VarChar, assess.verifiedBy || '')
                  .input('hDoc', sql.VarChar, assess.docComplete || '')
                  .input('hBen', sql.VarChar, assess.benType || '')
                  .input('hMonCat', sql.VarChar, assess.monCat || '')
                  .input('hAnnSav', sql.Decimal(18,2), cleanNum(assess.valAnnSav))
                  .input('hOneSav', sql.Decimal(18,2), cleanNum(assess.valOneSav))
                  .input('hImpCost', sql.Decimal(18,2), cleanNum(assess.valImpCost))
                  .input('hTech', sql.VarChar, assess.techCorrect || '')
                  .input('hKra', sql.VarChar, assess.kraAlign || '')
                  .input('hPqc', sql.VarChar, assess.pqcdsm || '')
                  .input('hSus', sql.VarChar, assess.sustain || '')
                  .input('hSusOth', sql.VarChar, assess.sustainOther || '');

            await reqSql.query(`
                UPDATE tbl_Kaizens SET 
                    Status = '${newStatus}', 
                    HODTotalScore = @hScore, 
                    HODRemarks = @hRem, 
                    HODEvalDate = GETDATE(),
                    HOD_VerifiedBy = @hVer,
                    HOD_DocComplete = @hDoc,
                    HOD_BenTypeConf = @hBen,
                    HOD_MonCat = @hMonCat,
                    HOD_ValAnnSav = @hAnnSav,
                    HOD_ValOneTimeSav = @hOneSav,
                    HOD_ValImplCost = @hImpCost,
                    HOD_TechCorrect = @hTech,
                    HOD_KRAAlign = @hKra,
                    HOD_PQCDSM = @hPqc,
                    HOD_Sustainability = @hSus,
                    HOD_SustainOther = @hSusOth,
                    UpdatedBy = @updatedBy, 
                    UpdatedOn = GETDATE() 
                WHERE KaizenID = @id
            `);
            
            await pool.request().input('kID', sql.Int, id).input('stage', sql.VarChar, 'HOD').query('DELETE FROM tbl_KaizenScores WHERE KaizenID = @kID AND EvalStage = @stage');
            if (hod_evaluation.scores) {
                for (const [key, points] of Object.entries(hod_evaluation.scores)) {
                    await pool.request().input('kID', sql.Int, id).input('stage', sql.VarChar, 'HOD').input('qKey', sql.VarChar, key).input('pts', sql.Int, parseInt(points) || 0)
                        .query('INSERT INTO tbl_KaizenScores (KaizenID, EvalStage, QuestionKey, PointsAwarded) VALUES (@kID, @stage, @qKey, @pts)');
                }
            }

            // 📧 EMAIL TRIGGER 2: HOD Action
            const eData = await getKaizenEmails(pool, id);
            if (newStatus === "Rejected by HOD") {
                sendKaizenMail(
                    eData.team, eData.hod, 
                    `Kaizen Rejected: KZN-${id}`, 
                    `<h3>Kaizen Rejected</h3>
                     <p>Your Kaizen <b>KZN-${id}</b> (${escapeHtml(eData.theme)}) has been rejected by the HOD.</p>
                     <p><b>Remarks:</b> ${escapeHtml(hod_evaluation.comments)}</p>`
                );
            } else if (newStatus === "Approved by HOD") {
                sendKaizenMail(
                    eData.comm, [...eData.team, ...eData.hod], 
                    `Kaizen Pending Committee Evaluation: KZN-${id}`, 
                    `<h3>Committee Evaluation Required</h3>
                     <p>Kaizen <b>KZN-${id}</b> (${escapeHtml(eData.theme)}) has been approved by the HOD and is now awaiting Committee Evaluation.</p>
                     <p>Please log in to the portal to review.</p>`
                );
            }
        }

        if (committee_evaluation) {
            if (!req.user.is_committee && !req.user.is_admin) {
                return res.status(403).json({ success: false, message: "Security Block: You do not have Committee privileges." });
            }

            let vID;
            const assess = committee_evaluation.assessment || {};
            
            const check = await pool.request().input('kID', sql.Int, id).input('eID', sql.VarChar, committee_evaluation.evaluator_id)
                .query('SELECT VoteID FROM tbl_CommitteeVotes WHERE KaizenID = @kID AND EvaluatorEmpID = @eID');
            
            const vReq = pool.request()
                .input('kID', sql.Int, id)
                .input('eID', sql.VarChar, committee_evaluation.evaluator_id)
                .input('mult', sql.Decimal(4,2), committee_evaluation.multiplier)
                .input('fScore', sql.Int, committee_evaluation.final_score)
                .input('comm', sql.NVarChar, committee_evaluation.comments)
                
                .input('cImp', sql.VarChar, assess.impact || '')
                .input('cInn', sql.VarChar, assess.innovativeness || '')
                .input('cSus', sql.VarChar, assess.sustainment || '')
                .input('cRep', sql.VarChar, assess.replicability || '')
                .input('cCost', sql.VarChar, assess.costBenefit || '')
                .input('cCat', sql.VarChar, assess.categoryMatch || '')
                .input('cDoc', sql.VarChar, assess.docComplete || '')
                .input('cCon', sql.VarChar, assess.conflict || '')
                .input('cAnnSav', sql.Decimal(18,2), cleanNum(assess.annualSaving))
                .input('cOneSav', sql.Decimal(18,2), cleanNum(assess.oneTimeSaving))
                .input('cAward', sql.VarChar, assess.award || '');
            
            if(check.recordset.length > 0) {
                vID = check.recordset[0].VoteID;
                await vReq.input('vID', sql.Int, vID).query(`
                    UPDATE tbl_CommitteeVotes SET 
                        Multiplier=@mult, FinalScore=@fScore, Comments=@comm, VoteDate=GETDATE(),
                        Comm_Impact=@cImp, Comm_Innovativeness=@cInn, Comm_Sustainment=@cSus,
                        Comm_Replicability=@cRep, Comm_CostBenefit=@cCost, Comm_CatMatch=@cCat,
                        Comm_DocComplete=@cDoc, Comm_Conflict=@cCon, Comm_AnnSav=@cAnnSav,
                        Comm_OneTimeSav=@cOneSav, Comm_AwardCat=@cAward
                    WHERE VoteID=@vID
                `);
            } else {
                const insertVote = await vReq.query(`
                    INSERT INTO tbl_CommitteeVotes (
                        KaizenID, EvaluatorEmpID, Multiplier, FinalScore, Comments,
                        Comm_Impact, Comm_Innovativeness, Comm_Sustainment, Comm_Replicability,
                        Comm_CostBenefit, Comm_CatMatch, Comm_DocComplete, Comm_Conflict,
                        Comm_AnnSav, Comm_OneTimeSav, Comm_AwardCat
                    ) OUTPUT INSERTED.VoteID VALUES (
                        @kID, @eID, @mult, @fScore, @comm,
                        @cImp, @cInn, @cSus, @cRep, @cCost, @cCat, @cDoc, @cCon, @cAnnSav, @cOneSav, @cAward
                    )
                `);
                vID = insertVote.recordset[0].VoteID;
            }

            await pool.request().input('vID', sql.Int, vID).query('DELETE FROM tbl_CommitteeVoteScores WHERE VoteID = @vID');
            if (committee_evaluation.scores) {
                for (const [key, points] of Object.entries(committee_evaluation.scores)) {
                    await pool.request().input('vID', sql.Int, vID).input('qKey', sql.VarChar, key).input('pts', sql.Int, parseInt(points) || 0)
                        .query('INSERT INTO tbl_CommitteeVoteScores (VoteID, QuestionKey, PointsAwarded) VALUES (@vID, @qKey, @pts)');
                }
            }

            const avgRes = await pool.request().input('kID', sql.Int, id).query('SELECT AVG(FinalScore) as avgScore, COUNT(*) as count FROM tbl_CommitteeVotes WHERE KaizenID = @kID');
            commScore = avgRes.recordset[0].avgScore || 0;
            const count = avgRes.recordset[0].count || 0;

            const commUsersRes = await pool.request().query('SELECT EmpID FROM tbl_Users WHERE IsCommittee = 1 AND IsDeleted = 0');
            const commUsers = commUsersRes.recordset.map(u => u.EmpID);
            
            const kMembersRes = await pool.request().input('kID_conf', sql.Int, id).query('SELECT OnlineEmpID, OfflineMemberName FROM tbl_KaizenTeamMembers WHERE KaizenID = @kID_conf');
            const teamEmpIDs = kMembersRes.recordset.map(t => t.OnlineEmpID || extractId(t.OfflineMemberName));
            
            const kLeaderCreatorRes = await pool.request().input('kID_lc', sql.Int, id).query('SELECT OnlineLeaderEmpID, OfflineLeaderName, OnlineCreatorEmpID, OfflineCreatorName FROM tbl_Kaizens WHERE KaizenID = @kID_lc');
            const leaderEmpID = kLeaderCreatorRes.recordset[0]?.OnlineLeaderEmpID || extractId(kLeaderCreatorRes.recordset[0]?.OfflineLeaderName);
            const creatorEmpID = kLeaderCreatorRes.recordset[0]?.OnlineCreatorEmpID || extractId(kLeaderCreatorRes.recordset[0]?.OfflineCreatorName);

            const involvedSet = new Set([...teamEmpIDs, leaderEmpID, creatorEmpID].filter(x => x));
            
            let conflicts = 0;
            commUsers.forEach(empId => {
                if (involvedSet.has(empId)) conflicts++;
            });

            let required = Math.max(1, commUsers.length - conflicts); 
            newStatus = status.includes("Rejected") ? status : (count >= required ? "Approved by Committee" : "Partially Approved by Committee");
            
            await pool.request().input('id', sql.Int, id).input('avg', sql.Int, commScore).input('stat', sql.VarChar, newStatus).input('updatedBy', sql.VarChar, action_by || 'System')
                .query('UPDATE tbl_Kaizens SET CommitteeAvgScore = @avg, Status = @stat, UpdatedBy = @updatedBy, UpdatedOn = GETDATE() WHERE KaizenID = @id');

            // 📧 EMAIL TRIGGER 3: Committee Completion
            if (newStatus === "Approved by Committee") {
                const eData = await getKaizenEmails(pool, id);
                sendKaizenMail(
                    eData.coord, [...eData.team, ...eData.hod, ...eData.comm], 
                    `Kaizen Pending Coordinator Review: KZN-${id}`, 
                    `<h3>Committee Evaluation Completed</h3>
                     <p>Kaizen <b>KZN-${id}</b> (${escapeHtml(eData.theme)}) has been successfully evaluated by the required Committee members.</p>
                     <p>Please review and propose the final reward in the portal.</p>`
                );
            }
        }

        let currentTotal = selfScore + hodScore + (newStatus === "Approved by Committee" ? commScore : 0);
        await pool.request().input('id', sql.Int, id).input('tot', sql.Int, currentTotal).query('UPDATE tbl_Kaizens SET CurrentTotalScore = @tot WHERE KaizenID = @id');

        logAudit('UPDATE', 'KAIZEN_EVAL', id, action_by);
        res.json({ success: true });
    } catch (err) { console.error(err); res.json({ success: false, message: err.message }); }
});

app.post('/update-kaizen-status', authenticateToken, async (req, res) => {
    try {
        const { id, status, subStatus, reward_amount, coordinator_message, coordinator_action_date, hok_message, hok_action_date, final_user_message, action_by } = req.body;
        
        if (!req.user.is_admin && !req.user.is_coordinator && !req.user.is_hok) {
            return res.status(403).json({ success: false, message: "Security Block: Unauthorized." });
        }

        const pool = await app.locals.db;
        const kRecord = await pool.request().input('kID', sql.Int, id).query('SELECT Status, SubStatus FROM tbl_Kaizens WHERE KaizenID = @kID');
        if (kRecord.recordset.length === 0) return res.status(404).json({ success: false, message: "Kaizen not found." });
        const kaizen = kRecord.recordset[0];

        const isCoordinatorAction = coordinator_message !== undefined || final_user_message !== undefined;
        const isHokAction = hok_message !== undefined;

        if (isCoordinatorAction && !req.user.is_coordinator && !req.user.is_admin) {
            return res.status(403).json({ success: false, message: "Security Block: You do not have Coordinator privileges." });
        }
        if (isHokAction && !req.user.is_hok && !req.user.is_admin) {
            return res.status(403).json({ success: false, message: "Security Block: You do not have HOK privileges." });
        }

        let query = 'UPDATE tbl_Kaizens SET UpdatedBy = @actionBy, UpdatedOn = GETDATE()';
        const r = pool.request().input('id', sql.Int, id).input('actionBy', sql.VarChar, action_by || 'System');

        if(status) { query += ', Status = @status'; r.input('status', sql.VarChar, status); }
        if(subStatus) { query += ', SubStatus = @subStatus'; r.input('subStatus', sql.VarChar, subStatus); }
        if(reward_amount) { query += ', RewardAmount = @reward'; r.input('reward', sql.Decimal(18,2), reward_amount); }
        if(coordinator_message) { query += ', CoordMessage = @cm, CoordActionDate = GETDATE()'; r.input('cm', sql.NVarChar, coordinator_message); }
        if(hok_message) { query += ', HOKMessage = @hm, HOKActionDate = GETDATE()'; r.input('hm', sql.NVarChar, hok_message); }
        if(final_user_message) { query += ', FinalUserMessage = @fm'; r.input('fm', sql.NVarChar, final_user_message); }

        query += ' WHERE KaizenID = @id';
        await r.query(query);
        logAudit('UPDATE', 'KAIZEN_STATUS', id, action_by);

        // 📧 EMAIL TRIGGERS 4 & 5: Coordinator and HOK Actions
        const eData = await getKaizenEmails(pool, id);

        if (status === 'Completed' || status === 'Rejected by HOK') {
             // Finalization by Coordinator
             sendKaizenMail(
                 eData.team, 
                 [...eData.hod, ...eData.comm, ...eData.coord, ...eData.hok], 
                 `Kaizen Final Status Updated: KZN-${id}`, 
                 `<h3>Kaizen Status Update</h3>
                  <p>Kaizen <b>KZN-${id}</b> (${escapeHtml(eData.theme)}) has been marked as <b>${escapeHtml(status)}</b>.</p>
                  <p><b>Final Message:</b> ${escapeHtml(final_user_message || 'No additional message')}</p>`
             );
        } else if (hok_message) {
             // HOK action (Approved by hok, Send by hok to Review)
             sendKaizenMail(
                 eData.coord, eData.hok,
                 `HOK Review Completed: KZN-${id}`,
                 `<h3>HOK Review Update</h3>
                  <p>The Head of Kaizen has reviewed KZN-${id} (${escapeHtml(eData.theme)}).</p>
                  <p><b>Status:</b> ${escapeHtml(subStatus)}</p>
                  <p><b>Remarks:</b> ${escapeHtml(hok_message)}</p>`
             );
        } else if (coordinator_message && status === 'Waiting for Final Approval') {
             // Coordinator sent to HOK
             sendKaizenMail(
                 eData.hok, eData.coord,
                 `Kaizen Pending HOK Approval: KZN-${id}`,
                 `<h3>HOK Approval Required</h3>
                  <p>Kaizen <b>KZN-${id}</b> (${escapeHtml(eData.theme)}) has been forwarded by the Coordinator for final approval.</p>
                  <p><b>Proposed Reward:</b> ₹ ${escapeHtml(reward_amount)}</p>
                  <p><b>Coordinator Remarks:</b> ${escapeHtml(coordinator_message)}</p>`
             );
        }

        res.json({ success: true });
    } catch(err) { res.json({ success: false, message: err.message }); }
});

app.post('/delete-kaizen', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id, action_by } = req.body; const pool = await app.locals.db;
        await pool.request().input('id', sql.Int, id).input('ub', sql.VarChar, action_by || 'System').query('UPDATE tbl_Kaizens SET IsDeleted = 1, UpdatedBy = @ub, UpdatedOn = GETDATE() WHERE KaizenID = @id');
        logAudit('DELETE', 'KAIZEN', id, action_by); res.json({ success: true });
    } catch(e) { res.json({ success: false }); }
});

// ============================================================================
// 4. CRITERIA, GALLERY, ANNOUNCEMENTS
// ============================================================================
app.get('/get-criteria', authenticateToken, async (req, res) => {
    try {
        const pool = await app.locals.db;
        const qRes = await pool.request().query('SELECT * FROM tbl_CriteriaQuestions WHERE IsDeleted=0 ORDER BY OrderIndex ASC');
        const oRes = await pool.request().query('SELECT * FROM tbl_CriteriaOptions WHERE IsDeleted=0');
        let result = { self: [], hod: [], committee: [] };
        
        qRes.recordset.forEach(q => {
            let options = oRes.recordset.filter(o => o.QuestionID === q.QuestionID).map(o => ({ label: o.OptionLabel, points: o.Points }));
            if (result[q.EvalType]) {
                result[q.EvalType].push({ id: q.QuestionID.toString(), label: q.QuestionLabel, key: q.QuestionKey, options: options });
            }
        });
        res.json(req.query.type ? result[req.query.type] || [] : result);
    } catch (err) { res.status(500).json([]); }
});

app.post('/add-criteria', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { type, question, action_by } = req.body; const pool = await app.locals.db;
        const qResult = await pool.request().input('typ', sql.VarChar, type).input('k', sql.VarChar, question.key).input('l', sql.VarChar, question.label).input('cb', sql.VarChar, action_by || 'System')
            .query('INSERT INTO tbl_CriteriaQuestions (EvalType, QuestionKey, QuestionLabel, CreatedBy) OUTPUT INSERTED.QuestionID VALUES (@typ, @k, @l, @cb)');
        
        const newId = qResult.recordset[0].QuestionID;
        for (let opt of question.options) {
            await pool.request().input('qID', sql.Int, newId).input('ol', sql.VarChar, opt.label).input('pt', sql.Int, opt.points)
                .query('INSERT INTO tbl_CriteriaOptions (QuestionID, OptionLabel, Points) VALUES (@qID, @ol, @pt)');
        }
        logAudit('CREATE', `CRITERIA_${type}`, newId, action_by); res.json({ success: true });
    } catch (err) { res.json({ success: false, message: err.message }); }
});

app.post('/update-criteria-order', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { orderData, action_by } = req.body; 
        const pool = await app.locals.db;
        
        for (let item of orderData) {
            await pool.request()
                .input('id', sql.Int, parseInt(item.id))
                .input('oIdx', sql.Int, item.orderIndex)
                .input('ub', sql.VarChar, action_by || 'System')
                .query('UPDATE tbl_CriteriaQuestions SET OrderIndex=@oIdx, UpdatedBy=@ub, UpdatedOn=GETDATE() WHERE QuestionID=@id');
        }
        res.json({ success: true });
    } catch (err) { res.json({ success: false, message: err.message }); }
});

app.post('/delete-criteria', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { type, id, action_by } = req.body; const pool = await app.locals.db;
        await pool.request().input('id', sql.Int, parseInt(id)).input('ub', sql.VarChar, action_by || 'System')
            .query('UPDATE tbl_CriteriaQuestions SET IsDeleted=1, UpdatedBy=@ub, UpdatedOn=GETDATE() WHERE QuestionID=@id');
        logAudit('DELETE', `CRITERIA_${type}`, id, action_by); res.json({ success: true });
    } catch (err) { res.json({ success: false }); }
});

app.get('/get-gallery', async (req, res) => {
    try {
        const pool = await app.locals.db;
        const albums = await pool.request().query('SELECT AlbumID as id, Title as title FROM tbl_GalleryAlbums WHERE IsDeleted = 0');
        const images = await pool.request().query('SELECT AlbumID, ImagePath as url, Caption as caption FROM tbl_GalleryImages WHERE IsDeleted = 0');
        const gallery = albums.recordset.map(a => ({ id: a.id.toString(), title: a.title, images: images.recordset.filter(i => i.AlbumID === a.id).map(i => ({ url: i.url, caption: i.caption })) }));
        res.json(gallery);
    } catch (err) { res.status(500).json([]); }
});

app.post('/add-gallery-section', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { title, action_by } = req.body; const pool = await app.locals.db;
        await pool.request().input('t', sql.VarChar, title).input('cb', sql.VarChar, action_by || 'System').query('INSERT INTO tbl_GalleryAlbums (Title, CreatedBy) VALUES (@t, @cb)');
        res.json({ success: true });
    } catch (err) { res.json({ success: false }); }
});

app.post('/upload-gallery-image', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { sectionId, image, caption, action_by } = req.body; 
        const fileName = saveFile(image, `gallery_${Date.now()}.png`, GALLERY_DIR); 
        if (fileName) {
            const url = `http://localhost:${PORT}/homePageImage/${fileName}`; const pool = await app.locals.db;
            await pool.request().input('aID', sql.Int, parseInt(sectionId)).input('path', sql.VarChar, url).input('cap', sql.NVarChar, caption || '').input('cb', sql.VarChar, action_by || 'System')
                .query('INSERT INTO tbl_GalleryImages (AlbumID, ImagePath, Caption, CreatedBy) VALUES (@aID, @path, @cap, @cb)');
            res.json({ success: true });
        } else { res.json({ success: false }); }
    } catch (err) { res.json({ success: false }); }
});

app.post('/delete-gallery-section', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id, action_by } = req.body; const pool = await app.locals.db;
        await pool.request().input('id', sql.Int, parseInt(id)).input('ub', sql.VarChar, action_by || 'System')
            .query('UPDATE tbl_GalleryAlbums SET IsDeleted=1, UpdatedBy=@ub, UpdatedOn=GETDATE() WHERE AlbumID=@id; UPDATE tbl_GalleryImages SET IsDeleted=1, UpdatedBy=@ub, UpdatedOn=GETDATE() WHERE AlbumID=@id;');
        res.json({ success: true });
    } catch (err) { res.json({ success: false }); }
});

app.post('/delete-gallery-image', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { sectionId, imageIndex, action_by } = req.body; const pool = await app.locals.db;
        const imgs = await pool.request().input('aID', sql.Int, parseInt(sectionId)).query('SELECT ImageID FROM tbl_GalleryImages WHERE AlbumID = @aID AND IsDeleted = 0 ORDER BY ImageID ASC');
        if (imgs.recordset[imageIndex]) {
            await pool.request().input('iID', sql.Int, imgs.recordset[imageIndex].ImageID).input('ub', sql.VarChar, action_by || 'System')
                .query('UPDATE tbl_GalleryImages SET IsDeleted=1, UpdatedBy=@ub, UpdatedOn=GETDATE() WHERE ImageID=@iID');
            res.json({ success: true });
        } else res.json({ success: false });
    } catch (err) { res.json({ success: false }); }
});

app.get('/get-announcements', async (req, res) => {
    try {
        const pool = await app.locals.db;
        const result = await pool.request().query(`SELECT AnnouncementID as id, MessageText as message, ValidUntil as date, LinkURL as link FROM tbl_Announcements WHERE IsDeleted = 0 ORDER BY AnnouncementID DESC`);
        res.json(result.recordset);
    } catch (err) { res.status(500).json([]); }
});

app.post('/add-announcement', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { message, date, link, action_by } = req.body; const pool = await app.locals.db;
        await pool.request().input('m', sql.NVarChar, message).input('d', sql.Date, date || null).input('l', sql.VarChar, link || '').input('cb', sql.VarChar, action_by || 'System')
            .query('INSERT INTO tbl_Announcements (MessageText, ValidUntil, LinkURL, CreatedBy) VALUES (@m, @d, @l, @cb)');
        res.json({ success: true });
    } catch(err) { res.json({ success: false }); }
});

app.post('/delete-announcement', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id, action_by } = req.body; const pool = await app.locals.db;
        await pool.request().input('id', sql.Int, parseInt(id)).input('ub', sql.VarChar, action_by || 'System')
            .query('UPDATE tbl_Announcements SET IsDeleted=1, UpdatedBy=@ub, UpdatedOn=GETDATE() WHERE AnnouncementID=@id');
        res.json({ success: true });
    } catch(err) { res.json({ success: false }); }
});

app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));