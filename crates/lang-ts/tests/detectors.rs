//! Each detector must fire on the vulnerable snippet and stay silent on the safe one.

use std::collections::HashSet;

fn rules(code: &str) -> Vec<String> {
    let a = proof_it_lang_ts::analyze("t.ts", code, &HashSet::new()).expect("parse");
    a.findings.into_iter().map(|f| f.rule_id).collect()
}

fn case(rule: &str, bad: &str, good: &str) {
    let b = rules(bad);
    assert!(b.iter().any(|r| r == rule), "{rule} should fire on:\n{bad}\nfound: {b:?}");
    let g = rules(good);
    assert!(!g.iter().any(|r| r == rule), "{rule} should NOT fire on:\n{good}\nfound: {g:?}");
}

#[test]
fn sql_injection() {
    case(
        "SEC-SQLI",
        "app.get('/u', async (req, res) => { const id = req.query.id; const r = await db.query(`SELECT * FROM users WHERE id = ${id}`); res.json(r); });",
        "app.get('/u', async (req, res) => { const r = await db.query('SELECT * FROM users WHERE id = $1', [req.query.id]); res.json(r); });",
    );
}

#[test]
fn command_injection() {
    case("SEC-CMDI", "function h(req) { exec('convert ' + req.body.file); }", "function h(req) { execFile('convert', [req.body.file]); }");
}

#[test]
fn path_traversal() {
    case(
        "SEC-PATH-TRAVERSAL",
        "function h(req, res) { fs.readFile('/data/' + req.params.name, () => {}); }",
        "function h(req, res) { fs.readFile('/data/' + path.basename(req.params.name), () => {}); }",
    );
}

#[test]
fn ssrf() {
    case(
        "SEC-SSRF",
        "async function h(req) { await fetch(req.query.url); }",
        "async function h(req) { await fetch('https://api.example.com/' + encodeURIComponent(req.query.id)); }",
    );
}

#[test]
fn open_redirect() {
    case("SEC-OPEN-REDIRECT", "function h(req, res) { res.redirect(req.query.next); }", "function h(req, res) { res.redirect('/home'); }");
}

#[test]
fn nosql_injection() {
    case(
        "SEC-NOSQLI",
        "async function h(req) { return User.findOne(req.body); }",
        "async function h(req) { return User.findOne({ email: String(req.body.email) }); }",
    );
}

#[test]
fn mass_assignment() {
    case(
        "SEC-MASS-ASSIGN",
        "async function h(req) { return User.create(req.body); }",
        "async function h(req) { const { name } = req.body; return User.create({ name }); }",
    );
}

#[test]
fn jwt() {
    case("SEC-JWT-DECODE", "const c = jwt.decode(token); if (c.admin) grant();", "const c = jwt.verify(token, key, { algorithms: ['HS256'] });");
    case("SEC-JWT-IGNORE-EXPIRATION", "jwt.verify(t, k, { ignoreExpiration: true });", "jwt.verify(t, k, { algorithms: ['RS256'] });");
    case("SEC-JWT-ALG-NONE", "jwt.verify(t, k, { algorithms: ['none', 'HS256'] });", "jwt.verify(t, k, { algorithms: ['HS256'] });");
    case("SEC-JWT-NO-EXPIRY", "jwt.sign({ sub: u.id }, key);", "jwt.sign({ sub: u.id }, key, { expiresIn: '15m' });");
}

#[test]
fn crypto() {
    case(
        "SEC-WEAK-HASH",
        "const passwordHash = crypto.createHash('md5').update(password).digest('hex');",
        "const etag = crypto.createHash('md5').update(body).digest('hex');",
    );
    case("SEC-INSECURE-RANDOM", "const resetToken = Math.random().toString(36);", "const jitter = Math.random() * 100;");
    case("SEC-TLS-DISABLED", "const agent = new https.Agent({ rejectUnauthorized: false });", "const agent = new https.Agent({ ca });");
    case("SEC-DEPRECATED-CIPHER", "const c = crypto.createCipher('aes192', pw);", "const c = crypto.createCipheriv('aes-256-gcm', key, iv);");
}

#[test]
fn eval_and_function() {
    case("SEC-CODE-INJECTION", "function h(req) { eval(req.body.expr); }", "function h(req) { JSON.parse(req.body.expr); }");
}

#[test]
fn cors_and_cookies() {
    case("SEC-CORS", "app.use(cors({ origin: '*', credentials: true }));", "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));");
    case(
        "SEC-COOKIE-FLAGS",
        "app.use(session({ secret: s, cookie: { httpOnly: false } }));",
        "app.use(session({ secret: s, cookie: { httpOnly: true, secure: true } }));",
    );
}

#[test]
fn taint_through_locals_and_destructuring() {
    let r = rules(
        "app.post('/x', async (req, res) => { const { name } = req.body; const q = 'SELECT * FROM t WHERE n = \\'' + name + '\\''; await pool.query(q); });",
    );
    // `q` is built from request data through a destructured local: real injection.
    assert!(r.iter().any(|x| x == "SEC-SQLI"), "{r:?}");
    // A constant query held in a local is not dynamic SQL.
    let ok = rules("app.post('/x', async (req, res) => { const q = 'SELECT 1'; await pool.query(q, [req.body.id]); });");
    assert!(!ok.iter().any(|x| x == "SEC-SQLI" || x == "SEC-DYNAMIC-SQL"), "{ok:?}");
}

#[test]
fn static_checks() {
    case("STATIC-SELF-COMPARE", "if (record.ownerId === record.ownerId) allow();", "if (record.ownerId === user.id) allow();");
    case("STATIC-DEAD-AUTHZ", "if (false) { authorize(user, record); }", "if (debug) { authorize(user, record); }");
    case("STATIC-ASYNC-FOREACH", "items.forEach(async (i) => { await save(i); });", "for (const i of items) { await save(i); }");
    case("STATIC-EMPTY-CATCH", "try { await save(); } catch (e) {}", "try { await save(); } catch (e) { log(e); }");
}

#[test]
fn ssrf_via_client_methods() {
    case(
        "SEC-SSRF",
        "function h(req) { const url = req.query.url + req.query.symbol; return needle.get(url, () => {}); }",
        "function h(req) { return needle.get('https://api.example.com/q?s=' + encodeURIComponent(req.query.symbol), () => {}); }",
    );
    case(
        "SEC-SSRF",
        "async function h(req) { return axios.post(req.body.callback, {}); }",
        "async function h(req) { return axios.post(CALLBACK_URL, { id: req.body.id }); }",
    );
}

#[test]
fn nosql_where() {
    case(
        "SEC-NOSQLI",
        "function q(userId, t) { return { $where: `this.userId == ${userId} && this.stocks > '${t}'` }; }",
        "function q(userId) { return { userId: Number(userId) }; }",
    );
}

#[test]
fn redos() {
    case("SEC-REDOS", "const ok = /([0-9]+)+\\#/.test(bankRouting);", "const ok = /([0-9]+)\\#/.test(bankRouting);");
    case("SEC-REDOS", "const re = /^(a|b*)*$/;", "const re = /^(ab)*$/;");
    case(
        "SEC-REGEX-INJECTION",
        "function h(req) { return new RegExp(req.query.q).test(x); }",
        "function h(req) { return new RegExp(escapeRegExp(req.query.q)).test(x); }",
    );
}

#[test]
fn xxe() {
    case(
        "SEC-XXE",
        "function h(req) { return libxmljs.parseXmlString(req.body.xml, { noent: true }); }",
        "function h(req) { return libxmljs.parseXmlString(req.body.xml, { noblanks: true }); }",
    );
}

#[test]
fn templates() {
    case("SEC-TEMPLATE-AUTOESCAPE", "swig.setDefaults({ autoescape: false });", "swig.setDefaults({ cache: false });");
    case("SEC-TEMPLATE-AUTOESCAPE", "const t = Handlebars.compile(src, { noEscape: true });", "const t = Handlebars.compile(src);");
    case(
        "SEC-SSTI",
        "function h(req, res) { res.send(ejs.render(req.body.template, {})); }",
        "function h(req, res) { res.send(ejs.render(TEMPLATE, { name: req.body.name })); }",
    );
}

#[test]
fn sessions_errors_logs() {
    case(
        "SEC-HARDCODED-SESSION-SECRET",
        "app.use(session({ secret: 'keyboard cat', cookie: { secure: true } }));",
        "app.use(session({ secret: process.env.SESSION_SECRET, cookie: { secure: true } }));",
    );
    case(
        "SEC-SESSION-DEFAULTS",
        "app.use(session({ secret: process.env.S, resave: false }));",
        "app.use(session({ secret: process.env.S, cookie: { secure: true, httpOnly: true, sameSite: 'lax' } }));",
    );
    case(
        "SEC-ERROR-DISCLOSURE",
        "app.use((err, req, res, next) => { res.status(500).send(err.stack); });",
        "app.use((err, req, res, next) => { log(err); res.status(500).send('internal error'); });",
    );
    case("SEC-LOG-INJECTION", "function h(req) { console.log('login failed for', req.body.userName); }", "function h(req) { console.log('login failed'); }");
}

#[test]
fn react_dangerous_html() {
    let bad = rules_tsx("export const C = ({ html }) => <div dangerouslySetInnerHTML={{ __html: html }} />;");
    assert!(bad.iter().any(|r| r == "SEC-XSS"), "{bad:?}");
    let good = rules_tsx("export const C = ({ html }) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;");
    assert!(!good.iter().any(|r| r == "SEC-XSS"), "{good:?}");
}

fn rules_tsx(code: &str) -> Vec<String> {
    let a = proof_it_lang_ts::analyze("c.tsx", code, &HashSet::new()).expect("parse");
    a.findings.into_iter().map(|f| f.rule_id).collect()
}

#[test]
fn expression_evaluators() {
    case(
        "SEC-CODE-INJECTION",
        "function calc(req, res) { res.send(String(mathjs.eval(req.body.eqn))); }",
        "function calc(req, res) { res.send(String(mathjs.eval('1 + 1'))); }",
    );
}

#[test]
fn destructured_and_interprocedural_taint() {
    case(
        "SEC-OPEN-REDIRECT",
        "export function go() { return ({ query }: Request, res: Response) => { const to = query.to as string; res.redirect(to); }; }",
        "export function go() { return ({ query }: Request, res: Response) => { res.redirect('/home'); }; }",
    );
    case(
        "SEC-PATH-TRAVERSAL",
        "export function serve() { return ({ params }: Request, res: Response) => { const file = params.file; verify(file, res); }; function verify(file: string, res: Response) { res.sendFile(path.resolve('ftp/', file)); } }",
        "export function serve() { return ({ params }: Request, res: Response) => { verify('readme.md', res); }; function verify(file: string, res: Response) { res.sendFile(path.resolve('ftp/', file)); } }",
    );
}

#[test]
fn more_injection_classes() {
    case(
        "SEC-CODE-INJECTION",
        "function h(req) { const sandbox = { safeEval, data: req.body.orderLines }; vm.runInContext('safeEval(data)', sandbox); }",
        "function h(req) { const sandbox = { n: 1 }; vm.runInContext('n + 1', sandbox); }",
    );
    case(
        "SEC-NOSQLI",
        "function h(req) { db.reviewsCollection.update({ _id: req.body.id }, { $set: { message: req.body.message } }, { multi: true }); }",
        "function h(req) { db.reviewsCollection.update({ _id: String(req.body.id) }, { $set: { message: req.body.message } }); }",
    );
    case(
        "SEC-XXE",
        "vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true })', sandbox);",
        "vm.runInContext('libxml.parseXml(data, { noblanks: true })', sandbox);",
    );
    case(
        "SEC-ZIP-SLIP",
        "for (const entry of dir.files) { const fileName = entry.path; entry.stream().pipe(fs.createWriteStream('uploads/' + fileName)); }",
        "for (const entry of dir.files) { fs.createWriteStream('uploads/' + randomUUID()); }",
    );
    case(
        "SEC-WEAK-HASH",
        "export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex');",
        "export const etag = (data: string) => crypto.createHash('md5').update(data).digest('hex');",
    );
    case("SEC-JWT-ALG-UNPINNED", "jwt.verify(token, publicKey, cb);", "jwt.verify(token, publicKey, { algorithms: ['RS256'] }, cb);");
}

#[test]
fn libxml2_flags() {
    case(
        "SEC-XXE",
        "const option = libxml2.ParseOption.XML_PARSE_NOENT | libxml2.ParseOption.XML_PARSE_NOBLANKS;",
        "const option = libxml2.ParseOption.XML_PARSE_NOBLANKS;",
    );
}

#[test]
fn structured_logging_is_not_injection() {
    case(
        "SEC-LOG-INJECTION",
        "function h(req) { logger.info(`login failed for ${req.body.user}`); }",
        "function h(req) { logger.info('login failed', { user: req.body.user }); }",
    );
}

#[test]
fn uploads() {
    case(
        "SEC-UNRESTRICTED-UPLOAD",
        "const upload = multer({ dest: 'uploads/' });",
        "const upload = multer({ dest: 'uploads/', limits: { fileSize: 1e6 }, fileFilter: imagesOnly });",
    );
}

#[test]
fn option_objects_passed_by_name() {
    case(
        "SEC-CORS",
        "const corsOptions = { origin: true, credentials: true };\napp.use(cors(corsOptions));",
        "const corsOptions = { origin: ['https://app.example'], credentials: true };\napp.use(cors(corsOptions));",
    );
    case(
        "SEC-XXE",
        "const optionsXml = { noent: true };\nfunction h(req, res) { libxml.parseXml(req.body.xml, optionsXml); }",
        "const optionsXml = { noent: false };\nfunction h(req, res) { libxml.parseXml(req.body.xml, optionsXml); }",
    );
}

#[test]
fn reflected_cors_origin() {
    case(
        "SEC-CORS",
        "function h(req, res) { res.header('Access-Control-Allow-Origin', req.get('origin')); res.header('Access-Control-Allow-Credentials', true); }",
        "function h(req, res) { res.header('Access-Control-Allow-Origin', 'https://app.example'); }",
    );
}

#[test]
fn header_injection() {
    case(
        "SEC-HEADER-INJECTION",
        "function h(req, res) { res.setHeader('Location', req.query.next); res.end(); }",
        "function h(req, res) { res.setHeader('Location', '/home'); res.end(); }",
    );
}

#[test]
fn xpath_injection() {
    case(
        "SEC-XPATH-INJECTION",
        "function h(req, res) { const v = decodeURI(req.params.release); xpath.evaluate(\"//config/release[text()='\" + v + \"']\", doc, null, 0, null); }",
        "function h(req, res) { xpath.evaluate(\"//config/release\", doc, null, 0, null); }",
    );
}

#[test]
fn xml_injection() {
    case(
        "SEC-XML-INJECTION",
        "function h(req, res) { const u = req.body.username; res.set('Content-Type', 'application/xml'); res.send(`<profile><username>${u}</username></profile>`); }",
        "function h(req, res) { const u = escapeXml(req.body.username); res.set('Content-Type', 'application/xml'); res.send(`<profile><username>${u}</username></profile>`); }",
    );
    // SOAP: the value comes from a parsed request document.
    case(
        "SEC-XML-INJECTION",
        "function h(req, res) { const d = libxml.parseXml(req.body); const name = d.get('//username').text(); res.send(`<soapenv:Body><username>${name}</username></soapenv:Body>`); }",
        "function h(req, res) { res.send(`<soapenv:Body><username>${'fixed'}</username></soapenv:Body>`); }",
    );
}

#[test]
fn log_store_injection() {
    case(
        "SEC-LOG-INJECTION",
        "const loginLogs = [];\nfunction h(req, res) { loginLogs.push(`login from ${req.body.username}`); }",
        "const catalogs = [];\nfunction h(req, res) { catalogs.push(req.body.item); }",
    );
}

#[test]
fn graphql_introspection_and_resolver_arguments() {
    case(
        "SEC-GRAPHQL-INTROSPECTION",
        "const server = new ApolloServer({ introspection: true, schema });",
        "const server = new ApolloServer({ introspection: process.env.NODE_ENV !== 'production', schema });",
    );
    case(
        "SEC-PATH-TRAVERSAL",
        "const typeDefs = gql`type Mutation { upload(path: String): String }`;\nconst resolvers = { Mutation: { upload: async (parent, args, context) => { const p = '/srv/uploads/' + args.path; await fsPromise.writeFile(p, args.content); } } };",
        "const typeDefs = gql`type Mutation { upload(path: String): String }`;\nconst resolvers = { Mutation: { upload: async (parent, args, context) => { const p = '/srv/uploads/' + path.basename(args.path); await fsPromise.writeFile(p, args.content); } } };",
    );
}

#[test]
fn rpc_method_parameters_are_sources() {
    case(
        "SEC-SSRF",
        "const xmlrpc = require('xmlrpc');\nconst methods = { 'check': function (params, callback) { const url = params.toString(); needle.get(url, {}, () => {}); callback(null, 'ok'); } };",
        "const xmlrpc = require('xmlrpc');\nconst methods = { 'check': function (params, callback) { needle.get('https://status.example', {}, () => {}); callback(null, 'ok'); } };",
    );
}

#[test]
fn sql_built_in_steps() {
    case(
        "SEC-SQLI",
        "async function h(req, res) { const { status } = req.query; let q = `SELECT * FROM t WHERE a = 1`; if (status) { q += ` AND status = '${status}'`; } await prisma.$queryRawUnsafe(q); }",
        "async function h(req, res) { const { status } = req.query; let q = `SELECT * FROM t WHERE a = 1`; if (status) { q += ` AND status = $1`; } await prisma.$queryRawUnsafe(q, status); }",
    );
    // The parameterised form is not even dynamic SQL.
    let r = rules(
        "async function h(req, res) { let q = `SELECT * FROM t WHERE a = 1`; q += ` AND status = $1`; await prisma.$queryRawUnsafe(q, req.query.status); }",
    );
    assert!(!r.iter().any(|x| x == "SEC-DYNAMIC-SQL" || x == "SEC-SQLI"), "{r:?}");
}

#[test]
fn taint_through_regex_matches() {
    case(
        "SEC-CMDI",
        "function h(req, res) { const item = req.body.content; const url = item.match(/\\((http.*)\\)/)[1]; exec('identify ' + url, () => {}); }",
        "function h(req, res) { const item = req.body.content; const ok = /^[a-z]+$/.test(item); exec('identify fixed.png', () => {}); }",
    );
    case(
        "SEC-CMDI",
        "function h(req, res) { const re = /url=(\\S+)/; const m = re.exec(req.query.q); exec('curl ' + m[1]); }",
        "function h(req, res) { const re = /url=(\\S+)/; const m = re.exec('url=x'); exec('curl ' + m[1]); }",
    );
}

#[test]
fn request_object_as_template_locals() {
    case(
        "SEC-SSTI",
        "function h(req, res) { const profile = req.body; if (validator.isEmail(profile.email)) { return res.render('account.hbs', profile); } }",
        "function h(req, res) { const profile = { email: req.body.email, name: req.body.name }; return res.render('account.hbs', profile); }",
    );
    case("SEC-SSTI", "function h(req, res) { res.render('page', { ...req.query }); }", "function h(req, res) { res.render('page', { q: req.query.q }); }");
}

#[test]
fn plaintext_passwords() {
    case(
        "SEC-PLAINTEXT-PASSWORD",
        "function login(req, res) { User.find({ username: req.body.username, password: req.body.password }, cb); }",
        "async function login(req, res) { const u = await User.findOne({ username: req.body.username }); const ok = await bcrypt.compare(req.body.password, u.password); }",
    );
    case(
        "SEC-PLAINTEXT-PASSWORD",
        "async function login(req, res) { await prisma.user.findFirst({ where: { email: req.body.email, password: req.body.password } }); }",
        "async function login(req, res) { await prisma.user.findFirst({ where: { email: req.body.email } }); }",
    );
    case(
        "SEC-PLAINTEXT-PASSWORD",
        "async function login(req, res) { await db.query('SELECT * FROM users WHERE email = $1 AND password = $2', [req.body.email, req.body.password]); }",
        "async function login(req, res) { await db.query('SELECT id, password_hash FROM users WHERE email = $1', [req.body.email]); }",
    );
}

#[test]
fn session_cookie_without_secure() {
    case(
        "SEC-SESSION-DEFAULTS",
        "app.use(session({ secret: process.env.S, cookie: { path: '/' } }));",
        "app.use(session({ secret: process.env.S, cookie: { path: '/', secure: process.env.NODE_ENV === 'production', httpOnly: true } }));",
    );
}

#[test]
fn spoofable_client_ip() {
    case(
        "SEC-SPOOFABLE-CLIENT-IP",
        "const rateLimitMap = new Map();\nfunction limiter(req, res, next) { const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress; if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []); next(); }",
        "const rateLimitMap = new Map();\nfunction limiter(req, res, next) { const ip = req.ip; if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []); next(); }",
    );
    case(
        "SEC-SPOOFABLE-CLIENT-IP",
        "app.use(rateLimit({ windowMs: 60000, max: 5, keyGenerator: (req) => req.headers['x-forwarded-for'] }));",
        "app.use(rateLimit({ windowMs: 60000, max: 5, keyGenerator: (req) => req.ip }));",
    );
    case("SEC-SPOOFABLE-CLIENT-IP", "app.set('trust proxy', true);", "app.set('trust proxy', 1);");
    case("SEC-SPOOFABLE-CLIENT-IP", "app.enable('trust proxy');", "app.set('trust proxy', ['loopback', 'uniquelocal']);");
}

#[test]
fn sanitizers_are_judged_by_their_code() {
    // A "sanitizer" that returns its input unchanged does not clear taint.
    case(
        "SEC-SQLI",
        "function sanitizeInput(x) { return x; }\nasync function h(req, res) { const q = sanitizeInput(req.query.q); await db.query(`SELECT * FROM t WHERE n = '${q}'`); }",
        "function sanitizeInput(x) { return String(x).replace(/[^a-z0-9]/gi, ''); }\nasync function h(req, res) { const q = sanitizeInput(req.query.q); await db.query(`SELECT * FROM t WHERE n = '${q}'`); }",
    );
    // Taint flows through ordinary local helpers.
    case(
        "SEC-CMDI",
        "const buildCmd = (host) => 'ping -c 1 ' + host;\nfunction h(req, res) { exec(buildCmd(req.body.host)); }",
        "const buildCmd = (host) => 'ping -c 1 localhost';\nfunction h(req, res) { exec(buildCmd(req.body.host)); }",
    );
}
