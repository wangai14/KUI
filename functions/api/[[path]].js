// ==========================================
// KUI Serverless 聚合网关后端 - 探针全量数据吸收 + 自动热修复完全体
// ==========================================

async function sha256(text) {
    const buffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// D1 数据库自动无损热挂载高级探针字段
async function ensureDbSchema(db) {
    try { await db.prepare("SELECT username FROM nodes LIMIT 1").first(); } 
    catch (e) { try { await db.prepare("ALTER TABLE nodes ADD COLUMN username TEXT DEFAULT 'admin'").run(); } catch(e){} }
    
    try { await db.prepare("SELECT username FROM users LIMIT 1").first(); } 
    catch (e) {
        try {
            await db.prepare(`CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY, password TEXT NOT NULL, 
                traffic_limit INTEGER DEFAULT 0, traffic_used INTEGER DEFAULT 0, 
                expire_time INTEGER DEFAULT 0, enable INTEGER DEFAULT 1
            )`).run();
        } catch(e){}
    }

    // 动态追加高级探针监控字段
    const newCols = [
        'disk INTEGER DEFAULT 0', 
        'load TEXT DEFAULT ""', 
        'uptime TEXT DEFAULT ""', 
        'net_in_speed INTEGER DEFAULT 0', 
        'net_out_speed INTEGER DEFAULT 0', 
        'tcp_conn INTEGER DEFAULT 0', 
        'udp_conn INTEGER DEFAULT 0'
    ];
    for (let col of newCols) { 
        try { await db.prepare(`ALTER TABLE servers ADD COLUMN ${col}`).run(); } catch(err){} 
    }
}

async function verifyAuth(authHeader, db, env) {
    if (!authHeader) return null;
    const adminUser = env.ADMIN_USERNAME || "admin";
    const adminPass = env.ADMIN_PASSWORD || "admin";

    if (authHeader === adminPass || authHeader === await sha256(adminPass)) return adminUser;

    const parts = authHeader.split('.');
    if (parts.length !== 3) return null;
    const [b64User, timestamp, clientSig] = parts;

    if (Math.abs(Date.now() - parseInt(timestamp)) > 300000) return null;

    const username = atob(b64User);
    let baseKeyHex;
    if (username === adminUser) {
        baseKeyHex = await sha256(adminPass);
    } else {
        const u = await db.prepare("SELECT password FROM users WHERE username = ?").bind(username).first();
        if (!u) return null;
        baseKeyHex = u.password;
    }

    const keyBytes = new Uint8Array(baseKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(username + timestamp));
    const expectedSig = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');

    return clientSig === expectedSig ? username : null;
}

export async function onRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const method = request.method;
    const action = params.path ? params.path[0] : ''; 
    const db = env.DB; 

    // [1] Agent 探针上报接口 (全量吸收硬件监控指标 + 自我修复容错)
    if (action === "report" && method === "POST") {
        if (!(await verifyAuth(request.headers.get("Authorization"), db, env))) return new Response("Unauthorized", { status: 401 });
        const data = await request.json(); 
        const nowMs = Date.now();
        
        // 🌟 容错核心：尝试写入，如果因为缺字段失败，立刻升级数据库再重试
        try {
            await db.prepare("UPDATE servers SET cpu=?, mem=?, disk=?, load=?, uptime=?, net_in_speed=?, net_out_speed=?, tcp_conn=?, udp_conn=?, last_report=?, alert_sent=0 WHERE ip=?").bind(
                data.cpu||0, data.mem||0, data.disk||0, data.load||'', data.uptime||'', data.net_in_speed||0, data.net_out_speed||0, data.tcp_conn||0, data.udp_conn||0, nowMs, data.ip
            ).run();
        } catch (e) {
            // 捕获到表结构不匹配异常，触发热升级
            await ensureDbSchema(db);
            // 重新写入数据，防止本次心跳丢失
            await db.prepare("UPDATE servers SET cpu=?, mem=?, disk=?, load=?, uptime=?, net_in_speed=?, net_out_speed=?, tcp_conn=?, udp_conn=?, last_report=?, alert_sent=0 WHERE ip=?").bind(
                data.cpu||0, data.mem||0, data.disk||0, data.load||'', data.uptime||'', data.net_in_speed||0, data.net_out_speed||0, data.tcp_conn||0, data.udp_conn||0, nowMs, data.ip
            ).run();
        }
        
        const stmts = [];
        let totalDelta = 0;
        if (data.node_traffic && data.node_traffic.length > 0) {
            for (let nt of data.node_traffic) {
                stmts.push(db.prepare("UPDATE nodes SET traffic_used = traffic_used + ? WHERE id = ?").bind(nt.delta_bytes, nt.id));
                stmts.push(db.prepare(`UPDATE users SET traffic_used = traffic_used + ? WHERE username = (SELECT username FROM nodes WHERE id = ?)`).bind(nt.delta_bytes, nt.id));
                totalDelta += nt.delta_bytes;
            }
        }
        
        if (data.argo_urls && data.argo_urls.length > 0) {
            for (let argo of data.argo_urls) {
                stmts.push(db.prepare("UPDATE nodes SET sni = ? WHERE id = ? AND protocol = 'VLESS-Argo' AND sni != ?").bind(argo.url, argo.id, argo.url));
            }
        }

        if (totalDelta > 0) stmts.push(db.prepare("INSERT INTO traffic_stats (ip, delta_bytes, timestamp) VALUES (?, ?, ?)").bind(data.ip, totalDelta, nowMs));
        if (stmts.length > 0) await db.batch(stmts);
        return Response.json({ success: true });
    }

    // [2] Agent 探针拉取配置接口
    if (action === "config" && method === "GET") {
        if (!(await verifyAuth(request.headers.get("Authorization"), db, env))) return new Response("Unauthorized", { status: 401 });
        const ip = url.searchParams.get("ip");
        const now = Date.now();
        const adminUser = env.ADMIN_USERNAME || "admin";

        const query = `
            SELECT n.* FROM nodes n
            LEFT JOIN users u ON n.username = u.username
            WHERE n.vps_ip = ? AND n.enable = 1 
            AND (n.traffic_limit = 0 OR n.traffic_used < n.traffic_limit)
            AND (n.expire_time = 0 OR n.expire_time > ?)
            AND (
                n.username = ? OR n.username = 'admin' OR (
                    u.username IS NOT NULL AND u.enable = 1 
                    AND (u.traffic_limit = 0 OR u.traffic_used < u.traffic_limit)
                    AND (u.expire_time = 0 OR u.expire_time > ?)
                )
            )
        `;
        const { results: machineNodes } = await db.prepare(query).bind(ip, now, adminUser, now).all();
        
        for (let node of machineNodes) {
            if (node.protocol === "dokodemo-door" && node.relay_type === "internal") {
                const targetNode = await db.prepare("SELECT * FROM nodes WHERE id = ?").bind(node.target_id).first();
                if (targetNode) node.chain_target = { ip: targetNode.vps_ip, port: targetNode.port, protocol: targetNode.protocol, uuid: targetNode.uuid, sni: targetNode.sni, public_key: targetNode.public_key, short_id: targetNode.short_id };
            }
        }
        return Response.json({ success: true, configs: machineNodes });
    }

    // [3] 全量聚合订阅接口 (修复了 TUIC 客户端的证书拦截问题)
    if (action === "sub" && method === "GET") {
        const ip = url.searchParams.get("ip");
        const reqUser = url.searchParams.get("user");
        const token = url.searchParams.get("token");
        const adminUser = env.ADMIN_USERNAME || "admin";

        let isValid = false;
        if (reqUser === adminUser) {
            isValid = (token === await sha256(env.ADMIN_PASSWORD || "admin"));
        } else {
            const u = await db.prepare("SELECT password FROM users WHERE username = ?").bind(reqUser).first();
            if (u && token === u.password) isValid = true;
        }
        if (!isValid) return new Response("Forbidden", { status: 403 });

        const now = Date.now();
        let query;
        let sqlParams = [now];

        if (reqUser === adminUser) {
            query = `SELECT * FROM nodes WHERE enable = 1 AND (traffic_limit = 0 OR traffic_used < traffic_limit) AND (expire_time = 0 OR expire_time > ?) AND (username = ? OR username = 'admin')`;
            sqlParams.push(adminUser);
            if (ip) { query += " AND vps_ip = ?"; sqlParams.push(ip); }
        } else {
            query = `
                SELECT n.* FROM nodes n 
                JOIN users u ON n.username = u.username 
                WHERE n.enable = 1 AND (n.traffic_limit = 0 OR n.traffic_used < n.traffic_limit) 
                AND (n.expire_time = 0 OR n.expire_time > ?) 
                AND n.username = ? AND u.enable = 1 AND (u.traffic_limit = 0 OR u.traffic_used < u.traffic_limit) AND (u.expire_time = 0 OR u.expire_time > ?)
            `;
            sqlParams.push(reqUser, now);
            if (ip) { query += " AND n.vps_ip = ?"; sqlParams.push(ip); }
        }

        const { results } = await db.prepare(query).bind(...sqlParams).all();
        let subLinks = [];
        
        for (let node of results) {
            const vpsInfo = await db.prepare("SELECT name FROM servers WHERE ip = ?").bind(node.vps_ip).first();
            const remark = encodeURIComponent(`${vpsInfo ? vpsInfo.name : 'KUI'} | ${node.protocol}_${node.port}`);
            
            if (node.protocol === "VLESS") {
                subLinks.push(`vless://${node.uuid}@${node.vps_ip}:${node.port}?encryption=none&security=none&type=tcp#${remark}`);
            } else if (node.protocol === "Reality") {
                subLinks.push(`vless://${node.uuid}@${node.vps_ip}:${node.port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${node.sni}&fp=chrome&pbk=${node.public_key}&sid=${node.short_id}&type=tcp&headerType=none#${remark}-Reality`);
            } else if (node.protocol === "Hysteria2") {
                subLinks.push(`hysteria2://${node.uuid}@${node.vps_ip}:${node.port}/?insecure=1&sni=${node.sni}#${remark}-Hy2`);
            } else if (node.protocol === "TUIC") {
                subLinks.push(`tuic://${node.uuid}:${node.private_key}@${node.vps_ip}:${node.port}?sni=${node.sni}&congestion_control=bbr&alpn=h3&allow_insecure=1#${remark}-TUIC`);
            } else if (node.protocol === "Socks5") {
                const auth = btoa(`${node.uuid}:${node.private_key}`);
                subLinks.push(`socks5://${auth}@${node.vps_ip}:${node.port}#${remark}-Socks5`);
            } else if (node.protocol === "VLESS-Argo" && !node.sni.includes('等待')) {
                subLinks.push(`vless://${node.uuid}@${node.sni}:443?encryption=none&security=tls&type=ws&host=${node.sni}&path=%2F#${remark}-Argo`);
            }
        }

        return new Response(btoa(unescape(encodeURIComponent(subLinks.join('\n')))), { headers: { "Content-Type": "text/plain; charset=utf-8" }});
    }

    if (action === "login" && method === "POST") {
        const username = await verifyAuth(request.headers.get("Authorization"), db, env);
        if (username) {
            if (username === (env.ADMIN_USERNAME || "admin")) await ensureDbSchema(db);
            return Response.json({ success: true, role: username === (env.ADMIN_USERNAME || "admin") ? 'admin' : 'user' });
        }
        return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    // ==============================================
    // 面板内部管理接口屏障
    // ==============================================
    const currentUser = await verifyAuth(request.headers.get("Authorization"), db, env);
    const isAdmin = currentUser === (env.ADMIN_USERNAME || "admin");
    if (!currentUser) return Response.json({ error: "Unauthorized" }, { status: 401 });

    try {
        if (action === "data") {
            const servers = (await db.prepare("SELECT * FROM servers").all()).results;
            const nodes = isAdmin ? (await db.prepare("SELECT * FROM nodes").all()).results : (await db.prepare("SELECT * FROM nodes WHERE username = ?").bind(currentUser).all()).results;
            const users = isAdmin ? (await db.prepare("SELECT * FROM users").all()).results : (await db.prepare("SELECT * FROM users WHERE username = ?").bind(currentUser).all()).results;
            return Response.json({ servers, nodes, users });
        }
        
        if (action === "stats" && method === "GET" && isAdmin) {
            const query = `SELECT strftime('%m-%d', datetime(timestamp / 1000, 'unixepoch', 'localtime')) as day, SUM(delta_bytes) as total_bytes FROM traffic_stats WHERE ip = ? AND timestamp > ? GROUP BY day ORDER BY day ASC`;
            const { results } = await db.prepare(query).bind(url.searchParams.get("ip"), Date.now() - 604800000).all();
            return Response.json(results || []);
        }
        
        if (action === "users" && isAdmin) {
            if (method === "POST") {
                const { username, password, traffic_limit, expire_time } = await request.json();
                const hash = await sha256(password);
                await db.prepare("INSERT INTO users (username, password, traffic_limit, expire_time) VALUES (?, ?, ?, ?)").bind(username, hash, traffic_limit, expire_time).run();
                return Response.json({ success: true });
            }
            if (method === "PUT") {
                const { username, enable, reset_traffic } = await request.json();
                if (reset_traffic) await db.prepare("UPDATE users SET traffic_used = 0 WHERE username = ?").bind(username).run();
                else if (enable !== undefined) await db.prepare("UPDATE users SET enable = ? WHERE username = ?").bind(enable, username).run();
                return Response.json({ success: true });
            }
            if (method === "DELETE") {
                const target = url.searchParams.get("username");
                await db.prepare("DELETE FROM users WHERE username = ?").bind(target).run();
                await db.prepare("UPDATE nodes SET username = ? WHERE username = ?").bind(currentUser, target).run();
                return Response.json({ success: true });
            }
        }
        
        if (action === "vps" && isAdmin) {
            if (method === "POST") {
                const { ip, name } = await request.json();
                await db.prepare("INSERT OR IGNORE INTO servers (ip, name, alert_sent) VALUES (?, ?, 0)").bind(ip, name).run();
                return Response.json({ success: true });
            }
            if (method === "DELETE") {
                const ip = url.searchParams.get("ip");
                await db.batch([
                    db.prepare("DELETE FROM nodes WHERE vps_ip = ?").bind(ip),
                    db.prepare("DELETE FROM traffic_stats WHERE ip = ?").bind(ip),
                    db.prepare("DELETE FROM servers WHERE ip = ?").bind(ip)
                ]);
                return Response.json({ success: true });
            }
        }

        if (action === "nodes" && isAdmin) {
            if (method === "POST") {
                const n = await request.json();
                let nodeUser = n.username || currentUser;
                if (nodeUser === 'admin') nodeUser = currentUser; 
                
                await db.prepare(`INSERT INTO nodes (id, uuid, vps_ip, protocol, port, sni, private_key, public_key, short_id, relay_type, target_ip, target_port, target_id, enable, traffic_used, traffic_limit, expire_time, username) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
                    n.id, n.uuid, n.vps_ip, n.protocol, n.port, n.sni||null, n.private_key||null, n.public_key||null, n.short_id||null, n.relay_type||null, n.target_ip||null, n.target_port||null, n.target_id||null, 1, 0, n.traffic_limit||0, n.expire_time||0, nodeUser
                ).run();
                return Response.json({ success: true });
            }
            if (method === "PUT") {
                const { id, enable, reset_traffic } = await request.json();
                if (reset_traffic) await db.prepare("UPDATE nodes SET traffic_used = 0 WHERE id = ?").bind(id).run();
                else if (enable !== undefined) await db.prepare("UPDATE nodes SET enable = ? WHERE id = ?").bind(enable, id).run();
                return Response.json({ success: true });
            }
            if (method === "DELETE") {
                await db.prepare("DELETE FROM nodes WHERE id = ?").bind(url.searchParams.get("id")).run();
                return Response.json({ success: true });
            }
        }

        return new Response("Not Found", { status: 404 });
    } catch (err) { return Response.json({ error: err.message }, { status: 500 }); }
}

export async function onRequestScheduled(context) {
    const { env } = context;
    const db = env.DB;
    const nowMs = Date.now();
    try {
        const { results } = await db.prepare(`SELECT ip, name, last_report FROM servers WHERE last_report < ? AND alert_sent = 0`).bind(nowMs - 180000).all();
        if (results && results.length > 0) {
            const tgBotToken = env.TG_BOT_TOKEN; const tgChatId = env.TG_CHAT_ID;
            const updateStmts = [];
            for (let vps of results) {
                if (tgBotToken && tgChatId) {
                    const text = `⚠️ [KUI 节点失联告警]\n\n节点别名: ${vps.name}\n公网IP: ${vps.ip}\n最后在线: ${new Date(vps.last_report).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}`;
                    await fetch(`https://api.telegram.org/bot${tgBotToken}/sendMessage`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ chat_id: tgChatId, text }) });
                }
                updateStmts.push(db.prepare("UPDATE servers SET alert_sent = 1 WHERE ip = ?").bind(vps.ip));
            }
            if (updateStmts.length > 0) await db.batch(updateStmts);
        }
    } catch (error) {}
}
