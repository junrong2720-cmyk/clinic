/* 中医诊疗系统 · 主程序（纯前端，数据存于浏览器 localStorage） */
(function () {
  'use strict';
  const T = window.TCM;
  const KEY = 'tcm-clinic-v1';
  const DEFAULT_USAGE = '水煎服，每日 1 剂，早晚分温服';
  const NOTES = ['', '先煎', '后下', '包煎', '烊化', '冲服', '另煎', '打碎'];
  const UNITS = ['g', '枚', '片'];
  const ADVICE = ['忌食生冷', '忌辛辣油腻', '调畅情志', '避风寒', '规律作息', '清淡饮食', '7 日后复诊'];

  const $ = (s, el) => (el || document).querySelector(s);
  const main = $('#main'), modal = $('#modal'), toastEl = $('#toast');
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
  const pad = n => String(n).padStart(2, '0');
  const dOnly = iso => { const d = new Date(iso); return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()); };
  const dTime = iso => { const d = new Date(iso); return dOnly(d) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()); };
  const isToday = iso => dOnly(iso) === dOnly(new Date());
  const byDateDesc = (a, b) => new Date(b.date) - new Date(a.date);
  const clone = o => JSON.parse(JSON.stringify(o));

  /* ---------- 数据 ---------- */
  let storageBroken = false;
  let locked = null;                       // 数据已加密但尚未解锁时，这里放密文对象
  let cryptoKey = null, saltB64 = null;    // 解锁后的密钥（只在内存里，密码本身不保存）
  let saveChain = Promise.resolve();
  let db = load();
  let draft = null;
  let pendingYes = null;

  /* 加密：密码经 PBKDF2(SHA-256, 30 万次) 派生 AES-GCM 256 位密钥 */
  const canCrypto = !!(window.crypto && window.crypto.subtle);
  const b64 = buf => { const u = new Uint8Array(buf); let s = ''; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s); };
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  function deriveKey(pw, salt) {
    return crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey'])
      .then(base => crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: 300000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']));
  }
  function encStr(key, str) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(str)).then(ct => ({ iv: b64(iv), ct: b64(ct) }));
  }
  function decStr(key, o) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(o.iv) }, key, unb64(o.ct)).then(buf => new TextDecoder().decode(buf));
  }
  function emptyDb() { return { settings: {}, myFormulas: [], patients: [], visits: [], tomb: {}, draft: null }; }
  // 同步用：每条记录带修改时间 u；删除的记录在 tomb 里留下「已删除」标记
  function touch(o) { o.u = Date.now(); queueSync(2500); return o; }
  function bury(id) { (db.tomb || (db.tomb = {}))[id] = Date.now(); queueSync(2500); }

  function load() {
    try {
      const raw = localStorage.getItem(KEY);
      if (raw) { const d = JSON.parse(raw); if (d && d.enc && d.ct) { locked = d; return emptyDb(); } if (d && Array.isArray(d.patients) && Array.isArray(d.visits)) { d.settings = d.settings || {}; d.myFormulas = d.myFormulas || []; d.tomb = d.tomb || {}; return d; } }
    } catch (e) { storageBroken = true; /* 存储不可用时退回示例数据 */ }
    return seed();
  }
  function save() {
    if (locked) return;   // 未解锁时内存里是空壳，绝不能覆盖密文
    const json = JSON.stringify(db), fail = () => toast('保存失败：浏览器存储不可用或已满', true);
    if (!cryptoKey) { try { localStorage.setItem(KEY, json); } catch (e) { fail(); } return; }
    const key = cryptoKey, salt = saltB64;
    saveChain = saveChain.then(() => encStr(key, json)).then(o => localStorage.setItem(KEY, JSON.stringify({ enc: 1, salt: salt, iv: o.iv, ct: o.ct }))).catch(fail);
  }
  let saveTimer = 0;
  function queueSave() { clearTimeout(saveTimer); saveTimer = setTimeout(save, 400); }

  function seed() {
    const at = (days, h, m) => { const t = new Date(Date.now() - days * 864e5); t.setHours(h, m, 0, 0); return t.toISOString(); };
    const rx = (name, extra, doses) => ({ formula: name + (extra.length ? '加减' : ''), herbs: T.formulaHerbs(name).concat(extra), doses: doses, usage: DEFAULT_USAGE });
    const h = (name, dose) => ({ name: name, dose: dose, unit: 'g', note: '' });
    const base = { pregnant: false, exam: '', demo: true };
    return {
      settings: { clinic: '', doctor: '' },
      myFormulas: [],
      draft: null,
      patients: [
        { id: 'demo-1', name: '陈静怡', gender: '女', birth: '1988-05-12', phone: '13800000001', allergy: '青霉素', history: '慢性浅表性胃炎', note: '', createdAt: at(10, 9, 0), demo: true },
        { id: 'demo-2', name: '王建国', gender: '男', birth: '1964-03-02', phone: '13800000002', allergy: '', history: '高血压病 8 年，服氨氯地平', note: '', createdAt: at(0, 0, 0), demo: true },
        { id: 'demo-3', name: '李晓梅', gender: '女', birth: '1997-09-21', phone: '13800000003', allergy: '', history: '', note: '', createdAt: at(5, 14, 0), demo: true }
      ],
      visits: [
        Object.assign({ id: 'demo-v1', patientId: 'demo-1', date: at(10, 9, 20), type: '初诊', chief: '胃脘胀痛反复半年，加重 1 周', hpi: '半年前因工作压力大出现胃脘胀痛，连及两胁，情绪波动时加重，嗳气后稍舒，时有反酸，纳食减少，二便尚调。', symptoms: ['胃脘痛', '胁肋胀痛', '嗳气', '反酸', '善太息', '情志抑郁', '纳呆'], tongueBody: ['淡红'], tongueCoat: ['薄白'], pulse: ['弦'], disease: '胃痛', western: '慢性浅表性胃炎', syndrome: '肝胃不和证', method: '疏肝理气，和胃止痛', rx: rx('柴胡疏肝散', [h('海螵蛸', 15), h('延胡索', 10)], 7), advice: '忌食生冷辛辣，调畅情志，规律进餐。7 日后复诊。' }, base),
        Object.assign({ id: 'demo-v2', patientId: 'demo-1', date: at(3, 10, 5), type: '复诊', chief: '服药后胃脘胀痛减轻，仍偶有反酸', hpi: '药后胀痛明显减轻，嗳气减少，纳食渐增，偶有反酸，夜寐尚可。', symptoms: ['胃脘痛', '嗳气', '反酸', '纳呆'], tongueBody: ['淡红'], tongueCoat: ['薄白'], pulse: ['弦', '细'], disease: '胃痛', western: '慢性浅表性胃炎', syndrome: '肝胃不和证', method: '疏肝和胃，佐以健脾', rx: rx('柴胡疏肝散', [h('海螵蛸', 15), h('白术', 10)], 7), advice: '效不更方，稍事加减。忌食生冷辛辣。' }, base),
        Object.assign({ id: 'demo-v3', patientId: 'demo-3', date: at(5, 14, 30), type: '初诊', chief: '入睡困难伴多梦 2 月', hpi: '近 2 月备考劳累，入睡困难，多梦易醒，白天乏力健忘，心慌，食欲差。', symptoms: ['失眠', '多梦', '心悸', '健忘', '乏力', '纳呆', '面色萎黄', '神疲'], tongueBody: ['淡白'], tongueCoat: ['薄白'], pulse: ['细', '弱'], disease: '不寐', western: '', syndrome: '心脾两虚证', method: '补益心脾，养血安神', rx: rx('归脾汤', [], 7), advice: '睡前避免饮茶、咖啡及使用手机，适度运动。' }, base),
        Object.assign({ id: 'demo-v4', patientId: 'demo-2', date: new Date(Date.now() - 40 * 60000).toISOString(), type: '初诊', chief: '头晕头胀 1 周', hpi: '1 周前劳累后出现头晕头胀，情绪急躁时加重，伴耳鸣、腰酸、夜寐不安。自测血压 150/95 mmHg。', symptoms: ['头晕', '头痛', '急躁易怒', '腰膝酸软', '耳鸣', '失眠', '口苦', '面红目赤'], tongueBody: ['红'], tongueCoat: ['薄黄'], pulse: ['弦', '细'], disease: '眩晕', western: '高血压病', syndrome: '肝阳上亢证', method: '平肝潜阳，滋养肝肾', rx: rx('天麻钩藤饮', [], 7), advice: '监测血压，继续服用降压药；忌烟酒辛辣，保证睡眠。' }, base)
      ]
    };
  }

  const draftDirty = () => { const d = db.draft; return !!d && !!(d.id || d.chief || d.hpi || d.symptoms.length || d.tongueBody.length || d.tongueCoat.length || d.pulse.length || d.rx.herbs.length || d.syndrome || (d.photos || []).length); };
  const P = id => db.patients.find(p => p.id === id);
  const V = id => db.visits.find(v => v.id === id);
  const visitsOf = pid => db.visits.filter(v => v.patientId === pid).sort(byDateDesc);
  function ageOf(p) {
    const n = new Date();
    if (p.birth) { const b = new Date(p.birth); let a = n.getFullYear() - b.getFullYear(); if (n < new Date(n.getFullYear(), b.getMonth(), b.getDate())) a--; return a; }
    if (p.birthYear) return n.getFullYear() - p.birthYear;
    return null;
  }
  const ageText = p => { const a = ageOf(p); return a == null ? '—' : a + ' 岁'; };
  const dxText = v => [v.disease, v.syndrome].filter(Boolean).join(' · ') || '—';
  const rxText = v => { const n = v.rx.herbs.length; return n ? (v.rx.formula || '自拟方') + '（' + n + ' 味 × ' + v.rx.doses + ' 剂）' : '未开方'; };
  const fourText = v => [v.symptoms.join('、'), [v.tongueBody.length ? '舌' + v.tongueBody.join('、') : '', v.tongueCoat.length ? '苔' + v.tongueCoat.join('、') : ''].filter(Boolean).join('，'), v.pulse.length ? '脉' + v.pulse.join('') : ''].filter(Boolean).join('；');
  const tongueText = v => [v.tongueBody.length ? '舌' + v.tongueBody.join('、') : '', v.tongueCoat.length ? '苔' + v.tongueCoat.join('、') : ''].filter(Boolean).join('，');
  const herbLabel = h => esc(h.name) + ' ' + (h.dose === '' ? '' : h.dose) + esc(h.unit) + (h.note ? '<small>' + esc(h.note) + '</small>' : '');

  /* ---------- 辨证与处方审核 ---------- */
  function diagnose(d) {
    const S = new Set(d.symptoms), TB = new Set(d.tongueBody), TC = new Set(d.tongueCoat), PU = new Set(d.pulse);
    return T.SYNDROMES.map(sy => {
      const mainHit = sy.main.filter(x => S.has(x)), minorHit = sy.minor.filter(x => S.has(x));
      const tHit = sy.tongue.filter(x => TB.has(x)), cHit = sy.coat.filter(x => TC.has(x)), pHit = sy.pulse.filter(x => PU.has(x));
      const cap = Math.min(sy.minor.length, 4), need = sy.pulseNeed || sy.pulse.length;
      const score = mainHit.length * 3 + Math.min(minorHit.length, cap) + (tHit.length ? 2 : 0) + (cHit.length ? 2 : 0) + (need ? 3 * Math.min(1, pHit.length / need) : 0);
      const total = sy.main.length * 3 + cap + (sy.tongue.length ? 2 : 0) + (sy.coat.length ? 2 : 0) + (need ? 3 : 0);
      return { sy: sy, score: score, ratio: score / total, mainHit: mainHit, minorHit: minorHit, tHit: tHit, cHit: cHit, pHit: pHit, missing: sy.main.filter(x => !S.has(x)) };
    }).filter(r => r.mainHit.length > 0 && r.score >= 5).sort((a, b) => b.ratio - a.ratio || b.score - a.score).slice(0, 5);
  }

  function checkRx(rx, ctx) {
    const out = [], herbs = rx.herbs.filter(h => h.name && h.name.trim());
    const names = herbs.map(h => h.name.trim());
    const has = keys => names.filter(n => keys.some(k => n.indexOf(k) >= 0));
    T.FAN.forEach(g => {
      const a = has(g.a).filter(n => !(g.not || []).some(x => n.indexOf(x) >= 0)), b = has(g.b);
      if (a.length && b.length) out.push({ lv: 'danger', text: '十八反：' + a.join('、') + ' 与 ' + b.join('、') + ' 同用（' + g.label + '）' });
    });
    T.WEI.forEach(pair => {
      const a = has([pair[0]]), b = has([pair[1]]);
      if (a.length && b.length) out.push({ lv: 'danger', text: '十九畏：' + a[0] + ' 与 ' + b[0] + ' 同用' });
    });
    has(T.BANNED).forEach(n => out.push({ lv: 'danger', text: n + ' 含马兜铃酸，已取消药用标准，请改用替代品' }));
    if (ctx && ctx.pregnant) {
      const f = has(T.PREG_FORBID), c = has(T.PREG_CAUTION).filter(n => f.indexOf(n) < 0);
      if (f.length) out.push({ lv: 'danger', text: '妊娠禁用：' + f.join('、') });
      if (c.length) out.push({ lv: 'warn', text: '妊娠慎用：' + c.join('、') });
    }
    herbs.forEach(h => {
      const n = h.name.trim();
      const key = Object.keys(T.DOSE_CAP).filter(k => n.indexOf(k) >= 0).sort((a, b) => b.length - a.length)[0];
      if (h.dose === '' || h.dose == null || !(h.dose > 0)) { out.push({ lv: 'warn', text: n + ' 未填剂量' }); return; }
      if (!key || h.unit !== 'g') return;
      const cap = T.DOSE_CAP[key];
      if (h.dose > cap[0]) out.push({ lv: 'warn', text: n + ' ' + h.dose + 'g 超过《中国药典》常用量上限 ' + cap[0] + 'g' + (cap[1] ? '（' + cap[1] + '）' : '') + '，请确认' });
      else if (/先煎/.test(cap[1]) && h.note !== '先煎') out.push({ lv: 'warn', text: n + ' 宜先煎久煎，请标注煎法' });
    });
    const dup = names.filter((n, i) => names.indexOf(n) !== i);
    if (dup.length) out.push({ lv: 'warn', text: '重复药味：' + Array.from(new Set(dup)).join('、') });
    return out;
  }

  /* ---------- 通用界面 ---------- */
  let toastTimer = 0;
  function toast(msg, err) {
    toastEl.textContent = msg; toastEl.className = 'toast' + (err ? ' err' : ''); toastEl.hidden = false;
    clearTimeout(toastTimer); toastTimer = setTimeout(() => { toastEl.hidden = true; }, 2600);
  }
  function openModal(html, wide) {
    modal.innerHTML = '<div class="modal-box' + (wide ? ' wide' : '') + '" role="dialog" aria-modal="true">' + html + '</div>';
    modal.hidden = false;
    const f = $('input,select,textarea,button', modal); if (f) f.focus();
  }
  function closeModal() { modal.hidden = true; modal.innerHTML = ''; pendingYes = null; }
  function confirmBox(title, body, yesLabel, onYes, danger) {
    pendingYes = onYes;
    openModal('<h2>' + esc(title) + '</h2><div>' + body + '</div><div class="acts"><button class="btn" data-act="modal-close">取消</button><button class="btn ' + (danger ? 'danger' : 'primary') + '" data-act="modal-yes">' + esc(yesLabel) + '</button></div>');
  }
  const go = to => { if (location.hash === '#' + to) route(); else location.hash = to; };

  function visitTable(list, showPatient) {
    if (!list.length) return '<p class="empty">暂无病历</p>';
    return '<div class="tw"><table class="list"><thead><tr><th>就诊时间</th>' + (showPatient ? '<th>患者</th>' : '') + '<th>类型</th><th>主诉</th><th>诊断</th><th>处方</th></tr></thead><tbody>' +
      list.map(v => {
        const p = P(v.patientId) || { name: '（已删除）' };
        return '<tr data-act="go" data-to="visit/' + v.id + '"><td class="nowrap">' + dTime(v.date) + '</td>' + (showPatient ? '<td class="nowrap">' + esc(p.name) + (v.demo ? ' <span class="tag gray">示例</span>' : '') + '</td>' : '') +
          '<td><span class="tag' + (v.type === '初诊' ? ' zhu' : '') + '">' + v.type + '</span></td><td>' + esc(v.chief) + '</td><td>' + esc(dxText(v)) + '</td><td>' + esc(rxText(v)) + '</td></tr>';
      }).join('') + '</tbody></table></div>';
  }

  /* ---------- 舌象照片（压缩后存 IndexedDB，病历里只记编号） ---------- */
  const MAX_PHOTOS = 6;
  const phCache = new Map();
  const idb = (function () {
    let opened;
    const open = () => opened || (opened = new Promise((res, rej) => {
      const r = indexedDB.open('tcm-clinic', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('photos');
      r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
    }));
    const tx = (mode, fn) => open().then(d => new Promise((res, rej) => {
      const t = d.transaction('photos', mode), q = fn(t.objectStore('photos'));
      t.oncomplete = () => res(q.result); t.onerror = t.onabort = () => rej(t.error);
    }));
    return { put: (id, v) => tx('readwrite', s => s.put(v, id)), get: id => tx('readonly', s => s.get(id)), del: id => tx('readwrite', s => s.delete(id)), keys: () => tx('readonly', s => s.getAllKeys()) };
  })();
  const phPut = (id, url) => cryptoKey ? encStr(cryptoKey, url).then(o => idb.put(id, { enc: 1, iv: o.iv, ct: o.ct })) : idb.put(id, url);
  const phGet = id => idb.get(id).then(v => v && v.enc ? decStr(cryptoKey, v) : v);
  // 换密钥（设置 / 修改 / 取消密码）：先用旧密钥读出全部照片，再用新密钥写回
  async function rekey(newKey, newSalt) {
    await saveChain;
    const ks = await idb.keys().catch(() => []), vals = [];
    for (const k of ks) vals.push([k, await phGet(k)]);
    cryptoKey = newKey; saltB64 = newSalt;
    for (const x of vals) if (x[1]) await phPut(x[0], x[1]);
    save(); await saveChain;
  }
  function compress(file) {
    return new Promise((res, rej) => {
      const url = URL.createObjectURL(file), img = new Image();
      img.onload = () => {
        const k = Math.min(1, 1280 / Math.max(img.width, img.height)), c = document.createElement('canvas');
        c.width = Math.round(img.width * k); c.height = Math.round(img.height * k);
        c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
        URL.revokeObjectURL(url); res(c.toDataURL('image/jpeg', 0.82));
      };
      img.onerror = () => { URL.revokeObjectURL(url); rej(new Error('decode')); };
      img.src = url;
    });
  }
  function hydratePhotos(root) {
    (root || document).querySelectorAll('img[data-photo]:not([src])').forEach(img => {
      const id = img.dataset.photo, set = u => { if (u) img.src = u; else img.alt = '照片缺失'; };
      if (phCache.has(id)) set(phCache.get(id));
      else phGet(id).then(u => { if (u) phCache.set(id, u); set(u); }).catch(() => set(null));
    });
  }
  function gcPhotos() {
    if (storageBroken || locked) return;
    const keep = new Set();
    db.visits.concat(db.draft ? [db.draft] : []).forEach(v => (v.photos || []).forEach(p => keep.add(p.id)));
    idb.keys().then(ks => ks.filter(k => !keep.has(k)).forEach(k => { phCache.delete(k); idb.del(k); })).catch(() => {});
  }
  const photoThumbs = (list, removable) => list.map(ph => '<figure class="ph"><img data-photo="' + ph.id + '" data-act="photo-view" data-id="' + ph.id + '" alt="舌象照片">' + (removable ? '<button type="button" class="ph-x" data-act="photo-del" data-id="' + ph.id + '" aria-label="删除这张照片">×</button>' : '') + '</figure>').join('');
  const photoSec = v => (v.photos || []).length ? '<h3>舌象照片</h3><div class="phs">' + photoThumbs(v.photos) + '</div>' : '';
  function renderPhotos() {
    const el = $('#ph-strip'); if (!el || !draft) return;
    el.innerHTML = photoThumbs(draft.photos, true) + (draft.photos.length < MAX_PHOTOS ? '<label class="ph ph-add">＋<span>拍照 / 选图</span><input type="file" class="vh" id="ph-file" accept="image/*" multiple></label>' : '');
    hydratePhotos(el);
  }
  function addPhotos(files) {
    const d = draft, room = MAX_PHOTOS - d.photos.length;
    const list = Array.from(files).filter(f => /^image\//.test(f.type));
    if (!list.length) return;
    if (room <= 0) { toast('每次就诊最多 ' + MAX_PHOTOS + ' 张照片', true); return; }
    let failed = 0;
    list.slice(0, room).reduce((chain, f) => chain.then(() => compress(f)).then(url => {
      const id = uid();
      d.photos.push({ id: id, at: new Date().toISOString() }); phCache.set(id, url);
      return phPut(id, url).catch(err => { d.photos.splice(d.photos.findIndex(p => p.id === id), 1); phCache.delete(id); throw err; });
    }).catch(() => { failed++; }), Promise.resolve()).then(() => {
      if (draft === d) renderPhotos();
      save();
      if (failed) toast(failed + ' 张图片未能保存（HEIC 格式请先转成 JPG）', true);
      else if (list.length > room) toast('只加入了前 ' + room + ' 张，每次就诊最多 ' + MAX_PHOTOS + ' 张', true);
    });
  }
  function viewPhoto(id) {
    const has = v => (v.photos || []).some(p => p.id === id);
    const owner = draft && has(draft) ? draft : db.visits.find(has);
    if (!owner) return;
    const prev = visitsOf(owner.patientId).filter(v => v.id !== owner.id && new Date(v.date) < new Date(owner.date) && (v.photos || []).length)[0];
    const fig = (pid, v, tag) => '<figure><img data-photo="' + pid + '" alt="舌象照片"><figcaption><b>' + tag + '</b>　' + dOnly(v.date) + (tongueText(v) ? '　' + esc(tongueText(v)) : '') + '</figcaption></figure>';
    openModal('<h2>' + (prev ? '舌象对照' : '舌象照片') + '</h2><div class="ph-cmp">' + (prev ? fig(prev.photos[0].id, prev, '上次') : '') + fig(id, owner, prev ? '本次' : '就诊') + '</div><div class="acts"><button class="btn" data-act="modal-close">关闭</button></div>', true);
    hydratePhotos(modal);
  }

  /* ---------- 工作台 ---------- */
  function vDashboard() {
    const today = db.visits.filter(v => isToday(v.date)).length;
    const week = db.visits.filter(v => Date.now() - new Date(v.date) < 7 * 864e5).length;
    const recent = db.visits.slice().sort(byDateDesc).slice(0, 10);
    const dp = draftDirty() && P(db.draft.patientId);
    const hasDemo = db.patients.some(p => p.demo);
    return '<header class="head"><div><h1>工作台</h1><p class="sub">' + new Date().toLocaleDateString('zh-CN', { year: 'numeric', month: 'long', day: 'numeric', weekday: 'long' }) + '</p></div>' +
      '<div class="acts"><button class="btn" data-act="go" data-to="consult">已有患者接诊</button><button class="btn primary" data-act="patient-form" data-then="consult">新患者接诊</button></div></header>' +
      (dp ? '<div class="banner"><span>有一份未保存的接诊草稿：' + esc(dp.name) + '</span><span class="acts"><button class="btn sm" data-act="go" data-to="consult/' + dp.id + (db.draft.id ? '/edit/' + db.draft.id : '') + '">继续填写</button><button class="btn sm" data-act="draft-drop">丢弃</button></span></div>' : '') +
      (hasDemo ? '<div class="banner info"><span>下面带「示例」标记的患者和病历是演示数据，方便你先试用。</span><button class="btn sm" data-act="demo-clear">清除示例数据</button></div>' : '') +
      '<p class="sum">今日接诊 <b>' + today + '</b> 人次<i></i>近 7 日 <b>' + week + '</b> 人次<i></i>在档患者 <b>' + db.patients.length + '</b> 人<i></i>病历 <b>' + db.visits.length + '</b> 份</p>' +
      '<section class="card"><h2>最近病历</h2>' + visitTable(recent, true) + '</section>';
  }

  /* ---------- 患者 ---------- */
  function patientRows(q, pick) {
    q = (q || '').trim().toLowerCase();
    const list = db.patients.filter(p => !q || p.name.toLowerCase().indexOf(q) >= 0 || (p.phone || '').indexOf(q) >= 0)
      .map(p => ({ p: p, vs: visitsOf(p.id) })).sort((a, b) => new Date((b.vs[0] || b.p).date || b.p.createdAt) - new Date((a.vs[0] || a.p).date || a.p.createdAt));
    if (!list.length) return '<p class="empty">' + (q ? '没有匹配的患者' : '还没有患者，点右上角「新建患者」开始') + '</p>';
    return '<div class="tw"><table class="list"><thead><tr><th>姓名</th><th>性别</th><th>年龄</th><th>电话</th><th>过敏史</th><th>就诊</th><th>最近就诊</th><th></th></tr></thead><tbody>' +
      list.map(x => '<tr data-act="go" data-to="' + (pick ? 'consult/' : 'patient/') + x.p.id + '"><td class="nowrap"><b>' + esc(x.p.name) + '</b>' + (x.p.demo ? ' <span class="tag gray">示例</span>' : '') + '</td><td>' + esc(x.p.gender) + '</td><td class="nowrap">' + ageText(x.p) + '</td><td>' + esc(x.p.phone || '—') + '</td><td>' + (x.p.allergy ? '<span class="allergy">' + esc(x.p.allergy) + '</span>' : '<span class="muted">无</span>') + '</td><td>' + x.vs.length + ' 次</td><td class="nowrap">' + (x.vs[0] ? dOnly(x.vs[0].date) : '—') + '</td><td><button class="btn sm" data-act="go" data-to="consult/' + x.p.id + '">接诊</button></td></tr>').join('') +
      '</tbody></table></div>';
  }
  function vPatients(pick) {
    return '<header class="head"><div><h1>' + (pick ? '接诊' : '患者档案') + '</h1><p class="sub">' + (pick ? '选择一位患者开始接诊，或新建患者' : '共 ' + db.patients.length + ' 位患者') + '</p></div>' +
      '<div class="acts"><input id="pq" type="search" placeholder="搜索姓名 / 电话" data-pick="' + (pick ? 1 : '') + '" style="width:200px"><button class="btn primary" data-act="patient-form" data-then="' + (pick ? 'consult' : '') + '">新建患者</button></div></header>' +
      '<section class="card"><div id="plist">' + patientRows('', pick) + '</div></section>';
  }
  function patientInfo(p) {
    return '<dl class="info"><div><dt>性别 / 年龄</dt><dd>' + esc(p.gender) + ' · ' + ageText(p) + (p.birth ? '（' + esc(p.birth) + '）' : '') + '</dd></div><div><dt>电话</dt><dd>' + esc(p.phone || '—') + '</dd></div><div><dt>过敏史</dt><dd>' + (p.allergy ? '<span class="allergy">' + esc(p.allergy) + '</span>' : '无') + '</dd></div><div><dt>既往史</dt><dd>' + esc(p.history || '—') + '</dd></div>' + (p.note ? '<div><dt>备注</dt><dd>' + esc(p.note) + '</dd></div>' : '') + '</dl>';
  }
  function vPatient(p) {
    const vs = visitsOf(p.id);
    return '<header class="head"><div><h1>' + esc(p.name) + (p.demo ? ' <span class="tag gray">示例</span>' : '') + '</h1><p class="sub"><a class="link" href="#patients">患者档案</a> / 详情</p></div>' +
      '<div class="acts"><button class="btn danger" data-act="patient-del" data-id="' + p.id + '">删除</button><button class="btn" data-act="patient-form" data-id="' + p.id + '">编辑资料</button>' + (vs.length ? '<button class="btn" data-act="go" data-to="consult/' + p.id + '/copy">复诊（沿用上次）</button>' : '') + '<button class="btn primary" data-act="go" data-to="consult/' + p.id + '">接诊</button></div></header>' +
      '<section class="card"><h2>基本资料</h2>' + patientInfo(p) + '</section>' +
      (vs.some(v => (v.photos || []).length) ? '<section class="card"><h2>舌象变化</h2><div class="ph-tl">' + vs.filter(v => (v.photos || []).length).reverse().map(v => '<div><div class="phs">' + photoThumbs(v.photos) + '</div><p class="cap">' + dOnly(v.date) + ' ' + v.type + (tongueText(v) ? '<br>' + esc(tongueText(v)) : '') + '</p></div>').join('') + '</div></section>' : '') +
      '<section class="card"><h2>就诊记录（' + vs.length + '）</h2>' + (vs.length ? '<div class="tl">' + vs.map(v => '<div class="tl-i" data-act="go" data-to="visit/' + v.id + '"><div class="tl-d">' + dTime(v.date) + '<br><span class="tag' + (v.type === '初诊' ? ' zhu' : '') + '">' + v.type + '</span></div><div><b>' + esc(v.chief) + '</b><br>' + esc(dxText(v)) + (v.method ? '　治法：' + esc(v.method) : '') + '<br><span class="muted">' + esc(rxText(v)) + '</span></div></div>').join('') + '</div>' : '<p class="empty">尚无就诊记录</p>') + '</section>';
  }
  function patientForm(id, then) {
    const p = id ? P(id) : { name: '', gender: '女', birth: '', phone: '', allergy: '', history: '', note: '' };
    const age = id ? ageOf(p) : null;
    openModal('<h2>' + (id ? '编辑患者资料' : '新建患者') + '</h2><form id="pf" data-id="' + (id || '') + '" data-then="' + (then || '') + '" autocomplete="off"><div class="g2">' +
      '<label class="f req"><span>姓名</span><input type="text" name="name" id="pf-name" required value="' + esc(p.name) + '"></label>' +
      '<label class="f"><span>性别</span><select name="gender" id="pf-gender"><option' + (p.gender === '女' ? ' selected' : '') + '>女</option><option' + (p.gender === '男' ? ' selected' : '') + '>男</option></select></label>' +
      '<label class="f"><span>出生日期</span><input type="date" name="birth" id="pf-birth" value="' + esc(p.birth || '') + '"></label>' +
      '<label class="f"><span>或直接填年龄</span><input type="number" name="age" id="pf-age" min="0" max="120" value="' + (age == null ? '' : age) + '"></label>' +
      '<label class="f"><span>电话</span><input type="tel" name="phone" id="pf-phone" value="' + esc(p.phone || '') + '"></label>' +
      '<label class="f"><span>过敏史</span><input type="text" name="allergy" id="pf-allergy" placeholder="无则留空" value="' + esc(p.allergy || '') + '"></label>' +
      '<label class="f span2"><span>既往史</span><input type="text" name="history" id="pf-history" value="' + esc(p.history || '') + '"></label>' +
      '<label class="f span2"><span>备注</span><input type="text" name="note" id="pf-note" value="' + esc(p.note || '') + '"></label>' +
      '</div><div class="acts"><button type="button" class="btn" data-act="modal-close">取消</button><button class="btn primary">' + (then === 'consult' ? '保存并接诊' : '保存') + '</button></div></form>');
  }
  function savePatient(form) {
    const f = new FormData(form), id = form.dataset.id;
    const name = String(f.get('name')).trim();
    if (!name) { toast('请填写姓名', true); return; }
    const p = id ? P(id) : { id: uid(), createdAt: new Date().toISOString() };
    touch(p); p.name = name; p.gender = f.get('gender'); p.birth = f.get('birth') || '';
    p.birthYear = !p.birth && f.get('age') !== '' ? new Date().getFullYear() - Number(f.get('age')) : null;
    p.phone = String(f.get('phone')).trim(); p.allergy = String(f.get('allergy')).trim(); p.history = String(f.get('history')).trim(); p.note = String(f.get('note')).trim();
    if (!id) db.patients.push(p);
    save(); closeModal(); toast(id ? '资料已更新' : '患者已建档');
    go(form.dataset.then === 'consult' ? 'consult/' + p.id : 'patient/' + p.id);
  }

  /* ---------- 接诊 ---------- */
  function blankDraft(p) {
    return { id: null, patientId: p.id, date: new Date().toISOString(), type: visitsOf(p.id).length ? '复诊' : '初诊', pregnant: false, chief: '', hpi: '', symptoms: [], tongueBody: [], tongueCoat: [], pulse: [], exam: '', disease: '', western: '', syndrome: '', method: '', effect: '', photos: [], rx: { formula: '', herbs: [], doses: 7, usage: DEFAULT_USAGE }, advice: '' };
  }
  const prevOf = d => visitsOf(d.patientId).filter(v => v.id !== d.id && new Date(v.date) < new Date(d.date))[0] || null;
  function prevCard(v, d) {
    if (!v) return '';
    return '<section class="card prevc"><details><summary><b>上次就诊</b>' + dOnly(v.date) + ' ' + v.type + '　' + esc(dxText(v)) + '　' + esc(rxText(v)) + '</summary><div class="rec">' +
      '<h3>主诉</h3><p>' + esc(v.chief) + '</p>' + (fourText(v) ? '<h3>四诊</h3><p>' + esc(fourText(v)) + '</p>' : '') + photoSec(v) + (v.method ? '<h3>治法</h3><p>' + esc(v.method) + '</p>' : '') +
      (v.rx.herbs.length ? '<h3>处方　' + esc(v.rx.formula) + '</h3><div class="herbs">' + v.rx.herbs.map(h => '<span>' + herbLabel(h) + '</span>').join('') + '</div>' : '') + (v.advice ? '<h3>医嘱</h3><p>' + esc(v.advice) + '</p>' : '') + '</div></details>' +
      '<div class="prev-foot"><p class="fine" id="sx-diff"></p><label>上次治疗的疗效<select data-bind="effect" id="c-effect">' + ['', '痊愈', '显效', '有效', '无效'].map(e => '<option value="' + e + '"' + ((d.effect || '') === e ? ' selected' : '') + '>' + (e || '未评价') + '</option>').join('') + '</select></label></div></section>';
  }
  function updateDiff() {
    const el = $('#sx-diff'); if (!el || !draft) return;
    const prev = prevOf(draft); if (!prev) return;
    if (!useFour()) { el.textContent = '点开上面一行可查看上次的病历和处方。'; return; }
    const now = draft.symptoms, was = prev.symptoms;
    const gone = was.filter(x => now.indexOf(x) < 0), added = now.filter(x => was.indexOf(x) < 0), kept = was.length - gone.length;
    el.textContent = !now.length ? '下方带红色底线的选项是上次就诊时的所见，便于对照。'
      : '与上次相比：' + [gone.length ? '已消失 ' + gone.join('、') : '', kept ? '仍有 ' + kept + ' 项' : '', added.length ? '新增 ' + added.join('、') : ''].filter(Boolean).join('；');
  }
  function fxOptions() {
    const cs = Array.from(new Set(T.FORMULAS.map(f => f.cat)));
    return '<option value="">从方剂库选方…</option>' +
      (db.myFormulas.length ? '<optgroup label="我的常用方">' + db.myFormulas.map(f => '<option value="my:' + f.id + '">' + esc(f.name) + '</option>').join('') + '</optgroup>' : '') +
      cs.map(c => '<optgroup label="' + c + '">' + T.FORMULAS.filter(f => f.cat === c).map(f => '<option>' + f.name + '</option>').join('') + '</optgroup>').join('');
  }
  // 四诊点选区（含辨证参考、随症加味）默认关闭，在「设置与备份」里可打开
  const useFour = () => db.settings.showFour === true;
  function prepareDraft(p, mode, vid) {
    if (mode === 'edit' && V(vid)) {
      draft = db.draft && db.draft.id === vid ? db.draft : clone(V(vid));
    } else if (mode === 'copy') {
      const last = visitsOf(p.id)[0];
      draft = blankDraft(p);
      if (last) (useFour() ? ['symptoms', 'tongueBody', 'tongueCoat', 'pulse'] : []).concat(['disease', 'western', 'syndrome', 'method', 'rx', 'pregnant']).forEach(k => { draft[k] = clone(last[k]); });
      draft.type = '复诊';
      history.replaceState(null, '', '#consult/' + p.id);
    } else {
      draft = db.draft && db.draft.patientId === p.id && !db.draft.id ? db.draft : blankDraft(p);
    }
    delete draft.demo;
    draft.photos = draft.photos || [];
    db.draft = draft;
  }
  function vConsult(p) {
    const d = draft;
    const chips = (g, items) => items.map(v => '<button type="button" class="chip' + (d[g].indexOf(v) >= 0 ? ' on' : '') + (prev && prev[g].indexOf(v) >= 0 ? ' was" title="上次就诊时有' : '') + '" data-act="chip" data-g="' + g + '" data-v="' + v + '" aria-pressed="' + (d[g].indexOf(v) >= 0) + '">' + v + '</button>').join('');
    const row = (label, g, items, key) => '<div class="sx-row' + (key ? ' key' : '') + '"><span class="sx-l">' + label + '</span><div class="chips">' + chips(g, items) + '</div></div>';
    const local = new Date(new Date(d.date) - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16);
    const prev = prevOf(d);
    const four = useFour(), steps = four ? ['一', '二', '三', '四', '五'] : ['一', '', '二', '三', '四'];
    const photoHint = '最多 ' + MAX_PHOTOS + ' 张，自动压缩后保存在本机；也可以按 Ctrl+V 直接粘贴截图。点缩略图放大' + (prev ? '，并与上次的舌象对照' : '') + '。';
    return '<header class="head"><div><h1>' + (d.id ? '修改病历' : '接诊') + '</h1><p class="sub"><a class="link" href="#patient/' + p.id + '">' + esc(p.name) + '</a> / ' + (d.id ? '修改 ' + dOnly(d.date) + ' 的病历' : '新病历（自动存草稿）') + '</p></div></header>' +
      '<div class="consult' + (four ? '' : ' nofour') + '">' +
      '<section class="card ptbar"><span class="nm">' + esc(p.name) + '</span><span>' + esc(p.gender) + ' · ' + ageText(p) + '</span>' +
      (p.allergy ? '<span class="allergy">过敏：' + esc(p.allergy) + '</span>' : '') + (p.history ? '<span class="muted">既往：' + esc(p.history) + '</span>' : '') +
      '<label>就诊<select data-bind="type" id="c-type" style="width:auto"><option' + (d.type === '初诊' ? ' selected' : '') + '>初诊</option><option' + (d.type === '复诊' ? ' selected' : '') + '>复诊</option></select></label>' +
      '<label>时间<input type="datetime-local" data-bind="date" id="c-date" value="' + local + '"></label>' +
      (p.gender === '女' ? '<label><input type="checkbox" data-bind="pregnant" id="c-preg"' + (d.pregnant ? ' checked' : '') + '>妊娠期</label>' : '') + '</section>' + prevCard(prev, d) +

      '<section class="card"><h2><span class="step">一</span>主诉与病史</h2><div class="g2"><label class="f req span2"><span>主诉</span><input type="text" data-bind="chief" id="c-chief" placeholder="主要症状 + 持续时间，如：胃脘胀痛反复半年，加重 1 周" value="' + esc(d.chief) + '"></label>' +
      '<label class="f span2"><span>' + (four ? '现病史' : '现病史（含四诊所见、舌脉）') + '</span><textarea data-bind="hpi" id="c-hpi" rows="' + (four ? 3 : 7) + '" placeholder="' + (four ? '起病诱因、症状演变、诊治经过、现在症' : '起病诱因、症状演变、诊治经过、现在症；望闻问切所见，舌象、脉象') + '">' + esc(d.hpi) + '</textarea></label>' +
      (four ? '' : '<div class="span2"><span class="sx-l">舌象照片（可选）</span><div class="phs" id="ph-strip" style="margin-top:6px"></div><p class="fine" style="margin-top:6px">' + photoHint + '</p></div>') + '</div></section>' +

      (four ? '<section class="card"><h2><span class="step">二</span>四诊采集</h2>' +
      T.SYMPTOM_GROUPS.map(g => row(g.name, 'symptoms', g.items)).join('') +
      row('舌质', 'tongueBody', T.TONGUE_BODY, true) + row('舌苔', 'tongueCoat', T.TONGUE_COAT, true) +
      '<div class="sx-row key"><span class="sx-l">舌象照片</span><div><div class="phs" id="ph-strip"></div><p class="fine" style="margin-top:6px">' + photoHint + '</p></div></div>' +
      row('脉象', 'pulse', T.PULSES, true) +
      '<label class="f" style="margin-top:12px"><span>四诊补充（上面没有的症状、体征、检查结果）</span><textarea data-bind="exam" id="c-exam" rows="2">' + esc(d.exam) + '</textarea></label></section>' +

      '<aside class="sg-col"><div class="sg-wrap"><h2>辨证参考</h2><p class="fine">按已选症状、舌、脉与证型库逐条比对，实时更新。</p><div id="suggest"></div></div></aside>' : '') +

      '<section class="card"><h2><span class="step">' + steps[2] + '</span>诊断</h2><div class="g4">' +
      '<label class="f"><span>中医病名</span><input type="text" data-bind="disease" id="c-disease" list="disease-list" value="' + esc(d.disease) + '"></label>' +
      '<label class="f"><span>证型</span><input type="text" data-bind="syndrome" id="c-syndrome" value="' + esc(d.syndrome) + '"></label>' +
      '<label class="f"><span>治法</span><input type="text" data-bind="method" id="c-method" value="' + esc(d.method) + '"></label>' +
      '<label class="f"><span>西医诊断</span><input type="text" data-bind="western" id="c-western" value="' + esc(d.western) + '"></label></div></section>' +

      '<section class="card"><h2><span class="step">' + steps[3] + '</span>处方</h2>' +
      '<div class="rx-cmd"><input type="text" id="rx-quick" list="rx-list" enterkeyhint="done" autocomplete="off" placeholder="直接打字，回车生效。例：柴胡疏肝散 加 延胡索10 海螵蛸15 去 川芎" aria-label="输入方名或药物"><button type="button" class="btn primary" data-act="rx-go">确定</button></div>' +
      '<datalist id="rx-list">' + fxNames().map(f => '<option value="' + esc(f.name) + '">').join('') + T.ALL_HERBS.map(h => '<option value="' + h + '">').join('') + '</datalist>' +
      '<p class="fine" style="margin:6px 0 12px">可以写：<b>方名</b>（载入整方）、<b>合 方名</b>（合方）、<b>药名+剂量</b>（加药；药已在方里就是改剂量）、<b>去 药名</b>（删药）。也可以像例子那样一句写完。</p>' +
      '<div class="rx-tools"><select id="fx-pick" aria-label="浏览方剂库">' + fxOptions() + '</select>' +
      '<button type="button" class="btn" data-act="fx-pick" data-mode="replace">载入</button><button type="button" class="btn" data-act="fx-pick" data-mode="merge">合方</button>' +
      '<button type="button" class="btn" data-act="rx-text">整方文本编辑</button><button type="button" class="btn" data-act="my-save">存为常用方</button><button type="button" class="btn" data-act="rx-undo">撤销</button><button type="button" class="btn danger" data-act="rx-clear">清空</button></div>' +
      '<label class="f" style="margin-bottom:10px"><span>方名</span><input type="text" data-bind="rx.formula" id="c-formula" placeholder="如：柴胡疏肝散加减" value="' + esc(d.rx.formula) + '"></label>' +
      '<div class="rx-grid" id="rx-body"></div><div class="rx-add" id="rx-add"></div>' +
      '<div class="rx-meta"><label>剂数<input type="number" min="1" max="60" data-bind="rx.doses" id="c-doses" value="' + d.rx.doses + '"></label><label class="use">用法<input type="text" data-bind="rx.usage" id="c-usage" value="' + esc(d.rx.usage) + '"></label><span class="rx-total" id="rx-total"></span></div>' +
      '<div class="warns" id="rx-warn"></div></section>' +

      '<section class="card"><h2><span class="step">' + steps[4] + '</span>医嘱</h2><textarea data-bind="advice" id="c-advice" rows="2" placeholder="饮食起居宜忌、复诊时间">' + esc(d.advice) + '</textarea><div class="chips" style="margin-top:8px">' + ADVICE.map(a => '<button type="button" class="chip" data-act="advice" data-v="' + a + '">+ ' + a + '</button>').join('') + '</div></section>' +

      '<div class="savebar"><button class="btn" data-act="consult-cancel">' + (d.id ? '放弃修改' : '放弃本次接诊') + '</button><button class="btn" data-act="consult-save">保存病历</button><button class="btn primary" data-act="consult-save" data-print="1">保存并打印处方</button></div>' +
      '</div>';
  }
  function updateSuggest() {
    const el = $('#suggest'); if (!el || !draft) return;
    const rs = diagnose(draft);
    if (!rs.length) {
      const n = draft.symptoms.length + draft.tongueBody.length + draft.tongueCoat.length + draft.pulse.length;
      el.innerHTML = '<p class="empty">' + (n ? '已选条目还不足以匹配证型，继续补充主症和舌脉。' : '在左侧点选症状、舌象、脉象后，这里会列出相符的证型、治法和代表方。') + '</p>';
      return;
    }
    el.innerHTML = rs.map(r => {
      const pct = Math.round(r.ratio * 100);
      const hits = r.mainHit.concat(r.minorHit, r.tHit.map(x => '舌' + x), r.cHit.map(x => '苔' + x), r.pHit.map(x => '脉' + x));
      return '<article class="sg"><header><h3>' + r.sy.name + '</h3><span class="lv' + (pct >= 70 ? ' hi' : '') + '">' + (pct >= 70 ? '高度相符' : pct >= 45 ? '较相符' : '部分相符') + ' ' + pct + '%</span></header>' +
        '<div class="bar"><i style="width:' + pct + '%"></i></div>' +
        '<p><b>相符</b>' + hits.join(' · ') + '</p>' +
        (r.missing.length ? '<p class="miss"><b>可追问</b>' + r.missing.join(' · ') + '</p>' : '') +
        '<p><b>治法</b>' + r.sy.method + '</p>' +
        '<div class="sg-act"><button type="button" class="btn sm primary" data-act="adopt" data-sy="' + r.sy.name + '">采用此证</button>' + r.sy.formulas.map(f => '<button type="button" class="btn sm" data-act="adopt" data-sy="' + r.sy.name + '" data-fx="' + f + '">' + f + '</button>').join('') + '</div></article>';
    }).join('');
  }
  function renderRx() {
    const el = $('#rx-body'); if (!el || !draft) return;
    const hs = draft.rx.herbs;
    el.innerHTML = hs.length ? hs.map((h, i) => '<div class="rx-row" data-i="' + i + '"><span class="n">' + (i + 1) + '</span>' +
      '<input type="text" data-hf="name" id="h-name-' + i + '" list="herb-list" aria-label="药名" value="' + esc(h.name) + '">' +
      '<input type="number" data-hf="dose" id="h-dose-' + i + '" min="0" step="0.5" aria-label="剂量" value="' + h.dose + '">' +
      '<select data-hf="unit" id="h-unit-' + i + '" aria-label="单位">' + UNITS.map(u => '<option' + (u === h.unit ? ' selected' : '') + '>' + u + '</option>').join('') + '</select>' +
      '<select data-hf="note" id="h-note-' + i + '" aria-label="煎法">' + NOTES.map(n => '<option value="' + n + '"' + (n === h.note ? ' selected' : '') + '>' + (n || '—') + '</option>').join('') + '</select>' +
      '<button type="button" class="x" data-act="rx-del" data-i="' + i + '" aria-label="删除 ' + esc(h.name) + '">×</button></div>').join('')
      : '<p class="empty" style="grid-column:1/-1">尚未开方。在上面的输入框里直接打方名或药物，回车即可' + (useFour() ? '；也可以从右侧辨证参考点方名载入' : '') + '。</p>';
    renderRxMeta();
  }
  function renderRxMeta() {
    const rx = draft.rx, hs = rx.herbs.filter(h => h.name.trim());
    const g = hs.reduce((s, h) => s + (h.unit === 'g' ? Number(h.dose) || 0 : 0), 0);
    $('#rx-total').textContent = hs.length ? '共 ' + hs.length + ' 味，每剂 ' + Math.round(g * 10) / 10 + ' g' + (rx.doses > 1 ? '，' + rx.doses + ' 剂合计 ' + Math.round(g * rx.doses * 10) / 10 + ' g' : '') : '';
    const p = P(draft.patientId);
    $('#rx-warn').innerHTML = checkRx(rx, { pregnant: draft.pregnant }).map(w => '<div class="w ' + w.lv + '">' + esc(w.text) + '</div>').join('') +
      (hs.length && p && p.allergy ? '<div class="w">患者过敏史：' + esc(p.allergy) + '，请核对处方</div>' : '');
    const names = hs.map(h => h.name.trim());
    const adds = hs.length && useFour() ? draft.symptoms.map(s => ({ s: s, hs: (T.ADDITIONS[s] || []).filter(h => names.indexOf(h.name) < 0) })).filter(x => x.hs.length).slice(0, 8) : [];
    $('#rx-add').innerHTML = adds.length ? '<span class="fine">随症加味参考（常用经验加味，须结合证型取舍；点击加入处方）</span>' + adds.map(x => '<div class="rx-add-row"><span class="sx-l">' + x.s + '</span><div class="chips">' + x.hs.map(h => '<button type="button" class="chip" data-act="add-herb" data-n="' + h.name + '" data-d="' + h.dose + '" data-note="' + h.note + '">+ ' + h.name + ' ' + h.dose + 'g</button>').join('') + '</div></div>').join('') : '';
  }
  function loadFormula(name, mode, quiet) {
    const my = name.indexOf('my:') === 0 ? db.myFormulas.find(f => f.id === name.slice(3)) : null;
    const rx = draft.rx, hs = my ? clone(my.herbs) : T.formulaHerbs(name);
    if (my) name = my.name;
    if (!hs.length) return;
    if (mode === 'merge' && rx.herbs.length) {
      hs.forEach(h => { if (!rx.herbs.some(x => x.name === h.name)) rx.herbs.push(h); });
      rx.formula = rx.formula ? rx.formula.replace(/加减$/, '') + '合' + name : name;
    } else { rx.herbs = hs; rx.formula = name; }
    $('#c-formula').value = rx.formula;
    if (quiet) return;
    renderRx(); queueSave(); toast((mode === 'merge' ? '已合入 ' : '已载入 ') + name);
  }
  function askFormula(name) {
    if (!draft.rx.herbs.length) { loadFormula(name, 'replace'); return; }
    openModal('<h2>载入 ' + esc(name) + '</h2><p>当前处方已有 ' + draft.rx.herbs.length + ' 味药。</p><div class="acts"><button class="btn" data-act="modal-close">取消</button><button class="btn" data-act="fx-load" data-fx="' + esc(name) + '" data-mode="merge">合方（追加不重复的药）</button><button class="btn primary" data-act="fx-load" data-fx="' + esc(name) + '" data-mode="replace">替换当前处方</button></div>');
  }
  /* 处方的「直接打字」输入：方名、合方、加药、改剂量、去药，一句话里都能写 */
  let rxUndo = null;
  const snapRx = () => { rxUndo = clone(draft.rx); };
  // 可识别的方名：我的常用方优先，其次方剂库和别称；名字长的排前面，避免「桂枝汤」抢在「桂枝加龙骨牡蛎汤」前面
  function fxNames() {
    return db.myFormulas.map(f => ({ name: f.name, key: 'my:' + f.id }))
      .concat(T.FORMULAS.map(f => ({ name: f.name, key: f.name })), Object.keys(T.ALIAS || {}).map(a => ({ name: a, key: T.ALIAS[a] })))
      .sort((a, b) => b.name.length - a.name.length);
  }
  const HERB_RE = /^([^\d\s()（）+＋]+)\s*(\d+(?:\.\d+)?)?\s*(g|克|枚|片)?\s*(?:[（(]\s*(先煎|后下|包煎|烊化|冲服|另煎|打碎)\s*[)）]|(先煎|后下|包煎|烊化|冲服|另煎|打碎))?/i;
  // 从字符串开头读出一味药：返回 { len, herb }，读不出返回 null
  function readHerb(s) {
    const m = HERB_RE.exec(s); if (!m) return null;
    let name = m[1], note = m[4] || m[5] || '';
    if (!note && !m[2]) { const k = NOTES.find(x => x && name.length > x.length && name.endsWith(x)); if (k) { name = name.slice(0, -k.length); note = k; } }
    return { len: m[0].length, hasUnit: !!m[3], herb: { name: name, dose: m[2] ? +m[2] : '', unit: m[3] && m[3] !== '克' ? m[3].toLowerCase() : 'g', note: note } };
  }
  const herbsToText = hs => hs.map(h => h.name + (h.dose === '' ? '' : h.dose) + (h.unit !== 'g' ? h.unit : '') + (h.note ? '(' + h.note + ')' : '')).join(' ');
  function textToHerbs(text) {
    const s = text.replace(/[，、；;,：:\n]/g, ' '), out = [];
    let pos = 0;
    while (pos < s.length) {
      if (/[\s()（）+＋]/.test(s[pos])) { pos++; continue; }
      const r = readHerb(s.slice(pos));
      if (!r) { pos++; continue; }
      pos += r.len;
      if (!r.herb.note) r.herb.note = T.autoNote(r.herb.name);
      out.push(r.herb);
    }
    return out;
  }
  function runRx(text) {
    const s = text.replace(/[，、；;,：:]/g, ' ');
    if (!s.trim()) return;
    snapRx();
    const rx = draft.rx, names = fxNames(), miss = [], unknown = [];
    const formulaAt = i => names.find(f => s.startsWith(f.name, i));
    let pos = 0, mode = 'add', loaded = 0, edited = false;
    while (pos < s.length) {
      const ch = s[pos];
      if (/\s/.test(ch)) { pos++; continue; }
      let f = formulaAt(pos), merge = false;
      if (!f && ch === '合') { let j = pos + 1; while (s[j] === ' ') j++; f = formulaAt(j); if (f) { merge = true; pos = j; } }
      if (f) {
        // 一句话里的第一首方替换当前处方（除非写了「合」），后面的方一律合入
        loadFormula(f.key, merge || loaded ? 'merge' : 'replace', true);
        pos += f.name.length; loaded++; mode = 'add'; continue;
      }
      if (s.startsWith('加减', pos)) { pos += 2; mode = 'add'; continue; }
      if (ch === '加' || ch === '+' || ch === '＋') { mode = 'add'; pos++; continue; }
      if (ch === '去' || ch === '减' || ch === '-' || ch === '－') { mode = 'del'; pos++; continue; }
      const r = readHerb(s.slice(pos));
      if (!r) { pos++; continue; }
      pos += r.len;
      const h = r.herb;
      if (mode === 'del') {
        const n0 = rx.herbs.length;
        rx.herbs = rx.herbs.filter(x => x.name !== h.name);
        if (rx.herbs.length === n0) rx.herbs = rx.herbs.filter(x => x.name.indexOf(h.name) < 0);
        if (rx.herbs.length === n0) miss.push(h.name); else edited = true;
        continue;
      }
      // 没带剂量、又像方名的词：方剂库里没有这首方
      if (h.dose === '' && h.name.length >= 3 && /(汤|散|丸|饮|饮子|煎|丹|方|膏)$/.test(h.name) && !/石膏$/.test(h.name)) { unknown.push(h.name); if (!rx.herbs.length) rx.formula = h.name; continue; }
      const ex = rx.herbs.find(x => x.name === h.name);
      if (ex) { if (h.dose !== '') ex.dose = h.dose; if (r.hasUnit) ex.unit = h.unit; if (h.note) ex.note = h.note; }
      else { if (!h.note) h.note = T.autoNote(h.name); rx.herbs.push(h); }
      edited = true;
    }
    // 只有在成方基础上动了药才补「加减」；自己起的方名不动
    if (edited && rx.formula && !/加减$/.test(rx.formula) && names.some(f => rx.formula.indexOf(f.name) >= 0)) rx.formula += '加减';
    $('#c-formula').value = rx.formula;
    renderRx(); queueSave();
    if (unknown.length) toast('方剂库里没有「' + unknown.join('、') + '」' + (rx.herbs.length ? '' : '，已填为方名，请直接输入药物'), true);
    else if (miss.length) toast('处方里没有：' + miss.join('、'), true);
  }
  function saveVisit(print) {
    const d = draft;
    if (!d.chief.trim()) { toast('请先填写主诉', true); $('#c-chief').focus(); return; }
    d.rx.herbs = d.rx.herbs.filter(h => h.name.trim());
    d.rx.doses = Math.max(1, Number(d.rx.doses) || 1);
    const commit = () => {
      const v = touch(clone(d));
      if (v.id) { const i = db.visits.findIndex(x => x.id === v.id); db.visits[i] = v; } else { v.id = uid(); db.visits.push(v); }
      db.draft = null; draft = null; save(); closeModal(); toast('病历已保存');
      go('visit/' + v.id);
      if (print) setTimeout(() => printVisit(v.id, 'rx'), 350);
    };
    const danger = checkRx(d.rx, { pregnant: d.pregnant }).filter(w => w.lv === 'danger');
    if (danger.length) confirmBox('处方存在配伍禁忌', '<div class="warns">' + danger.map(w => '<div class="w danger">' + esc(w.text) + '</div>').join('') + '</div><p style="margin-top:10px">确认仍按此处方保存吗？</p>', '仍然保存', commit, true);
    else commit();
  }

  /* ---------- 病历查看与打印 ---------- */
  function vVisit(v) {
    const p = P(v.patientId) || { id: '', name: '（已删除）', gender: '', allergy: '' };
    const sec = (t, c) => c ? '<h3>' + t + '</h3><p>' + esc(c) + '</p>' : '';
    const four = fourText(v);
    return '<header class="head"><div><h1>门诊病历' + (v.demo ? ' <span class="tag gray">示例</span>' : '') + '</h1><p class="sub"><a class="link" href="#patient/' + p.id + '">' + esc(p.name) + '</a> / ' + dTime(v.date) + ' ' + v.type + '</p></div>' +
      '<div class="acts"><button class="btn danger" data-act="visit-del" data-id="' + v.id + '">删除</button><button class="btn" data-act="go" data-to="consult/' + p.id + '/edit/' + v.id + '">修改</button><button class="btn" data-act="go" data-to="consult/' + p.id + '/copy">复诊（沿用）</button><button class="btn" data-act="print" data-id="' + v.id + '" data-mode="record">打印病历</button><button class="btn" data-act="print" data-id="' + v.id + '" data-mode="rx">打印处方笺</button>' + (v.rx.herbs.length ? '<button class="btn primary" data-act="sheet-img" data-id="' + v.id + '" data-mode="rx">处方图片</button>' : '') + '</div></header>' +
      '<section class="card"><h2>患者</h2>' + (p.id ? patientInfo(p) : '<p class="muted">患者档案已删除</p>') + '</section>' +
      '<section class="card rec"><h2>病历' + (v.pregnant ? ' <span class="tag zhu">妊娠期</span>' : '') + '</h2>' + sec('主诉', v.chief) + sec('现病史', v.hpi) + sec('四诊', four) + photoSec(v) + sec('四诊补充', v.exam) + sec('上次治疗的疗效', v.effect) +
      '<h3>诊断</h3><p>' + esc([v.disease && '中医：' + v.disease, v.syndrome && '证型：' + v.syndrome, v.western && '西医：' + v.western].filter(Boolean).join('　') || '—') + '</p>' + sec('治法', v.method) +
      '<h3>处方' + (v.rx.formula ? '　' + esc(v.rx.formula) : '') + '</h3>' + (v.rx.herbs.length ? '<div class="herbs">' + v.rx.herbs.map(h => '<span>' + herbLabel(h) + '</span>').join('') + '</div><p>共 ' + v.rx.herbs.length + ' 味 × ' + v.rx.doses + ' 剂　' + esc(v.rx.usage) + '</p>' : '<p class="muted">未开方</p>') +
      sec('医嘱', v.advice) + '</section>';
  }
  function printVisit(id, mode) {
    const v = V(id); if (!v) return;
    const p = P(v.patientId) || { name: '', gender: '' };
    const s = db.settings;
    const sec = (t, c) => c ? '<div class="rp-sec"><b>' + t + '</b>' + esc(c) + '</div>' : '';
    const dx = [v.disease, v.syndrome].filter(Boolean).join(' · ') + (v.western ? '（' + v.western + '）' : '');
    const four = [fourText(v), v.exam].filter(Boolean).join('；');
    const head = '<div class="rp-head"><h1>' + esc(s.clinic || '中医门诊') + '</h1><p>' + (mode === 'rx' ? '处方笺' : '门诊病历') + '</p></div>' +
      '<div class="rp-info"><span>姓名：' + esc(p.name) + '</span><span>性别：' + esc(p.gender) + '</span><span>年龄：' + (p.id ? ageText(p) : '') + '</span><span>日期：' + dOnly(v.date) + '</span><span>' + v.type + '</span>' + (p.allergy ? '<span>过敏史：' + esc(p.allergy) + '</span>' : '') + (v.pregnant ? '<span>妊娠期</span>' : '') + '</div>';
    const rp = '<div class="rp-R">Rp.</div><div class="rp-herbs">' + v.rx.herbs.map(h => '<span>' + herbLabel(h) + '</span>').join('') + '</div>' +
      '<div class="rp-sec"><b>用法</b>共 ' + v.rx.herbs.length + ' 味，' + v.rx.doses + ' 剂。' + esc(v.rx.usage) + '</div>';
    const html = head + (mode === 'rx'
      ? sec('诊断', dx) + sec('治法', v.method) + rp + sec('医嘱', v.advice)
      : sec('主诉', v.chief) + sec('现病史', v.hpi) + (p.history ? sec('既往史', p.history) : '') + sec('四诊', four) + sec('诊断', dx) + sec('治法', v.method) + (v.rx.herbs.length ? '<div class="rp-sec"><b>处方</b>' + esc(v.rx.formula) + '</div>' + rp : '') + sec('医嘱', v.advice)) +
      '<div class="rp-foot"><span>医师：' + esc(s.doctor || '') + (s.doctor ? '' : '＿＿＿＿＿＿') + '</span>' + (mode === 'rx' ? '<span>审核：＿＿＿＿</span><span>调配：＿＿＿＿</span><span>核对发药：＿＿＿＿</span>' : '') + '</div>';
    $('#print').innerHTML = html;
    openModal('<div class="sheet preview">' + html + '</div><div class="acts"><button class="btn" data-act="modal-close">关闭</button><button class="btn" data-act="print" data-id="' + v.id + '" data-mode="' + (mode === 'rx' ? 'record' : 'rx') + '">改看' + (mode === 'rx' ? '门诊病历' : '处方笺') + '</button><button class="btn" data-act="sheet-img" data-id="' + v.id + '" data-mode="' + mode + '">保存为图片</button><button class="btn primary" data-act="do-print">打印</button></div>', true);
  }

  /* ---------- 处方笺图片（发微信用）：直接画在画布上，不依赖外部库 ---------- */
  let sheetFile = null;
  function drawSheet(v, mode) {
    const p = P(v.patientId) || { name: '', gender: '' }, s = db.settings;
    const W = 1080, M = 64, CW = W - M * 2, LW = 130;
    const SANS = '"Microsoft YaHei","PingFang SC","Noto Sans CJK SC","Noto Sans SC",sans-serif', KAI = '"KaiTi","STKaiti","Kaiti SC",' + SANS;
    const dx = [v.disease, v.syndrome].filter(Boolean).join(' · ') + (v.western ? '（' + v.western + '）' : '');
    const info = ['姓名：' + p.name, '性别：' + p.gender, '年龄：' + (p.id ? ageText(p) : ''), '日期：' + dOnly(v.date), v.type].concat(p.allergy ? ['过敏史：' + p.allergy] : [], v.pregnant ? ['妊娠期'] : []);
    const before = mode === 'rx' ? [['诊断', dx], ['治法', v.method]]
      : [['主诉', v.chief], ['现病史', v.hpi], ['既往史', p.history], ['四诊', [fourText(v), v.exam].filter(Boolean).join('；')], ['诊断', dx], ['治法', v.method]];
    const n = v.rx.herbs.length;
    const after = [['用法', n ? '共 ' + n + ' 味，' + v.rx.doses + ' 剂。' + v.rx.usage : ''], ['医嘱', v.advice]];
    const render = ctx => {
      let y = M;
      const wrap = (text, maxW) => {
        const lines = [];
        String(text).split('\n').forEach(par => { let line = ''; for (const ch of par) { if (line && ctx.measureText(line + ch).width > maxW) { lines.push(line); line = ch; } else line += ch; } lines.push(line); });
        return lines;
      };
      const rule = (h, color) => { ctx.fillStyle = color; ctx.fillRect(M, y, CW, h); ctx.fillStyle = '#000'; y += h; };
      const kv = pair => {
        if (!pair[1]) return;
        y += 18;
        ctx.font = 'bold 30px ' + SANS; ctx.fillText(pair[0], M, y);
        ctx.font = '30px ' + SANS;
        wrap(pair[1], CW - LW).forEach(l => { ctx.fillText(l, M + LW, y); y += 46; });
        y += 12; rule(1, '#aaa');
      };
      ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, W, ctx.canvas.height); ctx.fillStyle = '#000'; ctx.textBaseline = 'top';
      ctx.textAlign = 'center';
      ctx.font = '56px ' + KAI; ctx.fillText(s.clinic || '中医门诊', W / 2, y); y += 78;
      ctx.font = '32px ' + SANS; ctx.fillText(mode === 'rx' ? '处  方  笺' : '门 诊 病 历', W / 2, y); y += 58;
      ctx.textAlign = 'left'; rule(4, '#000'); y += 20;
      ctx.font = '30px ' + SANS;
      let x = M;
      info.forEach(t => { const w = ctx.measureText(t).width; if (x > M && x + w > W - M) { x = M; y += 46; } ctx.fillText(t, x, y); x += w + 44; });
      y += 46 + 14; rule(2, '#000');
      before.forEach(kv);
      if (n) {
        y += 22; ctx.font = 'italic bold 52px Georgia,"Times New Roman",serif'; ctx.fillText('Rp.', M, y); y += 78;
        const colW = (CW - 40) / 3;
        v.rx.herbs.forEach((h, i) => {
          const cx = M + 20 + (i % 3) * colW, cy = y + Math.floor(i / 3) * 62, t = h.name + ' ' + h.dose + h.unit;
          ctx.font = '34px ' + SANS; ctx.fillText(t, cx, cy);
          if (h.note) { const w = ctx.measureText(t).width; ctx.font = '22px ' + SANS; ctx.fillText(h.note, cx + w + 6, cy + 2); }
        });
        y += Math.ceil(n / 3) * 62 + 16; rule(1, '#aaa');
      }
      after.forEach(kv);
      y += 48; ctx.font = '30px ' + SANS; ctx.fillText('医师：' + (s.doctor || '＿＿＿＿＿＿'), M, y);
      return y + 46 + M;
    };
    const c0 = document.createElement('canvas'); c0.width = W; c0.height = 10;
    const c = document.createElement('canvas'); c.width = W; c.height = Math.ceil(render(c0.getContext('2d')));
    render(c.getContext('2d'));
    return c;
  }
  function sheetImage(id, mode) {
    const v = V(id); if (!v) return;
    const c = drawSheet(v, mode), p = P(v.patientId) || { name: '' }, label = mode === 'rx' ? '处方笺' : '门诊病历';
    c.toBlob(b => {
      if (!b) { toast('生成图片失败', true); return; }
      sheetFile = new File([b], (mode === 'rx' ? '处方_' : '病历_') + p.name + '_' + dOnly(v.date) + '.png', { type: 'image/png' });
      let canShare = false;
      try { canShare = !!(navigator.canShare && navigator.canShare({ files: [sheetFile] })); } catch (e) { /* 不支持分享文件 */ }
      openModal('<h2>' + label + '图片</h2><img class="sheet-img" id="sheet-img" alt="' + label + '" src="' + c.toDataURL('image/png') + '"><p class="fine" style="margin-top:8px">手机上长按图片，可以直接发给微信好友或保存到相册。</p><div class="acts"><button class="btn" data-act="modal-close">关闭</button><button class="btn' + (canShare ? '' : ' primary') + '" data-act="sheet-dl">保存到本机</button>' + (canShare ? '<button class="btn primary" data-act="sheet-share">分享（微信等）</button>' : '') + '</div>', true);
    }, 'image/png');
  }

  /* ---------- 知识库 ---------- */
  function libList(tab, q) {
    q = (q || '').trim();
    if (tab === 'mine') {
      const list = db.myFormulas.filter(f => !q || (f.name + f.herbs.map(h => h.name).join('')).indexOf(q) >= 0);
      return list.length ? list.map(f => '<article class="card"><h3>' + esc(f.name) + '<span class="tag zhu">自拟</span><small>' + dOnly(f.createdAt) + ' 保存</small></h3><p><b>组成</b>' + f.herbs.map(h => esc(h.name) + ' ' + h.dose + esc(h.unit) + (h.note ? '（' + esc(h.note) + '）' : '')).join('、') + '</p><p><b>合计</b>' + f.herbs.length + ' 味</p><div class="acts" style="margin-top:10px"><button class="btn sm danger" data-act="my-del" data-id="' + f.id + '">删除</button></div></article>').join('')
        : '<p class="empty" style="grid-column:1/-1">' + (q ? '没有匹配的常用方' : '还没有常用方。接诊开方后点「存为常用方」，就会保存到这里。') + '</p>';
    }
    if (tab === 'syndromes') {
      const list = T.SYNDROMES.filter(s => !q || (s.name + s.cat + s.main.join('') + s.minor.join('') + s.formulas.join('') + s.method).indexOf(q) >= 0);
      return list.length ? list.map(s => '<article class="card"><h3>' + s.name + '<span class="tag">' + s.cat + '</span></h3><p><b>主症</b>' + s.main.join('、') + '</p><p><b>兼症</b>' + s.minor.join('、') + '</p><p><b>舌脉</b>舌' + s.tongue.join('/') + (s.coat.length ? '，苔' + s.coat.join('/') : '') + '，脉' + s.pulse.join(s.pulseNeed ? '/' : '') + '</p><p><b>治法</b>' + s.method + '</p><p><b>代表方</b>' + s.formulas.join('、') + '</p></article>').join('') : '<p class="empty">没有匹配的证型</p>';
    }
    const list = T.FORMULAS.filter(f => !q || (f.name + f.cat + f.action + f.indication + f.herbs.map(h => h.name).join('')).indexOf(q) >= 0);
    return list.length ? list.map(f => '<article class="card"><h3>' + f.name + '<span class="tag">' + f.cat + '</span><small>' + f.source + '</small></h3><p><b>组成</b>' + f.herbs.map(h => h.name + ' ' + h.dose + h.unit + (h.note ? '（' + h.note + '）' : '')).join('、') + '</p><p><b>功用</b>' + f.action + '</p><p><b>主治</b>' + f.indication + '</p>' + (f.note ? '<p class="muted"><b>备注</b>' + f.note + '</p>' : '') + '</article>').join('') : '<p class="empty">没有匹配的方剂</p>';
  }
  function vLibrary(tab) {
    tab = tab === 'syndromes' || tab === 'mine' ? tab : 'formulas';
    return '<header class="head"><div><h1>方剂与证型</h1><p class="sub">方剂 ' + T.FORMULAS.length + ' 首 · 证型 ' + T.SYNDROMES.length + ' 个。剂量为教材或临床常用参考量，临证请自行斟酌。</p></div>' +
      '<div class="acts"><input id="lq" type="search" data-tab="' + tab + '" placeholder="' + (tab === 'syndromes' ? '搜索证型 / 症状 / 方名' : '搜索方名 / 药名 / 主治') + '" style="width:240px"></div></header>' +
      '<div class="tabs"><a href="#library" class="' + (tab === 'formulas' ? 'on' : '') + '">方剂库</a><a href="#library/syndromes" class="' + (tab === 'syndromes' ? 'on' : '') + '">证型库</a><a href="#library/mine" class="' + (tab === 'mine' ? 'on' : '') + '">我的常用方（' + db.myFormulas.length + '）</a></div>' +
      '<div class="lib" id="lib">' + libList(tab, '') + '</div>';
  }

  /* ---------- 设置与备份 ---------- */
  function vSettings() {
    const s = db.settings;
    return '<header class="head"><div><h1>设置与备份</h1><p class="sub">数据保存在这台电脑的这个浏览器里，换浏览器或清除浏览数据会丢失，请定期导出备份。</p></div></header>' +
      '<section class="card"><h2>打印抬头</h2><div class="g2"><label class="f"><span>诊所 / 机构名称</span><input type="text" data-set="clinic" id="s-clinic" placeholder="显示在处方笺和病历顶部" value="' + esc(s.clinic || '') + '"></label><label class="f"><span>医师姓名</span><input type="text" data-set="doctor" id="s-doctor" value="' + esc(s.doctor || '') + '"></label></div></section>' +
      '<section class="card"><h2>接诊页</h2><label style="display:flex;gap:8px;align-items:flex-start;cursor:pointer"><input type="checkbox" data-set="showFour" id="s-four" style="margin-top:5px"' + (s.showFour === true ? ' checked' : '') + '><span>显示四诊点选区<br><span class="fine">打开后，接诊页会多出症状、舌、脉的点选区，以及依赖它的辨证参考栏和随症加味提示。关闭时四诊直接写在现病史里。</span></span></label></section>' +
      '<section class="card"><h2>密码与加密</h2>' + (cryptoKey
        ? '<p><span class="tag" style="background:var(--ok-l);color:var(--ok)">已加密</span>　病历、舌象照片和备份文件都用你的密码加密保存。忘记密码无法找回数据。</p><div class="acts" style="margin-top:12px"><label style="display:flex;align-items:center;gap:6px">无操作自动锁定<select data-set="autoLock" id="s-lock" style="width:auto">' + [[5, '5 分钟'], [10, '10 分钟'], [30, '30 分钟'], [0, '不自动锁定']].map(o => '<option value="' + o[0] + '"' + (Number(s.autoLock == null ? 10 : s.autoLock) === o[0] ? ' selected' : '') + '>' + o[1] + '</option>').join('') + '</select></label><button class="btn" data-act="lock-now">立即锁定</button><button class="btn" data-act="pw-form" data-mode="change">修改密码</button><button class="btn danger" data-act="pw-form" data-mode="remove">取消密码</button></div>'
        : canCrypto ? '<p class="sub">目前没有密码，能打开这个页面的人都能看到病历。设置密码后，数据会加密保存，每次打开需要输入密码。</p><div class="acts" style="margin-top:12px"><button class="btn primary" data-act="pw-form" data-mode="set">设置密码</button></div>'
          : '<p class="sub">当前打开方式不支持加密，请用 Chrome 或 Edge 打开。</p>') + '</section>' +
      syncCard() +
      '<section class="card"><h2>数据备份</h2><p class="sub" style="margin-bottom:12px">当前：患者 ' + db.patients.length + ' 人，病历 ' + db.visits.length + ' 份。备份文件包含常用方和舌象照片' + (cryptoKey ? '，并用当前密码加密' : '') + '。</p><div class="acts"><button class="btn primary" data-act="export">导出备份文件</button><label class="btn">从备份恢复<input type="file" id="import-file" accept=".json,application/json" hidden></label></div></section>' +
      '<section class="card"><h2>清理</h2><div class="acts">' + (db.patients.some(p => p.demo) ? '<button class="btn" data-act="demo-clear">清除示例数据</button>' : '') + '<button class="btn danger" data-act="wipe">清空全部数据</button></div></section>';
  }
  function exportData() {
    const ids = db.visits.flatMap(v => (v.photos || []).map(p => p.id));
    Promise.all(ids.map(id => phGet(id).then(u => [id, u]).catch(() => [id, null]))).then(pairs => {
      const photos = {};
      pairs.forEach(x => { if (x[1]) photos[x[0]] = x[1]; });
      const lost = ids.length - Object.keys(photos).length, at = new Date().toISOString();
      const plain = JSON.stringify({ app: 'tcm-clinic', version: 2, exportedAt: at, settings: db.settings, myFormulas: db.myFormulas, patients: db.patients, visits: db.visits, photos: photos });
      const salt = saltB64;
      return (cryptoKey ? encStr(cryptoKey, plain).then(o => JSON.stringify({ app: 'tcm-clinic', version: 3, exportedAt: at, enc: 1, salt: salt, iv: o.iv, ct: o.ct })) : Promise.resolve(plain)).then(text => {
        download('中医诊疗备份_' + dOnly(new Date()) + (cryptoKey ? '_加密' : '') + '.json', text, 'application/json');
        toast(lost ? '已导出，但有 ' + lost + ' 张照片读取失败、未包含在内' : '备份文件已导出' + (ids.length ? '（含 ' + ids.length + ' 张照片）' : '') + (cryptoKey ? '，已加密' : ''), !!lost);
      });
    }).catch(() => toast('导出失败', true));
  }
  function importData(file) {
    const r = new FileReader();
    r.onload = () => {
      let d;
      try { d = JSON.parse(r.result); } catch (e) { d = null; }
      if (d && d.enc && d.ct) openEncBackup(d); else applyBackup(d, false);
    };
    r.readAsText(file);
  }
  let pendingBackup = null;
  function openEncBackup(d) {
    if (!canCrypto) { toast('当前打开方式不支持解密，请用 Chrome 或 Edge 打开', true); return; }
    const ask = () => {
      pendingBackup = d;
      openModal('<h2>加密的备份文件</h2><form id="impf" autocomplete="off"><label class="f req"><span>导出这份备份时使用的密码</span><input type="password" name="pw" id="imp-pw" autocomplete="off" required></label><p class="lock-err" id="imp-err" role="alert"></p><div class="acts"><button type="button" class="btn" data-act="modal-close">取消</button><button class="btn primary">解密</button></div></form>');
    };
    // 与当前密码是同一把密钥时直接解开，否则询问密码
    if (cryptoKey && d.salt === saltB64) decStr(cryptoKey, d).then(t => applyBackup(JSON.parse(t), true), ask); else ask();
  }
  function decryptBackup(form) {
    const d = pendingBackup, err = $('#imp-err');
    err.textContent = '正在解密…';
    deriveKey(String(new FormData(form).get('pw')), unb64(d.salt)).then(k => decStr(k, d)).then(t => { pendingBackup = null; closeModal(); applyBackup(JSON.parse(t), true); }, () => { err.textContent = '密码不正确'; });
  }
  function applyBackup(d, wasEnc) {
    {
      if (!d || !Array.isArray(d.patients) || !Array.isArray(d.visits)) { toast('这不是有效的备份文件', true); return; }
      confirmBox('从备份恢复', '<p>备份中有患者 ' + d.patients.length + ' 人、病历 ' + d.visits.length + ' 份' + (d.exportedAt ? '（导出于 ' + dTime(d.exportedAt) + '）' : '') + '。</p><p>恢复会<b>覆盖</b>当前的全部数据。' + (cryptoKey ? '恢复后的数据用当前密码加密保存。' : wasEnc ? '当前没有设置密码，恢复后的数据<b>不加密</b>。' : '') + '</p>', '覆盖并恢复', () => {
        const ph = d.photos || {}, keys = Object.keys(ph);
        Promise.all(keys.map(k => phPut(k, ph[k]))).then(() => false, () => true).then(photoFail => {
          phCache.clear();
          db = { settings: d.settings || {}, myFormulas: d.myFormulas || [], patients: d.patients, visits: d.visits, draft: null }; draft = null; save(); closeModal();
          toast(photoFail ? '病历已恢复，但舌象照片未能写入' : '已从备份恢复' + (keys.length ? '（含 ' + keys.length + ' 张照片）' : ''), photoFail);
          go('dashboard');
        });
      }, true);
    }
  }

  /* ---------- 锁屏与密码 ---------- */
  const lockEl = $('#lock');
  function showLock() {
    document.body.classList.add('locked');
    lockEl.hidden = false;
    lockEl.innerHTML = '<form id="lockf" class="lock-box" autocomplete="off"><span class="seal">医</span><h1>中医诊疗系统</h1><p class="sub">数据已加密，请输入密码解锁</p>' +
      (canCrypto ? '<input type="password" id="lock-pw" name="pw" autocomplete="current-password" aria-label="密码" required><p class="lock-err" id="lock-err" role="alert"></p><button class="btn primary">解锁</button>'
        : '<p class="lock-err">当前打开方式不支持解密，请用 Chrome 或 Edge 打开。</p>') +
      '<button type="button" class="link" data-act="forgot">忘记密码？</button></form>';
    const i = $('#lock-pw'); if (i) i.focus();
  }
  function unlock(pw) {
    const err = $('#lock-err'), src = locked;
    err.textContent = '正在解锁…';
    let key;
    deriveKey(pw, unb64(src.salt)).then(k => { key = k; return decStr(k, src); }).then(t => {
      const d = JSON.parse(t);
      d.settings = d.settings || {}; d.myFormulas = d.myFormulas || []; d.tomb = d.tomb || {};
      db = d; cryptoKey = key; saltB64 = src.salt; locked = null;
      document.body.classList.remove('locked'); lockEl.hidden = true; lockEl.innerHTML = '';
      armIdle(); route(); queueSync(800);
    }, () => { err.textContent = '密码不正确'; const i = $('#lock-pw'); i.value = ''; i.focus(); });
  }
  function lockNow() {
    if (!cryptoKey) return;
    clearTimeout(saveTimer); save();
    saveChain.then(() => location.reload());   // 重新加载即清空内存里的明文和密钥
  }
  let idleTimer = 0, idleAt = 0;
  function armIdle() {
    clearTimeout(idleTimer);
    const m = Number(db.settings.autoLock == null ? 10 : db.settings.autoLock);
    if (cryptoKey && m > 0) idleTimer = setTimeout(lockNow, m * 60000);
  }
  ['click', 'keydown', 'input'].forEach(ev => document.addEventListener(ev, () => { const n = Date.now(); if (n - idleAt > 3000) { idleAt = n; armIdle(); } }, true));
  function pwForm(mode) {
    const cur = '<label class="f req"><span>当前密码</span><input type="password" name="cur" id="pw-cur" autocomplete="current-password" required></label>';
    const nw = '<label class="f req"><span>' + (mode === 'change' ? '新密码' : '密码') + '（至少 6 位）</span><input type="password" name="nw" id="pw-nw" autocomplete="new-password" minlength="6" required></label><label class="f req"><span>再输入一次</span><input type="password" name="nw2" id="pw-nw2" autocomplete="new-password" required></label>';
    const body = mode === 'set' ? nw + '<label style="display:flex;gap:8px;align-items:flex-start;cursor:pointer"><input type="checkbox" id="pw-ok" required style="margin-top:5px"><span>我明白：密码不会保存在任何地方，<b>忘记密码后数据无法找回</b>，也没有重置的办法。</span></label>'
      : mode === 'change' ? cur + nw + '<p class="fine">以前导出的加密备份文件仍用旧密码，修改后建议重新导出一份。</p>'
        : cur + '<p>取消后，病历和照片将<b>不加密</b>保存，打开页面不再需要密码。</p>';
    openModal('<h2>' + { set: '设置密码', change: '修改密码', remove: '取消密码' }[mode] + '</h2><form id="pwf" data-mode="' + mode + '" autocomplete="off"><div style="display:flex;flex-direction:column;gap:12px">' + body + '</div><p class="lock-err" id="pw-err" role="alert"></p><div class="acts"><button type="button" class="btn" data-act="modal-close">取消</button><button class="btn ' + (mode === 'remove' ? 'danger' : 'primary') + '">' + { set: '加密并保存', change: '修改密码', remove: '取消密码' }[mode] + '</button></div></form>');
  }
  async function doPw(form) {
    const f = new FormData(form), mode = form.dataset.mode, err = $('#pw-err');
    const cur = String(f.get('cur') || ''), nw = String(f.get('nw') || '');
    if (mode !== 'remove') {
      if (nw.length < 6) { err.textContent = '密码至少 6 位'; return; }
      if (nw !== String(f.get('nw2') || '')) { err.textContent = '两次输入的密码不一致'; return; }
    }
    err.textContent = '正在处理，请稍候…';
    try {
      if (mode !== 'set') {
        await saveChain;
        const ok = await deriveKey(cur, unb64(saltB64)).then(k => decStr(k, JSON.parse(localStorage.getItem(KEY)))).then(() => true, () => false);
        if (!ok) { err.textContent = '当前密码不正确'; return; }
      }
      if (db.sync && mode === 'remove') { err.textContent = '已开启同步，请先断开同步再取消密码'; return; }
      if (db.sync && mode === 'change') {
        // 先用旧密码把两边同步齐，再换密钥并整体重新上传
        err.textContent = '正在同步…';
        if (!(await syncNow(true))) { err.textContent = '修改密码前需要先成功同步一次，请检查网络后重试'; return; }
        db.sync.forcePush = true;
      }
      clearTimeout(saveTimer);
      if (mode === 'remove') await rekey(null, null);
      else { const salt = crypto.getRandomValues(new Uint8Array(16)); await rekey(await deriveKey(nw, salt), b64(salt)); }
      phCache.clear(); closeModal(); armIdle(); queueSync(300);
      toast({ set: '已设置密码，数据已加密', change: '密码已修改', remove: '已取消密码' }[mode]);
      route();
    } catch (e) { err.textContent = '操作失败，请重试'; }
  }

  /* ---------- 多设备同步：GitHub 私有仓库，只上传密文 ----------
   * 仓库里的文件：data.json（全部病历的密文）和 photos/<照片编号>.<密钥标记>.json（每张照片的密文）。
   * 合并规则：按记录编号取并集，同一条记录以修改时间较晚的为准；删除靠 tomb 标记传播。 */
  const SHARED = ['clinic', 'doctor', 'showFour', 'autoLock', 'u'];
  const stamp = r => r.u || Date.parse(r.createdAt || r.date || '') || 0;
  function payloadOf(d) {
    const s = {};
    SHARED.forEach(k => { if (d.settings[k] !== undefined) s[k] = d.settings[k]; });
    return { settings: s, myFormulas: d.myFormulas, patients: d.patients, visits: d.visits, tomb: d.tomb || {} };
  }
  function mergePayload(remote, local) {
    const tomb = Object.assign({}, remote.tomb || {});
    Object.keys(local.tomb).forEach(k => { if (!(tomb[k] >= local.tomb[k])) tomb[k] = local.tomb[k]; });
    // 云端在前：时间相同以云端为准，否则两台设备会互相覆盖个没完
    const list = (a, b) => { const m = new Map(); (a || []).concat(b).forEach(r => { const o = m.get(r.id); if (!o || stamp(r) > stamp(o)) m.set(r.id, r); }); return Array.from(m.values()).filter(r => !(tomb[r.id] >= stamp(r))); };
    const rs = remote.settings || {};
    return { settings: (local.settings.u || 0) > (rs.u || 0) ? local.settings : rs, myFormulas: list(remote.myFormulas, local.myFormulas), patients: list(remote.patients, local.patients), visits: list(remote.visits, local.visits), tomb: tomb };
  }
  function canon(p) {
    const by = a => a.slice().sort((x, y) => (x.id < y.id ? -1 : 1)), t = {};
    Object.keys(p.tomb).sort().forEach(k => { t[k] = p.tomb[k]; });
    return JSON.stringify({ s: SHARED.map(k => p.settings[k]), f: by(p.myFormulas), p: by(p.patients), v: by(p.visits), t: t });
  }
  function ghFetch(c, path, opt, raw) {
    opt = opt || {};
    const url = 'https://api.github.com/repos/' + encodeURIComponent(c.owner) + '/' + encodeURIComponent(c.repo) + (path == null ? '' : '/contents/' + path);
    return fetch(url, { method: opt.method || 'GET', cache: 'no-store', body: opt.body ? JSON.stringify(opt.body) : undefined,
      headers: { Authorization: 'Bearer ' + c.token, Accept: raw ? 'application/vnd.github.raw+json' : 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' } })
      .then(res => { if (res.status === 401 || res.status === 403) throw { code: 'auth' }; return res; }, () => { throw { code: 'net' }; });
  }
  async function ghGet(c, path) {
    const res = await ghFetch(c, path);
    if (res.status === 404) return null;
    if (!res.ok) throw { code: 'http', status: res.status };
    const j = await res.json();
    if (Array.isArray(j)) return j;
    return { sha: j.sha, text: j.content ? atob(j.content.replace(/\s/g, '')) : await (await ghFetch(c, path, null, true)).text() };
  }
  async function ghPut(c, path, text, sha) {
    const body = { message: 'sync', content: btoa(text) };
    if (sha) body.sha = sha;
    const res = await ghFetch(c, path, { method: 'PUT', body: body });
    if (res.status === 409 || res.status === 422) throw { code: 'conflict' };
    if (!res.ok) throw { code: 'http', status: res.status };
  }
  async function ghDel(c, path, sha) {
    const res = await ghFetch(c, path, { method: 'DELETE', body: { message: 'sync: remove', sha: sha } });
    if (!res.ok && res.status !== 404 && res.status !== 409) throw { code: 'http', status: res.status };
  }
  async function syncCore() {
    const c = db.sync, tag = saltB64.replace(/[^A-Za-z0-9]/g, '').slice(0, 10);
    const file = await ghGet(c, 'data.json');
    let remote = null;
    if (file) {
      const o = JSON.parse(file.text);
      if (o.salt === saltB64) remote = JSON.parse(await decStr(cryptoKey, o).catch(() => { throw { code: 'pw', remote: o }; }));
      else if (!c.forcePush) throw { code: 'pw', remote: o };
    }
    const local = payloadOf(db), merged = remote ? mergePayload(remote, local) : local, mj = canon(merged);
    let changed = false;
    if (mj !== canon(local)) {
      db.myFormulas = merged.myFormulas; db.patients = merged.patients; db.visits = merged.visits; db.tomb = merged.tomb;
      SHARED.forEach(k => { if (merged.settings[k] !== undefined) db.settings[k] = merged.settings[k]; });
      if (db.draft && !P(db.draft.patientId)) db.draft = null;
      changed = true;
    }
    if (!remote || mj !== canon(remote)) {
      const o = await encStr(cryptoKey, JSON.stringify(merged));
      await ghPut(c, 'data.json', JSON.stringify({ v: 1, salt: saltB64, iv: o.iv, ct: o.ct }), file && file.sha);
    }
    delete c.forcePush;
    // 照片：云端缺的上传，本机缺的下载，没有病历引用的从云端删除
    const listing = (await ghGet(c, 'photos')) || [];
    const remoteMap = new Map((Array.isArray(listing) ? listing : []).map(f => [f.name, f.sha]));
    const need = new Set(merged.visits.flatMap(v => (v.photos || []).map(p => p.id)));
    const have = new Set(await idb.keys().catch(() => []));
    let got = 0;
    for (const id of need) {
      const name = id + '.' + tag + '.json';
      if (remoteMap.has(name)) {
        if (!have.has(id)) { const f = await ghGet(c, 'photos/' + name); if (f) { const o = JSON.parse(f.text); await idb.put(id, { enc: 1, iv: o.iv, ct: o.ct }); got++; } }
      } else if (have.has(id)) {
        const v = await idb.get(id);
        if (v && v.enc) await ghPut(c, 'photos/' + name, JSON.stringify({ iv: v.iv, ct: v.ct }));
      }
    }
    for (const e of remoteMap) {
      const id = e[0].split('.')[0];
      if (!need.has(id) || e[0] !== id + '.' + tag + '.json') await ghDel(c, 'photos/' + e[0], e[1]);
    }
    c.lastSync = Date.now();
    save();
    if (changed && !draft && modal.hidden) route(); else if (got) hydratePhotos(main);
  }
  let syncing = null, syncTimer = 0, pwAsked = false, pendingRemote = null;
  const syncMsg = { msg: '', err: false };
  function setSync(msg, err) {
    syncMsg.msg = msg; syncMsg.err = !!err;
    const el = $('#side-sync'); el.textContent = msg; el.hidden = !msg; el.classList.toggle('err', !!err);
    const s = $('#sync-status'); if (s) { s.textContent = msg; s.classList.toggle('allergy', !!err); }
  }
  function syncNow(manual) {
    if (!db.sync || !cryptoKey || locked) return Promise.resolve(false);
    if (syncing) return syncing;
    if (navigator.onLine === false) { setSync('离线，联网后自动同步', true); return Promise.resolve(false); }
    setSync('正在同步…');
    const run = n => syncCore().catch(e => { if (e && e.code === 'conflict' && n > 0) return run(n - 1); throw e; });
    syncing = run(2).then(() => { const t = new Date(); setSync('已同步 ' + pad(t.getHours()) + ':' + pad(t.getMinutes())); return true; }, e => {
      const code = e && e.code;
      setSync(code === 'auth' ? '同步失败：访问令牌无效、过期或权限不足' : code === 'net' ? '同步失败：连不上 GitHub' : code === 'pw' ? '同步暂停：云端数据的密码与本机不同'
        : code === 'http' && e.status === 404 ? '同步失败：找不到仓库，或令牌没有读写权限' : '同步失败，稍后自动重试', true);
      if (code === 'pw' && modal.hidden && (manual || !pwAsked)) { pwAsked = true; askSyncPw(e.remote); }
      return false;
    }).then(r => { syncing = null; return r; });
    return syncing;
  }
  function queueSync(ms) {
    if (!db || !db.sync) return;
    clearTimeout(syncTimer); syncTimer = setTimeout(() => syncNow(false), ms || 2500);
  }
  function askSyncPw(remote) {
    pendingRemote = remote;
    openModal('<h2>云端数据换了密码</h2><form id="syncpwf" autocomplete="off"><p>仓库里的数据是用另一个密码加密的（通常是你在另一台设备上修改了密码）。请输入那个密码，这台设备也会改用它。</p><label class="f req" style="margin-top:12px"><span>另一台设备现在使用的密码</span><input type="password" name="pw" id="syncpw" autocomplete="off" required></label><p class="lock-err" id="syncpw-err" role="alert"></p><div class="acts"><button type="button" class="btn" data-act="modal-close">以后再说</button><button class="btn primary">确定</button></div></form>');
  }
  async function adoptSyncPw(form) {
    const o = pendingRemote, err = $('#syncpw-err');
    err.textContent = '正在验证…';
    try {
      const key = await deriveKey(String(new FormData(form).get('pw')), unb64(o.salt));
      await decStr(key, o);
      clearTimeout(saveTimer); await rekey(key, o.salt); phCache.clear();
      pendingRemote = null; closeModal(); toast('密码已更新，继续同步'); syncNow(true);
    } catch (e) { err.textContent = '密码不正确'; }
  }
  function syncForm() {
    openModal('<h2>开启同步</h2><form id="syncf" autocomplete="off"><div style="display:flex;flex-direction:column;gap:12px">' +
      '<label class="f req"><span>GitHub 用户名</span><input type="text" name="owner" id="sync-owner" required></label>' +
      '<label class="f req"><span>私有仓库名</span><input type="text" name="repo" id="sync-repo" required></label>' +
      '<label class="f req"><span>访问令牌（以 github_pat_ 开头）</span><input type="password" name="token" id="sync-token" autocomplete="off" required></label>' +
      '<label class="f req"><span>密码</span><input type="password" name="pw" id="sync-pw" autocomplete="current-password" required></label>' +
      '<p class="fine">' + (cryptoKey ? '第一台设备：填这台设备的密码。第二台设备：填第一台设备的密码，这台设备会改用同一个密码。' : '这台设备还没有设密码，这里填的密码就会成为它的密码（至少 6 位）。如果另一台设备已经在同步，必须填和它相同的密码。忘记密码无法找回数据。') + '本机的示例数据不会带到云端。上传的全部是密文，令牌只保存在本机并随数据一起加密。</p>' +
      '</div><p class="lock-err" id="sync-err" role="alert"></p><div class="acts"><button type="button" class="btn" data-act="modal-close">取消</button><button class="btn primary">连接并同步</button></div></form>');
  }
  async function connectSync(form) {
    const f = new FormData(form), err = $('#sync-err'), pw = String(f.get('pw'));
    const c = { owner: String(f.get('owner')).trim(), repo: String(f.get('repo')).trim(), token: String(f.get('token')).trim() };
    if (!c.owner || !c.repo || !c.token) { err.textContent = '请把三项都填上'; return; }
    err.textContent = '正在连接…';
    try {
      const repo = await ghFetch(c, null);
      if (!repo.ok) { err.textContent = '找不到这个仓库，或令牌无权访问它'; return; }
      const file = await ghGet(c, 'data.json');
      if (file) {
        const o = JSON.parse(file.text);
        let key;
        try { key = await deriveKey(pw, unb64(o.salt)); await decStr(key, o); }
        catch (e) { err.textContent = '密码不对：仓库里已有数据，需要填另一台设备上使用的密码'; return; }
        if (o.salt !== saltB64) { clearTimeout(saveTimer); await rekey(key, o.salt); phCache.clear(); }
        const dp = db.patients.filter(p => p.demo).map(p => p.id);
        db.visits = db.visits.filter(v => !v.demo && dp.indexOf(v.patientId) < 0); db.patients = db.patients.filter(p => !p.demo);
      } else if (!cryptoKey) {
        // 这台设备还没设密码，仓库也是空的：直接用填的密码加密本机数据
        if (pw.length < 6) { err.textContent = '密码至少 6 位'; return; }
        const salt = crypto.getRandomValues(new Uint8Array(16));
        clearTimeout(saveTimer); await rekey(await deriveKey(pw, salt), b64(salt)); phCache.clear();
      } else {
        await saveChain;
        const ok = await deriveKey(pw, unb64(saltB64)).then(k => decStr(k, JSON.parse(localStorage.getItem(KEY)))).then(() => true, () => false);
        if (!ok) { err.textContent = '密码不正确'; return; }
      }
      armIdle();
      db.sync = c; pwAsked = false; save(); closeModal(); route();
      const ok = await syncNow(true);
      toast(ok ? '同步已开启' : '设置已保存，但首次同步没有成功：' + syncMsg.msg, !ok);
      if (location.hash === '#settings' && modal.hidden) route();
    } catch (e) {
      err.textContent = e && e.code === 'auth' ? '访问令牌无效、过期或权限不足' : e && e.code === 'net' ? '连不上 GitHub，请检查网络' : '连接失败，请重试';
    }
  }
  function syncCard() {
    const c = db.sync;
    return '<section class="card"><h2>多设备同步</h2>' + (!canCrypto
      ? '<p class="sub">当前打开方式不支持加密，无法同步。请用 Chrome、Edge 或三星浏览器打开。</p>'
      : !c ? '<p class="sub">把加密后的数据存进你的 GitHub 私有仓库，让电脑和手机看到同一份病历。需要一个私有仓库和一个只能访问它的访问令牌。</p><div class="acts" style="margin-top:12px"><button class="btn primary" data-act="sync-form">开启同步</button></div>'
        : '<p>仓库 <b>' + esc(c.owner + '/' + c.repo) + '</b>　<span id="sync-status"' + (syncMsg.err ? ' class="allergy"' : '') + '>' + esc(syncMsg.msg) + '</span></p><p class="fine" style="margin-top:4px">上次成功同步：' + (c.lastSync ? dTime(c.lastSync) : '还没有') + '。保存病历后会自动同步，另外每 3 分钟检查一次。</p><div class="acts" style="margin-top:12px"><button class="btn" data-act="sync-now">立即同步</button><button class="btn danger" data-act="sync-off">断开同步</button></div>') + '</section>';
  }

  /* ---------- 病历统计 ---------- */
  const rq = { kw: '', from: '', to: '' };
  function filteredVisits() {
    const kw = rq.kw.trim().toLowerCase();
    return db.visits.filter(v => {
      const day = dOnly(v.date);
      if (rq.from && day < rq.from) return false;
      if (rq.to && day > rq.to) return false;
      if (!kw) return true;
      const p = P(v.patientId);
      return [(p && p.name) || '', v.chief, v.disease, v.syndrome, v.western, v.rx.formula, v.rx.herbs.map(h => h.name).join(' '), v.symptoms.join(' ')].join(' ').toLowerCase().indexOf(kw) >= 0;
    }).sort(byDateDesc);
  }
  const tally = arr => { const m = new Map(); arr.forEach(x => { if (x) m.set(x, (m.get(x) || 0) + 1); }); return Array.from(m).sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0]), 'zh')); };
  const pct = (n, d) => d ? Math.round(n / d * 1000) / 10 + '%' : '—';
  function statTable(title, heads, rows, note) {
    return '<section class="card"><h2>' + title + '</h2>' + (rows.length ? '<div class="tw"><table class="list stat"><thead><tr>' + heads.map((h, i) => '<th' + (i ? ' class="num"' : '') + '>' + h + '</th>').join('') + '</tr></thead><tbody>' +
      rows.map(r => '<tr>' + r.map((c, i) => '<td' + (i ? ' class="num"' : '') + '>' + esc(c) + '</td>').join('') + '</tr>').join('') + '</tbody></table></div>' : '<p class="empty">暂无数据</p>') + (note ? '<p class="fine" style="margin-top:8px">' + note + '</p>' : '') + '</section>';
  }
  function recBody() {
    const list = filteredVisits(), n = list.length, rxs = list.filter(v => v.rx.herbs.length), nr = rxs.length;
    const herbStat = new Map(), pairs = [];
    rxs.forEach(v => {
      const names = Array.from(new Set(v.rx.herbs.map(h => h.name.trim()))).sort((a, b) => a.localeCompare(b, 'zh'));
      names.forEach(nm => { const s = herbStat.get(nm) || { n: 0, g: 0, gn: 0 }; s.n++; herbStat.set(nm, s); });
      v.rx.herbs.forEach(h => { const s = herbStat.get(h.name.trim()); if (h.unit === 'g' && h.dose > 0) { s.g += Number(h.dose); s.gn++; } });
      for (let i = 0; i < names.length; i++) for (let j = i + 1; j < names.length; j++) pairs.push(names[i] + ' + ' + names[j]);
    });
    const herbRows = Array.from(herbStat).sort((a, b) => b[1].n - a[1].n || a[0].localeCompare(b[0], 'zh')).slice(0, 20).map(x => [x[0], x[1].n, pct(x[1].n, nr), x[1].gn ? Math.round(x[1].g / x[1].gn * 10) / 10 + ' g' : '—']);
    const pairRows = tally(pairs).filter(x => x[1] >= 2).slice(0, 15).map(x => [x[0], x[1], pct(x[1], nr)]);
    const eff = list.filter(v => v.effect);
    const rows3 = (arr, total) => tally(arr).slice(0, 10).map(x => [x[0], x[1], pct(x[1], total)]);
    return '<p class="sum">符合条件的病历 <b>' + n + '</b> 份<i></i>患者 <b>' + new Set(list.map(v => v.patientId)).size + '</b> 人<i></i>处方 <b>' + nr + '</b> 张</p>' +
      '<div class="acts" style="margin-bottom:16px"><button class="btn" data-act="csv-visits">导出病历表（CSV）</button><button class="btn" data-act="csv-matrix">导出用药矩阵（CSV）</button><span class="fine">可用 Excel / SPSS 打开，做频次、关联规则等用药规律分析。</span></div>' +
      '<div class="stats">' +
      statTable('中医病名', ['病名', '例次', '占比'], rows3(list.map(v => v.disease), n)) +
      statTable('证型', ['证型', '例次', '占比'], rows3(list.map(v => v.syndrome), n)) +
      statTable('疗效评价', ['疗效', '例次', '占比'], rows3(eff.map(v => v.effect), eff.length), eff.length ? '复诊时对上次治疗的评价，共 ' + eff.length + ' 次。总有效率 ' + pct(eff.filter(v => v.effect !== '无效').length, eff.length) + '。' : '复诊接诊时在「上次治疗的疗效」里选择后，这里会统计。') +
      statTable('高频药物（前 20）', ['药名', '频次', '使用率', '平均剂量'], herbRows) +
      statTable('常用药对（前 15）', ['药对', '同现', '占处方'], pairRows, pairRows.length ? '' : '同时出现在 2 张及以上处方里的药对会列在这里。') +
      '</div>' +
      '<section class="card"><h2>病历列表</h2>' + visitTable(list.slice(0, 50), true) + (n > 50 ? '<p class="fine">仅显示最近 50 份，导出 CSV 可得到全部。</p>' : '') + '</section>';
  }
  function vRecords() {
    return '<header class="head"><div><h1>病历统计</h1><p class="sub">按关键词和日期筛选病历，统计病种、证型和用药规律。</p></div></header>' +
      '<section class="card filt"><label class="f"><span>关键词（姓名 / 主诉 / 症状 / 诊断 / 方名 / 药名）</span><input type="search" id="rq-kw" value="' + esc(rq.kw) + '"></label>' +
      '<label class="f"><span>起始日期</span><input type="date" id="rq-from" value="' + rq.from + '"></label><label class="f"><span>截止日期</span><input type="date" id="rq-to" value="' + rq.to + '"></label>' +
      '<button class="btn" data-act="rq-clear">清除筛选</button></section><div id="rec-body">' + recBody() + '</div>';
  }
  function download(name, text, type) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type: type }));
    a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
  const csv = rows => '﻿' + rows.map(r => r.map(c => '"' + String(c == null ? '' : c).replace(/"/g, '""') + '"').join(',')).join('\r\n');
  function csvVisits() {
    const list = filteredVisits().reverse();
    if (!list.length) { toast('没有可导出的病历', true); return; }
    const rows = [['就诊时间', '姓名', '性别', '年龄', '初复诊', '妊娠期', '主诉', '现病史', '症状', '舌质', '舌苔', '脉象', '四诊补充', '中医病名', '证型', '西医诊断', '治法', '上次疗效', '方名', '药物组成', '药味数', '剂数', '用法', '医嘱']];
    list.forEach(v => {
      const p = P(v.patientId) || {}, a = p.id ? ageOf(p) : null, has = v.rx.herbs.length;
      rows.push([dTime(v.date), p.name || '', p.gender || '', a == null ? '' : a, v.type, v.pregnant ? '是' : '', v.chief, v.hpi, v.symptoms.join('、'), v.tongueBody.join('、'), v.tongueCoat.join('、'), v.pulse.join('、'), v.exam, v.disease, v.syndrome, v.western, v.method, v.effect || '', v.rx.formula,
        v.rx.herbs.map(h => h.name + h.dose + h.unit + (h.note ? '(' + h.note + ')' : '')).join('、'), has, has ? v.rx.doses : '', has ? v.rx.usage : '', v.advice]);
    });
    download('病历表_' + dOnly(new Date()) + '.csv', csv(rows), 'text/csv;charset=utf-8');
    toast('已导出 ' + list.length + ' 份病历');
  }
  function csvMatrix() {
    const list = filteredVisits().filter(v => v.rx.herbs.length).reverse();
    if (!list.length) { toast('没有可导出的处方', true); return; }
    const sets = list.map(v => new Set(v.rx.herbs.map(h => h.name.trim())));
    const herbs = tally(sets.flatMap(s => Array.from(s))).map(x => x[0]);
    const rows = [['序号', '就诊时间', '姓名', '中医病名', '证型'].concat(herbs)];
    list.forEach((v, i) => rows.push([i + 1, dTime(v.date), (P(v.patientId) || {}).name || '', v.disease, v.syndrome].concat(herbs.map(h => sets[i].has(h) ? 1 : 0))));
    download('用药矩阵_' + dOnly(new Date()) + '.csv', csv(rows), 'text/csv;charset=utf-8');
    toast('已导出 ' + list.length + ' 张处方 × ' + herbs.length + ' 味药');
  }
  function saveMy(form) {
    const name = String(new FormData(form).get('name')).trim();
    if (!name) { toast('请填写方名', true); return; }
    const herbs = clone(draft.rx.herbs.filter(h => h.name.trim()));
    const old = db.myFormulas.find(f => f.name === name);
    if (old) { old.herbs = herbs; old.createdAt = new Date().toISOString(); touch(old); }
    else db.myFormulas.push(touch({ id: uid(), name: name, herbs: herbs, createdAt: new Date().toISOString() }));
    save(); closeModal(); $('#fx-pick').innerHTML = fxOptions();
    toast(old ? '已更新常用方「' + name + '」' : '已存为常用方「' + name + '」');
  }

  /* ---------- 路由 ---------- */
  function route() {
    if (locked) return;
    $('#side-lock').hidden = !cryptoKey;
    const parts = decodeURIComponent(location.hash.slice(1) || 'dashboard').split('/');
    const view = parts[0], a = parts[1], b = parts[2], c = parts[3];
    const missing = '<p class="empty">没有找到这条记录。<a class="link" href="#dashboard">回工作台</a></p>';
    let html, nav = view;
    draft = null;
    if (!modal.hidden) closeModal();
    if (view === 'patients') html = vPatients(false);
    else if (view === 'patient') { html = P(a) ? vPatient(P(a)) : missing; nav = 'patients'; }
    else if (view === 'consult') {
      if (!a && draftDirty() && P(db.draft.patientId)) { location.replace('#consult/' + db.draft.patientId + (db.draft.id ? '/edit/' + db.draft.id : '')); return; }
      if (!a) html = vPatients(true);
      else if (!P(a)) html = missing;
      else { prepareDraft(P(a), b, c); html = vConsult(P(a)); }
    }
    else if (view === 'visit') { html = V(a) ? vVisit(V(a)) : missing; nav = 'patients'; }
    else if (view === 'records') html = vRecords();
    else if (view === 'library') html = vLibrary(a);
    else if (view === 'settings') html = vSettings();
    else { html = vDashboard(); nav = 'dashboard'; }
    main.innerHTML = html;
    document.querySelectorAll('#nav a').forEach(el => el.classList.toggle('on', el.dataset.nav === nav));
    window.scrollTo(0, 0);
    if (draft) { updateSuggest(); renderRx(); updateDiff(); renderPhotos(); save(); }
    hydratePhotos(main);
    gcPhotos();
  }

  /* ---------- 事件 ---------- */
  const acts = {
    go: el => go(el.dataset.to),
    'modal-close': closeModal,
    'modal-yes': () => { const f = pendingYes; if (f) f(); },
    'patient-form': el => patientForm(el.dataset.id, el.dataset.then),
    'patient-del': el => {
      const p = P(el.dataset.id), n = visitsOf(p.id).length;
      confirmBox('删除患者', '<p>将删除 <b>' + esc(p.name) + '</b> 的档案' + (n ? '及其 ' + n + ' 份病历' : '') + '，无法恢复。</p>', '删除', () => {
        bury(p.id); visitsOf(p.id).forEach(v => bury(v.id));
        db.patients = db.patients.filter(x => x.id !== p.id); db.visits = db.visits.filter(v => v.patientId !== p.id);
        if (db.draft && db.draft.patientId === p.id) db.draft = null;
        save(); closeModal(); toast('已删除'); go('patients');
      }, true);
    },
    'visit-del': el => {
      const v = V(el.dataset.id);
      confirmBox('删除病历', '<p>将删除 ' + dTime(v.date) + ' 的这份病历，无法恢复。</p>', '删除', () => {
        bury(v.id); db.visits = db.visits.filter(x => x.id !== v.id); save(); closeModal(); toast('已删除'); go('patient/' + v.patientId);
      }, true);
    },
    chip: el => {
      const arr = draft[el.dataset.g], v = el.dataset.v, i = arr.indexOf(v);
      if (i >= 0) arr.splice(i, 1); else arr.push(v);
      el.classList.toggle('on', i < 0); el.setAttribute('aria-pressed', i < 0);
      updateSuggest(); updateDiff(); renderRxMeta(); queueSave();
    },
    adopt: el => {
      const sy = T.SYNDROMES.find(s => s.name === el.dataset.sy);
      draft.syndrome = sy.name; draft.method = sy.method;
      $('#c-syndrome').value = sy.name; $('#c-method').value = sy.method;
      queueSave();
      if (el.dataset.fx) askFormula(el.dataset.fx); else toast('已填入证型和治法');
    },
    'fx-pick': el => { const name = $('#fx-pick').value; if (!name) { toast('请先选择方剂', true); return; } snapRx(); loadFormula(name, el.dataset.mode); },
    'fx-load': el => { const fx = el.dataset.fx, mode = el.dataset.mode; closeModal(); snapRx(); loadFormula(fx, mode); },
    'rx-go': () => { const i = $('#rx-quick'); runRx(i.value); i.value = ''; i.focus(); },
    'rx-clear': () => { if (!draft.rx.herbs.length && !draft.rx.formula) return; snapRx(); draft.rx.herbs = []; draft.rx.formula = ''; $('#c-formula').value = ''; renderRx(); queueSave(); toast('已清空，点「撤销」可以恢复'); },
    'rx-undo': () => {
      if (!rxUndo) { toast('没有可撤销的操作', true); return; }
      const cur = clone(draft.rx); draft.rx = rxUndo; rxUndo = cur;
      $('#c-formula').value = draft.rx.formula; $('#c-doses').value = draft.rx.doses; $('#c-usage').value = draft.rx.usage;
      renderRx(); queueSave(); toast('已撤销（再点一次可恢复）');
    },
    'rx-text': () => openModal('<h2>整方文本编辑</h2><form id="rxtf" autocomplete="off"><label class="f"><span>一味药写「药名+剂量」，用空格或顿号隔开；煎法写在后面，如 石膏30先煎、阿胶9(烊化)</span><textarea name="t" id="rxt" rows="8" style="font-size:15px;line-height:1.9">' + esc(herbsToText(draft.rx.herbs)) + '</textarea></label><p class="fine" style="margin-top:8px">保存后会用这里的内容替换整张处方，可以随意增删、调换顺序。</p><div class="acts"><button type="button" class="btn" data-act="modal-close">取消</button><button class="btn primary">保存</button></div></form>', true),
    'rx-del': el => { draft.rx.herbs.splice(+el.dataset.i, 1); renderRx(); queueSave(); },
    advice: el => {
      const ta = $('#c-advice'), v = el.dataset.v;
      draft.advice = (draft.advice ? draft.advice.replace(/[，。\s]*$/, '') + '，' : '') + v; ta.value = draft.advice; queueSave();
    },
    'consult-save': el => saveVisit(!!el.dataset.print),
    'consult-cancel': () => {
      const pid = draft.patientId;
      confirmBox('放弃', '<p>本次填写的内容不会保存。</p>', '放弃', () => { db.draft = null; draft = null; save(); closeModal(); go('patient/' + pid); }, true);
    },
    'draft-drop': () => { db.draft = null; save(); route(); },
    'demo-clear': () => confirmBox('清除示例数据', '<p>将删除所有带「示例」标记的患者和病历，你自己录入的数据不受影响。</p>', '清除', () => {
      const dp = db.patients.filter(p => p.demo).map(p => p.id);
      db.visits.filter(v => v.demo || dp.indexOf(v.patientId) >= 0).forEach(v => bury(v.id)); dp.forEach(bury);
      db.patients = db.patients.filter(p => !p.demo); db.visits = db.visits.filter(v => !v.demo && P(v.patientId));
      if (db.draft && !P(db.draft.patientId)) db.draft = null;
      save(); closeModal(); toast('示例数据已清除'); route();
    }),
    wipe: () => db.sync ? toast('已开启同步，请先断开同步再清空', true) : confirmBox('清空全部数据', '<p>将删除<b>所有</b>患者和病历，无法恢复。建议先导出备份。</p>', '全部清空', () => {
      db = { settings: db.settings, myFormulas: db.myFormulas, patients: [], visits: [], draft: null }; save(); closeModal(); toast('已清空'); go('dashboard');
    }, true),
    print: el => printVisit(el.dataset.id, el.dataset.mode),
    export: exportData,
    'do-print': () => window.print(),
    'sheet-img': el => sheetImage(el.dataset.id, el.dataset.mode),
    'sheet-share': () => { if (sheetFile) navigator.share({ files: [sheetFile] }).catch(() => {}); },
    'sheet-dl': () => {
      if (!sheetFile) return;
      const a = document.createElement('a');
      a.href = URL.createObjectURL(sheetFile); a.download = sheetFile.name;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
      toast('图片已保存到下载文件夹');
    },
    'lock-now': lockNow,
    'sync-form': syncForm,
    'sync-now': () => syncNow(true).then(ok => { toast(ok ? '同步完成' : syncMsg.msg || '同步失败', !ok); if (location.hash === '#settings' && modal.hidden) route(); }),
    'sync-off': () => confirmBox('断开同步', '<p>这台设备将不再与 GitHub 仓库同步，并删除保存在本机的访问令牌。</p><p>本机数据和仓库里的数据都会保留，以后可以重新开启。</p>', '断开', () => { delete db.sync; save(); setSync(''); closeModal(); toast('已断开同步'); route(); }, true),
    'pw-form': el => pwForm(el.dataset.mode),
    forgot: () => confirmBox('忘记密码', '<p>密码没有保存在任何地方，无法找回或重置，加密的数据也无法解开。</p><p>如果你有备份文件（未加密的，或记得当时密码的），可以清除本机数据后，到「设置与备份」里从备份恢复。</p><p><b>清除后，这台电脑这个浏览器里的全部病历和照片将永久删除。</b></p>', '清除本机全部数据', () => {
      try { localStorage.removeItem(KEY); } catch (e) { /* 忽略 */ }
      idb.keys().then(ks => Promise.all(ks.map(k => idb.del(k)))).catch(() => {}).then(() => location.reload());
    }, true),
    'photo-view': el => viewPhoto(el.dataset.id),
    'photo-del': el => { draft.photos = draft.photos.filter(p => p.id !== el.dataset.id); renderPhotos(); queueSave(); },
    'add-herb': el => {
      draft.rx.herbs.push({ name: el.dataset.n, dose: Number(el.dataset.d), unit: 'g', note: el.dataset.note || T.autoNote(el.dataset.n) });
      if (draft.rx.formula && !/加减$/.test(draft.rx.formula)) { draft.rx.formula += '加减'; $('#c-formula').value = draft.rx.formula; }
      renderRx(); queueSave();
    },
    'my-save': () => {
      const n = draft.rx.herbs.filter(h => h.name.trim()).length;
      if (!n) { toast('处方里还没有药', true); return; }
      openModal('<h2>存为常用方</h2><form id="mf" autocomplete="off"><label class="f req"><span>方名</span><input type="text" id="mf-name" name="name" required value="' + esc(draft.rx.formula || '') + '"></label><p class="fine" style="margin-top:8px">保存当前处方的 ' + n + ' 味药和剂量，同名会覆盖。之后在「从方剂库选方」的最上面可以直接选用。</p><div class="acts"><button type="button" class="btn" data-act="modal-close">取消</button><button class="btn primary">保存</button></div></form>');
    },
    'my-del': el => {
      const f = db.myFormulas.find(x => x.id === el.dataset.id);
      confirmBox('删除常用方', '<p>将删除常用方「' + esc(f.name) + '」，已保存的病历不受影响。</p>', '删除', () => { bury(f.id); db.myFormulas = db.myFormulas.filter(x => x.id !== f.id); save(); closeModal(); toast('已删除'); route(); }, true);
    },
    'csv-visits': csvVisits,
    'csv-matrix': csvMatrix,
    'rq-clear': () => { rq.kw = rq.from = rq.to = ''; route(); }
  };

  document.addEventListener('click', e => {
    if (e.target === modal) { closeModal(); return; }
    const el = e.target.closest('[data-act]'); if (!el) return;
    const inner = e.target.closest('button,a,input,select,label');
    if (inner && inner !== el && el.contains(inner) && !inner.dataset.act) return;
    if (inner && inner !== el && inner.dataset.act) { e.stopPropagation(); acts[inner.dataset.act](inner, e); return; }
    acts[el.dataset.act](el, e);
  });
  document.addEventListener('input', e => {
    const t = e.target;
    if (t.dataset.bind && draft) {
      const path = t.dataset.bind.split('.'), obj = path.length > 1 ? draft[path[0]] : draft, k = path[path.length - 1];
      if (t.type === 'checkbox') obj[k] = t.checked;
      else if (k === 'date') { const d = new Date(t.value); if (!isNaN(d)) obj[k] = d.toISOString(); }
      else if (k === 'doses') obj[k] = Number(t.value) || 1;
      else obj[k] = t.value;
      if (k === 'pregnant' || k === 'doses') renderRxMeta();
      queueSave();
    } else if (t.dataset.hf && draft) {
      const h = draft.rx.herbs[+t.closest('[data-i]').dataset.i], f = t.dataset.hf;
      h[f] = f === 'dose' ? (t.value === '' ? '' : Number(t.value)) : t.value;
      renderRxMeta(); queueSave();
    } else if (t.id === 'pq') $('#plist').innerHTML = patientRows(t.value, !!t.dataset.pick);
    else if (t.id === 'lq') $('#lib').innerHTML = libList(t.dataset.tab, t.value);
    else if (t.id.indexOf('rq-') === 0) { rq[t.id.slice(3)] = t.value; $('#rec-body').innerHTML = recBody(); }
    else if (t.dataset.set) { db.settings[t.dataset.set] = t.type === 'checkbox' ? t.checked : t.value; db.settings.u = Date.now(); queueSave(); queueSync(2500); }
    else if (t.id === 'pf-birth' && t.value) $('#pf-age').value = ageOf({ birth: t.value });
    else if (t.id === 'pf-age') $('#pf-birth').value = '';
  });
  document.addEventListener('change', e => {
    const t = e.target;
    if (t.id === 'import-file' && t.files[0]) { if (db.sync) toast('已开启同步，请先断开同步再从备份恢复', true); else importData(t.files[0]); t.value = ''; }
    else if (t.id === 'ph-file' && draft) { addPhotos(t.files); t.value = ''; }
    else if (t.dataset.hf === 'name' && draft) {
      const i = +t.closest('[data-i]').dataset.i, h = draft.rx.herbs[i], n = T.autoNote(t.value);
      if (n && !h.note) { h.note = n; $('#h-note-' + i).value = n; renderRxMeta(); queueSave(); }
    }
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && !modal.hidden) closeModal();
    if (e.key === 'Enter' && e.target.id === 'rx-quick') { e.preventDefault(); runRx(e.target.value); e.target.value = ''; }
  });
  document.addEventListener('paste', e => {
    if (!draft || !modal.hidden || !e.clipboardData) return;
    const imgs = Array.from(e.clipboardData.files || []).filter(f => /^image\//.test(f.type));
    if (imgs.length) { e.preventDefault(); addPhotos(imgs); }
  });
  document.addEventListener('submit', e => {
    if (e.target.id === 'pf') { e.preventDefault(); savePatient(e.target); }
    else if (e.target.id === 'mf') { e.preventDefault(); saveMy(e.target); }
    else if (e.target.id === 'lockf') { e.preventDefault(); unlock(String(new FormData(e.target).get('pw'))); }
    else if (e.target.id === 'pwf') { e.preventDefault(); doPw(e.target); }
    else if (e.target.id === 'impf') { e.preventDefault(); decryptBackup(e.target); }
    else if (e.target.id === 'rxtf') {
      e.preventDefault(); snapRx();
      draft.rx.herbs = textToHerbs(String(new FormData(e.target).get('t')));
      closeModal(); renderRx(); queueSave(); toast('处方已更新，共 ' + draft.rx.herbs.length + ' 味');
    }
    else if (e.target.id === 'syncf') { e.preventDefault(); connectSync(e.target); }
    else if (e.target.id === 'syncpwf') { e.preventDefault(); adoptSyncPw(e.target); }
  });
  window.addEventListener('hashchange', route);
  window.addEventListener('beforeunload', () => { clearTimeout(saveTimer); save(); });
  // 加密保存是异步的，页面切到后台时先存一次，避免关闭瞬间来不及写入
  document.addEventListener('visibilitychange', () => { if (document.hidden) { clearTimeout(saveTimer); save(); } else queueSync(1000); });
  setInterval(() => { if (!document.hidden) syncNow(false); }, 180000);
  window.addEventListener('online', () => queueSync(1000));

  $('#herb-list').innerHTML = T.ALL_HERBS.map(h => '<option value="' + h + '">').join('');
  $('#disease-list').innerHTML = T.DISEASES.map(h => '<option value="' + h + '">').join('');

  // 自检：证型引用的症状、方剂必须都在库里
  function selfCheck() {
    const vocab = new Set(T.SYMPTOM_GROUPS.flatMap(g => g.items)), fx = new Set(T.FORMULAS.map(f => f.name)), bad = [];
    T.SYNDROMES.forEach(s => {
      s.main.concat(s.minor).forEach(x => { if (!vocab.has(x)) bad.push(s.name + ' 症状:' + x); });
      s.tongue.forEach(x => { if (T.TONGUE_BODY.indexOf(x) < 0) bad.push(s.name + ' 舌:' + x); });
      s.coat.forEach(x => { if (T.TONGUE_COAT.indexOf(x) < 0) bad.push(s.name + ' 苔:' + x); });
      s.pulse.forEach(x => { if (T.PULSES.indexOf(x) < 0) bad.push(s.name + ' 脉:' + x); });
      s.formulas.forEach(x => { if (!fx.has(x)) bad.push(s.name + ' 方:' + x); });
    });
    return bad;
  }
  window.TCMApp = { diagnose: diagnose, checkRx: checkRx, selfCheck: selfCheck, db: () => db, encrypted: () => !!cryptoKey };

  if (locked) showLock(); else route();
  // 放到网上（https）后启用离线支持；本地双击或 localhost 预览时不启用
  if (location.protocol === 'https:' && 'serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
})();
