/* API 请求封装：统一 JSON、鉴权、错误处理 */
window.API = (function () {
  async function request(method, url, body, opts) {
    opts = opts || {};
    const init = { method, headers: {} };
    if (body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const res = await fetch(url, init);
    let data = null;
    try { data = await res.json(); } catch (e) { /* 非 JSON 响应 */ }
    if (res.status === 401) {
      // 未登录：仅当非静默请求、且不在登录页时才跳转，避免登录页自身反复重定向导致闪烁
      const onLoginPage = (location.pathname.split("/").pop() || "index.html") === "index.html";
      if (!opts.silent && !onLoginPage) {
        const path = encodeURIComponent(location.pathname + location.search);
        location.href = "/index.html?next=" + path;
      }
      throw new Error((data && data.error) || "未登录");
    }
    if (res.status === 403) {
      throw new Error((data && data.error) || "权限不足");
    }
    if (!res.ok) {
      throw new Error((data && data.error) || ("请求失败 (" + res.status + ")"));
    }
    return data;
  }

  return {
    get: (url, opts) => request("GET", url, undefined, opts),
    post: (url, body, opts) => request("POST", url, body, opts),
    put: (url, body, opts) => request("PUT", url, body, opts),
    del: (url, opts) => request("DELETE", url, undefined, opts),
    raw: request,
  };
})();

/* 通用 UI 工具 */
window.UI = (function () {
  function toast(msg, type) {
    let box = document.getElementById("toast");
    if (!box) {
      box = document.createElement("div");
      box.id = "toast";
      document.body.appendChild(box);
    }
    const el = document.createElement("div");
    el.className = "toast " + (type || "");
    el.textContent = msg;
    box.appendChild(el);
    setTimeout(() => { el.remove(); }, 3200);
  }
  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function fmtTime(ts) {
    if (!ts) return "-";
    const d = new Date(typeof ts === "number" && ts < 1e12 ? ts * 1000 : ts);
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }
  function modal(title, bodyHtml, footHtml) {
    let mask = document.getElementById("modal-mask");
    if (!mask) {
      mask = document.createElement("div");
      mask.id = "modal-mask";
      mask.className = "modal-mask";
      mask.innerHTML = `<div class="modal">
        <div class="modal-head"><span class="m-title"></span><button class="btn ghost sm m-close">✕</button></div>
        <div class="modal-body"></div>
        <div class="modal-foot"></div>
      </div>`;
      document.body.appendChild(mask);
    }
    mask.querySelector(".m-title").textContent = title;
    mask.querySelector(".modal-body").innerHTML = bodyHtml;
    const foot = mask.querySelector(".modal-foot");
    foot.innerHTML = footHtml || "";
    mask.classList.add("show");
    mask.querySelector(".m-close").onclick = () => mask.classList.remove("show");
    mask.onclick = (e) => { if (e.target === mask) mask.classList.remove("show"); };
    return {
      close: () => mask.classList.remove("show"),
      body: mask.querySelector(".modal-body"),
      foot,
    };
  }
  function badge(text, cls) {
    return `<span class="badge ${cls || "muted"}">${esc(text)}</span>`;
  }
  function actionBadge(a) {
    const map = { reject: "danger", review: "warning", alert: "info", pass: "success" };
    const label = { reject: "拒绝", review: "复核", alert: "告警", pass: "放行" };
    return `<span class="badge ${map[a] || "muted"}">${label[a] || esc(a)}</span>`;
  }
  function levelBadge(lv) {
    const map = { "低": "低", "中": "中", "高": "高", "严重": "严重" };
    return `<span class="badge ${map[lv] || "muted"}">${esc(lv)}</span>`;
  }
  function statusBadge(s) {
    const map = { new: ["新", "danger"], acked: ["已确认", "warning"], resolved: ["已解决", "success"] };
    const [l, c] = map[s] || [s, "muted"];
    return `<span class="badge ${c}">${l}</span>`;
  }
  function jsonPretty(obj) {
    return JSON.stringify(obj, null, 2);
  }
  return { toast, esc, fmtTime, modal, badge, actionBadge, levelBadge, statusBadge, jsonPretty };
})();

/* 会话 / 导航 */
window.App = (function () {
  let me = null;
  async function init() {
    try {
      const r = await API.get("/api/me", { silent: true });
      me = r.user;
    } catch (e) {
      me = null;
    }
    return me;
  }
  function currentUser() { return me; }
  function hasRole(...roles) { return me && roles.includes(me.role); }
  function logout() {
    API.post("/api/logout").then(() => { location.href = "/index.html"; });
  }
  // 注入侧边栏与顶栏
  const NAV = [
    ["index.html", "📊", "总览"],
    ["rules.html", "📜", "规则配置"],
    ["flows.html", "🔀", "决策流设计"],
    ["events.html", "⚡", "实时事件流"],
    ["alerts.html", "🔔", "告警列表"],
    ["stats.html", "📈", "统计报表"],
    ["versions.html", "🕘", "规则版本管理"],
    ["sandbox.html", "🧪", "测试沙箱"],
    ["users.html", "👥", "用户管理"],
    ["settings.html", "⚙️", "系统设置"],
    ["dict.html", "📚", "数据字典"],
  ];
  function renderShell(title) {
    const cur = location.pathname.split("/").pop() || "index.html";
    const navHtml = NAV.map(([f, ico, label]) =>
      `<a href="/${f}" class="${f === cur ? "active" : ""}"><span class="ico">${ico}</span>${label}</a>`
    ).join("");
    const user = me ? me : null;
    const userHtml = user
      ? `<span>${UI.esc(user.nickname || user.username)} (${UI.esc(user.role)})</span>
         <button class="btn sm ghost" onclick="App.logout()">退出</button>`
      : `<a href="/index.html">登录</a>`;
    const app = document.getElementById("app");
    if (!app) return;
    app.innerHTML = `
      <div class="sidebar">
        <div class="brand">🛡️ 风控引擎<small>规则引擎 · 决策流</small></div>
        <nav>${navHtml}</nav>
        <div class="foot">Rete · 滑动窗口 · 热更新</div>
      </div>
      <div class="main">
        <div class="topbar">
          <div class="title">${UI.esc(title || "")}</div>
          <div class="user">${userHtml}</div>
        </div>
        <div class="content" id="page"></div>
      </div>`;
  }
  return { init, currentUser, hasRole, logout, renderShell, NAV };
})();

/* 页面引导：登录检查 + 渲染骨架 */
async function boot(title, ready) {
  const user = await App.init();
  if (!user) { location.href = "/index.html"; return; }
  App.renderShell(title);
  if (ready) await ready();
}
