/* ═══════════════════════════════════════════════════════════
   Frida Childs Play - Frontend Application Logic
   ═══════════════════════════════════════════════════════════ */

// ─── State ──────────────────────────────────────────────────
let selectedDevice = "";
let selectedApp = "";
let allApps = [];
let currentFilePath = "";
let currentFilePackage = "";
let selectedClassName = "";

// ─── SocketIO ───────────────────────────────────────────────
const socket = io();

socket.on("connect", () => {
    appendLog("info", "Connected to server");
});

socket.on("disconnect", () => {
    appendLog("warn", "Disconnected from server");
});

socket.on("devices_update", (devices) => {
    updateDeviceSelect(devices);
});

socket.on("log_message", (data) => {
    appendLog(data.level, data.message);
});

socket.on("frida_progress", (data) => {
    updateFridaProgress(data);
});

socket.on("script_output", (data) => {
    appendScriptOutput(data.type, data.payload);
});

socket.on("runtime_event", (data) => {
    // Could be used for real-time monitoring
    console.log("Runtime event:", data);
});

// ─── Tab Navigation ─────────────────────────────────────────
document.querySelectorAll(".nav-btn").forEach(btn => {
    btn.addEventListener("click", () => {
        const tab = btn.dataset.tab;
        switchTab(tab);
    });
});

function switchTab(tabName) {
    document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));

    const navBtn = document.querySelector(`[data-tab="${tabName}"]`);
    const panel = document.getElementById(`tab-${tabName}`);

    if (navBtn) navBtn.classList.add("active");
    if (panel) panel.classList.add("active");
}

// ─── Device Management ──────────────────────────────────────
function refreshDevices() {
    fetch("/api/devices")
        .then(r => r.json())
        .then(data => {
            updateDeviceSelect(data.devices);
        })
        .catch(e => appendLog("error", "Failed to fetch devices"));
}

function updateDeviceSelect(devices) {
    const sel = document.getElementById("device-select");
    const current = sel.value;
    sel.innerHTML = '<option value="">-- Select Device --</option>';

    (devices || []).forEach(d => {
        if (d.status !== "device") return;
        const opt = document.createElement("option");
        opt.value = d.id;
        opt.textContent = `${d.id} (${d.model || d.type})`;
        sel.appendChild(opt);
    });

    // Restore selection
    if (current && sel.querySelector(`option[value="${current}"]`)) {
        sel.value = current;
    }

    // Update sidebar status
    const indicator = document.getElementById("device-status-indicator");
    const dot = indicator.querySelector(".status-dot");
    const statusText = indicator.querySelector(".status-text");

    const online = devices && devices.some(d => d.status === "device");
    if (online) {
        dot.className = "status-dot online";
        const cnt = devices.filter(d => d.status === "device").length;
        statusText.textContent = `${cnt} device${cnt > 1 ? 's' : ''} connected`;
    } else {
        dot.className = "status-dot offline";
        statusText.textContent = "No Device";
    }
}

function onDeviceSelected() {
    const sel = document.getElementById("device-select");
    selectedDevice = sel.value;

    const setupBtn = document.getElementById("setup-frida-btn");
    const infoDiv = document.getElementById("device-info");

    if (!selectedDevice) {
        setupBtn.disabled = true;
        infoDiv.style.display = "none";
        return;
    }

    setupBtn.disabled = false;
    infoDiv.style.display = "block";
    appendLog("info", `Device selected: ${selectedDevice}`);

    // Fetch device info
    fetch(`/api/device/${selectedDevice}/info`)
        .then(r => r.json())
        .then(info => {
            document.getElementById("info-model").textContent = info.model || "?";
            document.getElementById("info-android").textContent = info.android_version || "?";
            document.getElementById("info-arch").textContent = info.architecture || "?";
            document.getElementById("info-type").textContent = info.type || "?";
            document.getElementById("info-root").textContent = info.rooted ? "✅ Yes" : "❌ No";
        })
        .catch(() => {});

    // Check Frida status
    checkFridaStatus();
}

function checkFridaStatus() {
    if (!selectedDevice) return;

    fetch(`/api/frida/status/${selectedDevice}`)
        .then(r => r.json())
        .then(data => {
            const hostEl = document.getElementById("frida-host-status");
            const deviceEl = document.getElementById("frida-device-status");
            const runningEl = document.getElementById("frida-server-running");

            if (data.host_version) {
                hostEl.className = "status-badge ok";
                hostEl.textContent = data.host_version;
            } else {
                hostEl.className = "status-badge error";
                hostEl.textContent = "Not Installed";
            }

            if (data.device_version) {
                deviceEl.className = "status-badge ok";
                deviceEl.textContent = data.device_version;
            } else {
                deviceEl.className = "status-badge error";
                deviceEl.textContent = "Not Found";
            }

            if (data.server_running) {
                runningEl.className = "status-badge ok";
                runningEl.textContent = "Running";
            } else {
                runningEl.className = "status-badge error";
                runningEl.textContent = "Stopped";
            }
        })
        .catch(() => {});
}

// ─── Frida Setup ────────────────────────────────────────────
function setupFrida() {
    if (!selectedDevice) return;

    const btn = document.getElementById("setup-frida-btn");
    btn.disabled = true;
    btn.innerHTML = '<span class="loading-spinner"></span> Setting up...';

    document.getElementById("frida-progress").style.display = "block";
    document.getElementById("sudo-prompt").style.display = "none";

    fetch(`/api/frida/setup/${selectedDevice}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({})
    })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                appendLog("info", data.message);
                showToast(data.message, "success");
            } else if (data.message === "SUDO_REQUIRED") {
                document.getElementById("sudo-prompt").style.display = "block";
                appendLog("warn", "Sudo password required for pip install");
            } else {
                appendLog("error", data.message);
                showToast(data.message, "error");
            }
            btn.disabled = false;
            btn.innerHTML = '⚡ Auto Setup Frida';
            checkFridaStatus();
        })
        .catch(e => {
            appendLog("error", "Setup failed: " + e.message);
            btn.disabled = false;
            btn.innerHTML = '⚡ Auto Setup Frida';
        });
}

function setupFridaWithSudo() {
    if (!selectedDevice) return;
    const password = document.getElementById("sudo-password").value;
    if (!password) return;

    const btn = document.getElementById("setup-frida-btn");
    btn.disabled = true;
    btn.innerHTML = '<span class="loading-spinner"></span> Installing with sudo...';

    fetch(`/api/frida/setup/${selectedDevice}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sudo_password: password })
    })
        .then(r => r.json())
        .then(data => {
            document.getElementById("sudo-prompt").style.display = "none";
            document.getElementById("sudo-password").value = "";
            if (data.success) {
                appendLog("info", data.message);
                showToast(data.message, "success");
            } else {
                appendLog("error", data.message);
                showToast(data.message, "error");
            }
            btn.disabled = false;
            btn.innerHTML = '⚡ Auto Setup Frida';
            checkFridaStatus();
        })
        .catch(e => {
            appendLog("error", "Setup error: " + e.message);
            btn.disabled = false;
            btn.innerHTML = '⚡ Auto Setup Frida';
        });
}

function updateFridaProgress(data) {
    const bar = document.getElementById("frida-progress-bar");
    const text = document.getElementById("frida-progress-text");
    const wrapper = document.getElementById("frida-progress");

    wrapper.style.display = "block";

    if (data.percent >= 0) {
        bar.style.width = data.percent + "%";
    }
    text.textContent = data.detail || data.step || "Processing...";
}

// ─── Applications ───────────────────────────────────────────
function loadApps() {
    if (!selectedDevice) {
        showToast("Select a device first", "error");
        return;
    }

    const systemApps = document.getElementById("show-system-apps").checked;
    const tbody = document.getElementById("apps-tbody");
    tbody.innerHTML = '<tr><td colspan="4" class="empty-state"><span class="loading-spinner"></span> Loading...</td></tr>';

    fetch(`/api/apps/${selectedDevice}?system=${systemApps}`)
        .then(r => r.json())
        .then(data => {
            allApps = data.apps || [];
            renderApps(allApps);
        })
        .catch(e => {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-state">Error loading apps</td></tr>';
        });
}

function renderApps(apps) {
    const tbody = document.getElementById("apps-tbody");

    if (!apps.length) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No applications found</td></tr>';
        return;
    }

    tbody.innerHTML = apps.map(app => {
        const pidClass = app.pid > 0 ? "pid-running" : "pid-stopped";
        const pidText = app.pid > 0 ? app.pid : "-";
        const isSelected = selectedApp === app.identifier;

        return `
        <tr class="${isSelected ? 'selected' : ''}" onclick="selectApp('${app.identifier}', '${escapeHtml(app.name)}', ${app.pid})">
            <td><span class="pid-badge ${pidClass}">${pidText}</span></td>
            <td>${escapeHtml(app.name)}</td>
            <td style="font-family:'JetBrains Mono';font-size:11px;color:var(--text-muted)">${app.identifier}</td>
            <td>
                <button class="btn btn-sm btn-ghost" onclick="event.stopPropagation(); startApp('${app.identifier}')">▶ Start</button>
                <button class="btn btn-sm btn-ghost" onclick="event.stopPropagation(); killApp('${app.identifier}')" style="color:var(--accent-red)">⬛ Kill</button>
            </td>
        </tr>`;
    }).join("");
}

function selectApp(identifier, name, pid) {
    selectedApp = identifier;
    renderApps(allApps);

    // Update scripting tab target
    document.getElementById("script-target").textContent = identifier;
    document.getElementById("script-pid").textContent = pid > 0 ? pid : "-";

    appendLog("info", `Selected: ${name} (${identifier})`);
}

function filterApps() {
    const q = document.getElementById("app-search").value.toLowerCase();
    if (!q) {
        renderApps(allApps);
        return;
    }
    const filtered = allApps.filter(a =>
        a.name.toLowerCase().includes(q) || a.identifier.toLowerCase().includes(q)
    );
    renderApps(filtered);
}

function startApp(pkg) {
    fetch(`/api/app/start/${selectedDevice}/${pkg}`, { method: "POST" })
        .then(r => r.json())
        .then(data => {
            appendLog(data.success ? "info" : "error", data.success ? `Started ${pkg}` : `Failed to start ${pkg}`);
            setTimeout(loadApps, 1500);
        });
}

function killApp(pkg) {
    fetch(`/api/app/kill/${selectedDevice}/${pkg}`, { method: "POST" })
        .then(r => r.json())
        .then(data => {
            appendLog(data.success ? "info" : "error", data.success ? `Killed ${pkg}` : `Failed to kill ${pkg}`);
            setTimeout(loadApps, 1000);
        });
}

// ─── File Browser ───────────────────────────────────────────
function browseAppFiles(pkg, path) {
    if (!selectedDevice) return;

    currentFilePackage = pkg || selectedApp;
    if (!currentFilePackage) {
        showToast("Select an app first", "error");
        return;
    }

    const url = path
        ? `/api/files/${selectedDevice}/${currentFilePackage}?path=${encodeURIComponent(path)}`
        : `/api/files/${selectedDevice}/${currentFilePackage}`;

    const tbody = document.getElementById("file-tbody");
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><span class="loading-spinner"></span> Loading...</td></tr>';

    fetch(url)
        .then(r => r.json())
        .then(data => {
            currentFilePath = data.path || `/data/data/${currentFilePackage}`;
            document.getElementById("file-current-path").textContent = currentFilePath;
            renderFiles(data.files || []);
        })
        .catch(() => {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Error loading files</td></tr>';
        });
}

function renderFiles(files) {
    const tbody = document.getElementById("file-tbody");

    if (!files.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Empty directory</td></tr>';
        return;
    }

    tbody.innerHTML = files.map(f => {
        const icon = f.type === "directory" ? "📁" : (f.type === "link" ? "🔗" : "📄");
        const onClick = f.type === "directory"
            ? `browseAppFiles('${currentFilePackage}', '${escapeAttr(f.path)}')`
            : `viewFile('${escapeAttr(f.path)}')`;

        return `
        <tr onclick="${onClick}">
            <td><span class="file-icon">${icon}</span>${escapeHtml(f.name)}</td>
            <td style="font-size:11px;color:var(--text-muted)">${f.type}</td>
            <td style="font-size:11px">${f.size || "-"}</td>
            <td style="font-family:'JetBrains Mono';font-size:10px;color:var(--text-muted)">${f.permissions || ""}</td>
            <td>
                ${f.type === "file" ? `<button class="btn btn-sm btn-ghost" onclick="event.stopPropagation(); downloadFile('${escapeAttr(f.path)}')">⬇ Download</button>` : ""}
            </td>
        </tr>`;
    }).join("");
}

function viewFile(filePath) {
    document.getElementById("viewer-filename").textContent = filePath.split("/").pop();
    document.getElementById("file-content").textContent = "Loading...";

    fetch(`/api/files/view/${selectedDevice}/${currentFilePackage}?path=${encodeURIComponent(filePath)}`)
        .then(r => r.json())
        .then(data => {
            if (data.content !== undefined) {
                document.getElementById("file-content").textContent = data.content;
            } else {
                document.getElementById("file-content").textContent = "Error: " + (data.error || "Cannot read file");
            }
        })
        .catch(() => {
            document.getElementById("file-content").textContent = "Error loading file";
        });
}

function downloadFile(filePath) {
    const url = `/api/files/download/${selectedDevice}/${currentFilePackage}?path=${encodeURIComponent(filePath)}`;
    window.open(url, "_blank");
    appendLog("info", "Download started: " + filePath.split("/").pop());
}

function fileGoUp() {
    if (!currentFilePath || currentFilePath === "/" || currentFilePath === `/data/data/${currentFilePackage}`) return;
    const parent = currentFilePath.substring(0, currentFilePath.lastIndexOf("/")) || "/";
    browseAppFiles(currentFilePackage, parent);
}

function refreshFiles() {
    if (currentFilePath) {
        browseAppFiles(currentFilePackage, currentFilePath);
    } else if (selectedApp) {
        browseAppFiles(selectedApp);
    }
}

// Auto-browse when switching to Files tab
document.querySelector('[data-tab="files"]').addEventListener("click", () => {
    if (selectedApp && !currentFilePackage) {
        browseAppFiles(selectedApp);
    }
});

// ─── Scripting ──────────────────────────────────────────────
function scriptSpawn() {
    if (!selectedDevice || !selectedApp) {
        showToast("Select device and app first", "error");
        return;
    }

    const code = document.getElementById("script-editor").value;
    const btn = document.getElementById("btn-spawn");
    btn.disabled = true;
    btn.innerHTML = '<span class="loading-spinner"></span> Spawning...';

    fetch("/api/script/spawn", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            device_id: selectedDevice,
            package_name: selectedApp,
            script: code
        })
    })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                appendScriptOutput("send", data.message);
                document.getElementById("script-pid").textContent = data.pid || "-";
                document.getElementById("btn-detach").disabled = false;
                showToast(data.message, "success");
            } else {
                appendScriptOutput("error", data.message);
                showToast(data.message, "error");
            }
            btn.disabled = false;
            btn.innerHTML = '🚀 Spawn';
        })
        .catch(e => {
            appendScriptOutput("error", e.message);
            btn.disabled = false;
            btn.innerHTML = '🚀 Spawn';
        });
}

function scriptAttach() {
    if (!selectedDevice || !selectedApp) {
        showToast("Select device and app first", "error");
        return;
    }

    const code = document.getElementById("script-editor").value;
    const btn = document.getElementById("btn-attach");
    btn.disabled = true;
    btn.innerHTML = '<span class="loading-spinner"></span> Attaching...';

    fetch("/api/script/attach", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            device_id: selectedDevice,
            package_name: selectedApp,
            script: code
        })
    })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                appendScriptOutput("send", data.message);
                document.getElementById("script-pid").textContent = data.pid || "-";
                document.getElementById("btn-detach").disabled = false;
                showToast(data.message, "success");
            } else {
                appendScriptOutput("error", data.message);
                showToast(data.message, "error");
            }
            btn.disabled = false;
            btn.innerHTML = '🔗 Attach (PID)';
        })
        .catch(e => {
            appendScriptOutput("error", e.message);
            btn.disabled = false;
            btn.innerHTML = '🔗 Attach (PID)';
        });
}

function scriptDetach() {
    fetch("/api/script/detach", { method: "POST" })
        .then(r => r.json())
        .then(data => {
            appendScriptOutput("detached", "Session detached");
            document.getElementById("btn-detach").disabled = true;
            document.getElementById("script-pid").textContent = "-";
        });
}

function appendScriptOutput(type, message) {
    const el = document.getElementById("script-output");
    const line = document.createElement("div");
    line.className = `output-line ${type}`;
    line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    el.appendChild(line);
    el.scrollTop = el.scrollHeight;
}

function clearScriptOutput() {
    document.getElementById("script-output").innerHTML = "";
}

// ─── Inspector ──────────────────────────────────────────────
function enumerateClasses() {
    if (!selectedDevice || !selectedApp) {
        showToast("Select device and app first", "error");
        return;
    }

    const filter = document.getElementById("class-filter").value;
    const btn = document.getElementById("btn-enum-classes");
    btn.disabled = true;
    btn.innerHTML = '<span class="loading-spinner"></span> Enumerating...';

    const classList = document.getElementById("class-list");
    classList.innerHTML = '<div class="empty-state"><span class="loading-spinner"></span> Enumerating classes...</div>';

    fetch(`/api/classes/${selectedDevice}/${selectedApp}?filter=${encodeURIComponent(filter)}`)
        .then(r => r.json())
        .then(data => {
            if (data.classes) {
                renderClasses(data.classes);
                document.getElementById("class-count").textContent = data.classes.length;
            } else {
                classList.innerHTML = `<div class="empty-state">${data.error || 'Error'}</div>`;
            }
            btn.disabled = false;
            btn.innerHTML = '🔍 Enumerate Classes';
        })
        .catch(e => {
            classList.innerHTML = '<div class="empty-state">Error enumerating classes</div>';
            btn.disabled = false;
            btn.innerHTML = '🔍 Enumerate Classes';
        });
}

function renderClasses(classes) {
    const container = document.getElementById("class-list");

    if (!classes.length) {
        container.innerHTML = '<div class="empty-state">No classes found</div>';
        return;
    }

    container.innerHTML = classes.map(c =>
        `<div class="class-item" onclick="selectClass('${escapeAttr(c)}')">${escapeHtml(c)}</div>`
    ).join("");
}

function selectClass(className) {
    selectedClassName = className;

    // Highlight
    document.querySelectorAll(".class-item").forEach(el => {
        el.classList.toggle("selected", el.textContent === className);
    });

    // Load methods
    const methodList = document.getElementById("method-list");
    methodList.innerHTML = '<div class="empty-state"><span class="loading-spinner"></span> Loading methods...</div>';

    fetch(`/api/methods/${selectedDevice}/${selectedApp}?class=${encodeURIComponent(className)}`)
        .then(r => r.json())
        .then(data => {
            if (data.methods) {
                renderMethods(data.methods);
                document.getElementById("method-count").textContent = data.methods.length;
            } else {
                methodList.innerHTML = `<div class="empty-state">${data.error || 'Error'}</div>`;
            }
        })
        .catch(() => {
            methodList.innerHTML = '<div class="empty-state">Error loading methods</div>';
        });
}

function renderMethods(methods) {
    const container = document.getElementById("method-list");

    if (!methods.length) {
        container.innerHTML = '<div class="empty-state">No methods found</div>';
        return;
    }

    container.innerHTML = methods.map((m, i) => {
        const staticTag = m.isStatic ? '<span class="method-static">STATIC</span>' : '';
        const methodData = encodeURIComponent(JSON.stringify(m));

        return `
        <div class="method-item">
            <span class="method-sig">${escapeHtml(m.signature || m.name)} ${staticTag}</span>
            <button class="method-hook-btn" onclick="generateHook('${escapeAttr(selectedClassName)}', '${methodData}')">🪝 Hook</button>
        </div>`;
    }).join("");
}

function generateHook(className, methodDataEncoded) {
    const methodInfo = JSON.parse(decodeURIComponent(methodDataEncoded));

    fetch("/api/hook/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            class_name: className,
            method_info: methodInfo
        })
    })
        .then(r => r.json())
        .then(data => {
            if (data.script) {
                document.getElementById("hook-script-code").textContent = data.script;
                document.getElementById("hook-modal").style.display = "flex";
            }
        })
        .catch(e => showToast("Error generating hook", "error"));
}

function closeHookModal() {
    document.getElementById("hook-modal").style.display = "none";
}

function copyHookScript() {
    const script = document.getElementById("hook-script-code").textContent;
    navigator.clipboard.writeText(script).then(() => {
        showToast("Script copied to clipboard!", "success");
    });
}

function useHookScript() {
    const script = document.getElementById("hook-script-code").textContent;
    document.getElementById("script-editor").value = script;
    closeHookModal();
    switchTab("scripting");
    showToast("Script loaded in editor", "success");
}

// Close modal on overlay click
document.getElementById("hook-modal").addEventListener("click", (e) => {
    if (e.target === document.getElementById("hook-modal")) {
        closeHookModal();
    }
});

// ─── Logging ────────────────────────────────────────────────
function appendLog(level, message) {
    const el = document.getElementById("log-output");
    const line = document.createElement("div");
    line.className = `log-line ${level}`;
    const ts = new Date().toLocaleTimeString();
    line.textContent = `[${ts}] [${level.toUpperCase()}] ${message}`;
    el.appendChild(line);
    el.scrollTop = el.scrollHeight;

    // Keep last 200 lines
    while (el.children.length > 200) {
        el.removeChild(el.firstChild);
    }
}

function clearLogs() {
    document.getElementById("log-output").innerHTML = "";
}

// ─── Toast ──────────────────────────────────────────────────
function showToast(message, type = "info") {
    const existing = document.querySelector(".toast");
    if (existing) existing.remove();

    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => toast.remove(), 4000);
}

// ─── Utility ────────────────────────────────────────────────
function escapeHtml(str) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(str).replace(/[&<>"']/g, c => map[c]);
}

function escapeAttr(str) {
    return String(str).replace(/'/g, "\\'").replace(/"/g, '&quot;');
}

// ─── Keyboard Shortcut (Tab in editor) ──────────────────────
document.getElementById("script-editor").addEventListener("keydown", (e) => {
    if (e.key === "Tab") {
        e.preventDefault();
        const ta = e.target;
        const start = ta.selectionStart;
        const end = ta.selectionEnd;
        ta.value = ta.value.substring(0, start) + "    " + ta.value.substring(end);
        ta.selectionStart = ta.selectionEnd = start + 4;
    }
});

// ─── Initial Load ───────────────────────────────────────────
refreshDevices();
