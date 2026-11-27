const state = { token: sessionStorage.getItem("token"), sesion: null };

const $ = (sel) => document.querySelector(sel);
const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(ruta, opciones = {}) {
  const res = await fetch(ruta, {
    ...opciones,
    headers: {
      "Content-Type": "application/json",
      ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}),
      ...(opciones.headers || {}),
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error || `Error ${res.status}`), { data, status: res.status });
  return data;
}

/* ---------------- login ---------------- */
$("#form-login").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#login-error");
  err.hidden = true;
  try {
    const data = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({ usuario: $("#usuario").value, password: $("#password").value }),
    });
    state.token = data.token;
    sessionStorage.setItem("token", data.token);
    await iniciar();
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
  }
});

$("#btn-salir").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST" }); } catch {}
  sessionStorage.removeItem("token");
  state.token = null;
  state.sesion = null;
  $("#app").hidden = true;
  $("#login").hidden = false;
  $("#password").value = "";
});

/* ---------------- arranque ---------------- */
async function iniciar() {
  try {
    state.sesion = await api("/api/sesion");
  } catch {
    sessionStorage.removeItem("token");
    state.token = null;
    return;
  }
  const s = state.sesion;
  $("#login").hidden = true;
  $("#app").hidden = false;
  $("#chip-usuario").textContent = `${s.nombre} · ${s.rol}`;
  $("#ctx-linea").textContent = `Consultando como ${s.principal} (usuario de la base) · ${s.unmask ? "con UNMASK" : "sin UNMASK"}`;
  pintarNav();
  ir("resumen");
}

function pintarNav() {
  const s = state.sesion;
  const items = [
    ["resumen", "Resumen"],
    ["clientes", "Clientes"],
    ["transacciones", "Transacciones"],
    ["empleados", "Empleados"],
    ["firma", "Firma digital"],
    ["cifrado", "Cifrado (TDE)"],
    ["columnas", "Cifrado columnas"],
  ];
  if (s.rol === "auditor" || s.rol === "dba") items.push(["auditoria", "Auditoría"]);
  if (s.rol === "dba") items.push(["administracion", "Administración"]);

  $("#nav").innerHTML = items
    .map(([id, label]) => `<button data-vista="${id}">${label}</button>`)
    .join("");
  $("#nav").querySelectorAll("button").forEach((b) =>
    b.addEventListener("click", () => ir(b.dataset.vista))
  );
}

function marcarNav(vista) {
  $("#nav").querySelectorAll("button").forEach((b) =>
    b.classList.toggle("activo", b.dataset.vista === vista)
  );
}

function ir(vista) {
  marcarNav(vista);
  if (vista === "resumen") return vistaResumen();
  if (vista === "auditoria") return vistaAuditoria();
  if (vista === "administracion") return vistaAdmin();
  if (vista === "firma") return vistaFirma();
  if (vista === "cifrado") return vistaCifrado();
  if (vista === "columnas") return vistaColumnas();
  return vistaTabla(vista);
}

/* ---------------- vistas ---------------- */
async function vistaResumen() {
  const s = state.sesion;
  const roles = (s.roles || []).map((r) => r.rol).join(", ") || "—";
  const permisos = (s.permisos || [])
    .map((p) => `<div><span>${esc(p.estado)} ${esc(p.permiso)} ${esc(p.objeto)}</span><span class="mono">${esc(p.objeto)}</span></div>`)
    .join("");

  $("#vista").innerHTML = `
    <div class="card">
      <h3>Contexto de ejecución</h3>
      <p class="muted">Todo lo que ves lo decide SQL Server, no la aplicación: la app solo suplanta al usuario de la base.</p>
      <div class="kv">
        <div><span>Usuario de la aplicación</span><span>${esc(s.usuario)}</span></div>
        <div><span>Nombre</span><span>${esc(s.nombre)}</span></div>
        <div><span>Rol funcional</span><span>${esc(s.rol)}</span></div>
        <div><span>Principal de base de datos</span><span class="mono">${esc(s.principal)}</span></div>
        <div><span>Roles de SQL Server</span><span>${esc(roles)}</span></div>
        <div><span>Permiso UNMASK</span>
          <span class="badge ${s.unmask ? "ok" : "no"}">${s.unmask ? "sí (ve datos reales)" : "no (ve datos enmascarados)"}</span></div>
      </div>
    </div>
    <div class="card">
      <h3>Permisos efectivos</h3>
      ${permisos ? `<div class="kv">${permisos}</div>` : `<p class="muted">Sin permisos explícitos; hereda los del rol.</p>`}
    </div>
    <div class="card">
      <h3>Cómo probarlo</h3>
      <p class="muted">Entra con <b>ana</b> y compara la tarjeta y el saldo; luego con <b>maria</b> (UNMASK) y con <b>sofia</b> (todo enmascarado, sin administración). Con <b>admin</b> puedes cambiar permisos y máscaras y ver el efecto al instante.</p>
    </div>`;
}

async function vistaTabla(tabla) {
  $("#vista").innerHTML = `<div class="card"><p class="muted">Consultando ${esc(tabla)}…</p></div>`;
  try {
    const data = await api(`/api/datos/${tabla}`);
    const filas = data.filas || [];
    if (!filas.length) {
      $("#vista").innerHTML = `<div class="card"><h3>${esc(data.tabla)}</h3><p class="muted">Sin filas visibles.</p></div>`;
      return;
    }
    const cols = Object.keys(filas[0]);
    const sensibles = new Set(["NumeroTarjeta", "SaldoCuenta", "Salario", "Email", "EmailCorporativo", "CI", "Telefono"]);

    const cuerpo = filas
      .map((f) => {
        const celdas = cols
          .map((c) => {
            const v = f[c];
            const txt = v === null ? "NULL" : String(v);
            const enmascarado =
              /XXXX|xxx@|\*\*\*\*/.test(txt) ||
              ((c === "SaldoCuenta" || c === "Salario") && Number(v) === 0);
            const clase = v === null ? "nulo" : enmascarado ? "mascara" : "";
            return `<td class="${clase}">${esc(txt)}</td>`;
          })
          .join("");
        return `<tr>${celdas}</tr>`;
      })
      .join("");

    $("#vista").innerHTML = `
      <div class="card">
        <div class="row" style="justify-content: space-between">
          <div>
            <h3>${esc(data.tabla)}</h3>
            <p class="muted">${filas.length} filas · consultado como <span class="mono">${esc(data.principal)}</span></p>
          </div>
          <span class="badge ok">SELECT permitido</span>
        </div>
        <div class="tabla-wrap" style="margin-top: 14px">
          <table class="datos">
            <thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead>
            <tbody>${cuerpo}</tbody>
          </table>
        </div>
        <p class="muted" style="margin-top: 10px">En ámbar, los valores que SQL Server entrega enmascarados a este usuario.</p>
      </div>`;
  } catch (ex) {
    const d = ex.data || {};
    $("#vista").innerHTML = `
      <div class="denegado">
        <h3>Acceso denegado por la base de datos</h3>
        <p class="muted">El motor rechazó la consulta del principal <span class="mono">${esc(d.principal || state.sesion.principal)}</span>.</p>
        <pre style="margin-top: 10px">${esc(d.error || ex.message)}</pre>
        <p class="muted" style="margin-top: 10px">Esto es el control funcionando: la aplicación no filtra nada, lo hace SQL Server.</p>
      </div>`;
  }
}

async function vistaAuditoria() {
  $("#vista").innerHTML = `<div class="card"><p class="muted">Leyendo el registro de auditoría…</p></div>`;
  try {
    const data = await api("/api/auditoria");
    const filas = data.filas || [];
    if (!filas.length) {
      $("#vista").innerHTML = `<div class="card"><h3>Auditoría</h3><p class="muted">Todavía no hay eventos registrados. Abre Clientes o Empleados con otro usuario y vuelve.</p></div>`;
      return;
    }
    const cols = Object.keys(filas[0]);
    $("#vista").innerHTML = `
      <div class="card">
        <h3>Registro de auditoría</h3>
        <p class="muted">Eventos de <span class="mono">SELECT</span> sobre las tablas sensibles, tomados de <span class="mono">sys.fn_get_audit_file</span>.</p>
        <div class="tabla-wrap" style="margin-top: 12px">
          <table class="datos">
            <thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead>
            <tbody>${filas
              .map((f) => `<tr>${cols.map((c) => `<td>${esc(f[c])}</td>`).join("")}</tr>`)
              .join("")}</tbody>
          </table>
        </div>
      </div>`;
  } catch (ex) {
    $("#vista").innerHTML = `<div class="denegado"><h3>No disponible</h3><pre>${esc(ex.message)}</pre></div>`;
  }
}

async function vistaAdmin() {
  $("#vista").innerHTML = `<div class="card"><p class="muted">Cargando estado de seguridad…</p></div>`;
  let d;
  try {
    d = await api("/api/admin/estado");
  } catch (ex) {
    $("#vista").innerHTML = `<div class="denegado"><h3>No disponible</h3><pre>${esc(ex.message)}</pre></div>`;
    return;
  }

  const opcionesPrincipal = d.usuarios.map((u) => `<option value="${esc(u.principal)}">${esc(u.principal)} (${esc(u.tipo)})</option>`).join("");
  const opcionesTabla = ["clientes", "transacciones", "empleados"]
    .map((t) => `<option value="${t}">${t}</option>`)
    .join("");

  $("#vista").innerHTML = `
    <div class="card">
      <h3>Máscaras activas</h3>
      <p class="muted">Leídas de <span class="mono">sys.masked_columns</span>. Al quitarlas, el usuario ve el dato real.</p>
      <div class="tabla-wrap" style="margin-top: 12px">
        <table class="datos">
          <thead><tr><th>Tabla</th><th>Columna</th><th>Función</th><th></th></tr></thead>
          <tbody>
            ${d.mascaras
              .map(
                (m) => `<tr>
                  <td>${esc(m.tabla)}</td><td>${esc(m.columna)}</td>
                  <td class="mono">${esc(m.funcion)}</td>
                  <td><button class="ghost mini" data-quitar="${esc(m.tabla)}|${esc(m.columna)}">Quitar</button></td>
                </tr>`
              )
              .join("")}
          </tbody>
        </table>
      </div>
      <div class="row" style="margin-top: 12px">
        <select id="m-tabla"><option value="Clientes">Clientes</option><option value="Empleados">Empleados</option></select>
        <select id="m-columna">
          ${["NumeroTarjeta", "Email", "Telefono", "SaldoCuenta", "CI"].map((c) => `<option>${c}</option>`).join("")}
        </select>
        <select id="m-funcion">
          <option value="default()">default()</option>
          <option value="email()">email()</option>
          <option value="partial(0,&quot;XXXX-XXXX-XXXX-&quot;,4)">partial tarjeta</option>
          <option value="partial(0,&quot;XXXX&quot;,4)">partial últimos 4</option>
          <option value="partial(2,&quot;XXXXXXX&quot;,0)">partial primeros 2</option>
          <option value="random(1, 9999)">random(1,9999)</option>
        </select>
        <button class="primary mini" id="m-aplicar">Aplicar máscara</button>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <h3>Permisos por principal</h3>
        <div class="row" style="margin-top: 10px">
          <select id="p-principal">${opcionesPrincipal}</select>
          <select id="p-tabla">${opcionesTabla}</select>
          <select id="p-permiso"><option>SELECT</option><option>INSERT</option><option>UPDATE</option><option>DELETE</option></select>
          <select id="p-accion"><option>GRANT</option><option>DENY</option><option>REVOKE</option></select>
          <button class="primary mini" id="p-aplicar">Ejecutar</button>
        </div>
        <div class="tabla-wrap" style="margin-top: 14px">
          <table class="datos">
            <thead><tr><th>Principal</th><th>Permiso</th><th>Estado</th><th>Objeto</th></tr></thead>
            <tbody>
              ${d.permisos
                .map(
                  (p) => `<tr><td>${esc(p.principal)}</td><td>${esc(p.permiso)}</td>
                  <td>${esc(p.estado)}</td><td class="mono">${esc(p.objeto)}</td></tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <h3>Usuarios de la aplicación</h3>
        <p class="muted">El principal de base decide qué puede hacer cada uno.</p>
        <div class="tabla-wrap" style="margin-top: 12px">
          <table class="datos">
            <thead><tr><th>Usuario</th><th>Principal BD</th><th>Rol</th><th>Activo</th><th></th></tr></thead>
            <tbody>
              ${d.appUsuarios
                .map(
                  (u) => `<tr>
                    <td>${esc(u.Usuario)}</td><td class="mono">${esc(u.PrincipalBD)}</td>
                    <td>${esc(u.Rol)}</td>
                    <td><span class="badge ${u.Activo ? "ok" : "no"}">${u.Activo ? "sí" : "no"}</span></td>
                    <td><button class="ghost mini" data-toggle="${esc(u.Usuario)}" data-activo="${u.Activo ? "1" : "0"}">
                      ${u.Activo ? "Desactivar" : "Activar"}</button></td>
                  </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>Roles y sus miembros</h3>
      <div class="tabla-wrap">
        <table class="datos">
          <thead><tr><th>Principal</th><th>Tipo</th><th>Rol</th></tr></thead>
          <tbody>
            ${d.usuarios
              .map((u) => `<tr><td>${esc(u.principal)}</td><td>${esc(u.tipo)}</td><td>${esc(u.rol)}</td></tr>`)
              .join("")}
          </tbody>
        </table>
      </div>
    </div>
    <p class="muted" id="admin-msg"></p>`;

  const msg = (t) => ($("#admin-msg").textContent = t);

  $("#m-aplicar").addEventListener("click", async () => {
    try {
      const r = await api("/api/admin/mascara", {
        method: "POST",
        body: JSON.stringify({ tabla: $("#m-tabla").value, columna: $("#m-columna").value, funcion: $("#m-funcion").value }),
      });
      msg(`Ejecutado: ${r.ejecutado}`);
      vistaAdmin();
    } catch (ex) { msg(ex.message); }
  });

  $("#vista").querySelectorAll("[data-quitar]").forEach((b) =>
    b.addEventListener("click", async () => {
      const [tabla, columna] = b.dataset.quitar.split("|");
      try {
        const r = await api("/api/admin/mascara", { method: "POST", body: JSON.stringify({ tabla, columna, funcion: "" }) });
        msg(`Ejecutado: ${r.ejecutado}`);
        vistaAdmin();
      } catch (ex) { msg(ex.message); }
    })
  );

  $("#p-aplicar").addEventListener("click", async () => {
    try {
      const r = await api("/api/admin/permiso", {
        method: "POST",
        body: JSON.stringify({
          accion: $("#p-accion").value,
          permiso: $("#p-permiso").value,
          tabla: $("#p-tabla").value,
          principal: $("#p-principal").value,
        }),
      });
      msg(`Ejecutado: ${r.ejecutado}`);
      vistaAdmin();
    } catch (ex) { msg(ex.message); }
  });

  $("#vista").querySelectorAll("[data-toggle]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        await api("/api/admin/usuario", {
          method: "POST",
          body: JSON.stringify({ usuario: b.dataset.toggle, activo: b.dataset.activo !== "1" }),
        });
        vistaAdmin();
      } catch (ex) { msg(ex.message); }
    })
  );
}

/* ---------------- firma digital ---------------- */
async function vistaFirma() {
  const esDba = state.sesion.rol === "dba";
  let d;
  try {
    d = await api("/api/firma");
  } catch (ex) {
    $("#vista").innerHTML = `<div class="denegado"><h3>No disponible</h3><pre>${esc(ex.message)}</pre></div>`;
    return;
  }

  const filas = d.filas || [];
  const cuerpo = filas
    .map((f) => {
      const ok = Number(f.FirmaValida) === 1;
      const intacto = f.Integridad === "INTACTO";
      return `<tr>
        <td>${esc(f.DocID)}</td>
        <td class="mono">${esc(String(f.Referencia).slice(0, 8))}…</td>
        <td>${esc(f.ClienteID)}</td>
        <td>${esc(f.Monto)}</td>
        <td>${esc(f.Tipo)}</td>
        <td>${esc(f.fecha_firma)}</td>
        <td><span class="badge ${ok ? "ok" : "no"}">${ok ? "válida" : "inválida"}</span></td>
        <td><span class="badge ${intacto ? "ok" : "no"}">${esc(f.Integridad)}</span></td>
        ${esDba ? `<td class="row">
          <button class="ghost mini" data-alterar="${esc(f.DocID)}">Alterar</button>
          <button class="ghost mini" data-restaurar="${esc(f.DocID)}">Restaurar</button></td>` : ""}
      </tr>`;
    })
    .join("");

  $("#vista").innerHTML = `
    <div class="card">
      <h3>Firma una transacción</h3>
      <p class="muted">La base arma el XML, calcula el SHA-256 y lo firma con la clave privada del certificado. Nada se firma en la aplicación.</p>
      <div class="row" style="margin-top: 12px">
        <select id="f-cliente">
          <option value="1">Cliente 1</option><option value="2">Cliente 2</option>
          <option value="3">Cliente 3</option><option value="4">Cliente 4</option>
          <option value="5">Cliente 5</option>
        </select>
        <select id="f-tipo">
          <option>Transferencia</option><option>Deposito</option>
          <option>Retiro</option><option>Pago servicio</option>
        </select>
        <input id="f-monto" type="number" step="0.01" min="1" value="2500.00" style="max-width:150px" />
        <button class="primary mini" id="f-firmar">Firmar y guardar</button>
      </div>
      <p class="muted" id="f-msg" style="margin-top: 8px"></p>
    </div>

    <div class="card">
      <div class="row" style="justify-content: space-between">
        <div>
          <h3>Documentos firmados</h3>
          <p class="muted">Firma verificada con <span class="mono">VerifySignedByCert</span> e integridad comparando el hash del contenido actual.</p>
        </div>
        <span class="badge ok">${filas.length} documentos</span>
      </div>
      <div class="tabla-wrap" style="margin-top: 12px">
        <table class="datos">
          <thead><tr><th>Doc</th><th>Referencia</th><th>Cliente</th><th>Monto</th><th>Tipo</th><th>Fecha firma</th><th>Firma</th><th>Integridad</th>${esDba ? "<th>Demostración</th>" : ""}</tr></thead>
          <tbody>${cuerpo || `<tr><td colspan="9" class="nulo">Todavía no hay documentos firmados.</td></tr>`}</tbody>
        </table>
      </div>
      ${esDba ? `<p class="muted" style="margin-top:10px">Con <b>Alterar</b> se cambia el monto dentro del XML: la firma sigue siendo criptográficamente válida (nadie tocó el hash firmado), pero la integridad pasa a ALTERADO. Por eso se verifican las dos cosas.</p>` : ""}
    </div>`;

  const msg = (t) => ($("#f-msg").textContent = t);

  $("#f-firmar").addEventListener("click", async () => {
    try {
      const r = await api("/api/firma/firmar", {
        method: "POST",
        body: JSON.stringify({
          clienteId: Number($("#f-cliente").value),
          monto: Number($("#f-monto").value),
          tipo: $("#f-tipo").value,
        }),
      });
      msg(`Documento ${r.docId} firmado.`);
      vistaFirma();
    } catch (ex) { msg(ex.message); }
  });

  document.querySelectorAll("[data-alterar]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        await api("/api/firma/alterar", { method: "POST", body: JSON.stringify({ docId: Number(b.dataset.alterar) }) });
        vistaFirma();
      } catch (ex) { msg(ex.message); }
    })
  );

  document.querySelectorAll("[data-restaurar]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        await api("/api/firma/restaurar", { method: "POST", body: JSON.stringify({ docId: Number(b.dataset.restaurar) }) });
        vistaFirma();
      } catch (ex) { msg(ex.message); }
    })
  );
}

/* ---------------- cifrado ---------------- */
async function vistaCifrado() {
  let d;
  try {
    d = await api("/api/cifrado");
  } catch (ex) {
    $("#vista").innerHTML = `<div class="denegado"><h3>No disponible</h3><pre>${esc(ex.message)}</pre></div>`;
    return;
  }

  const tde = d.tde || {};
  const cert = d.certTde || {};
  const firma = d.certFirma || {};
  const cifrado = /ENCRYPTED/.test(String(tde.estado || ""));
  const esDba = d.rol === "dba";

  $("#vista").innerHTML = `
    <div class="card">
      <div class="row" style="justify-content: space-between">
        <div>
          <h3>Transparent Data Encryption</h3>
          <p class="muted">Cifra los archivos .mdf, .ndf, .ldf y los backups. La aplicación no cambia nada.</p>
        </div>
        <span class="badge ${cifrado ? "ok" : "no"}">${esc(tde.estado || "sin datos")}</span>
      </div>
      <div class="kv">
        <div><span>Algoritmo</span><span>${esc(tde.algoritmo || "—")} · ${esc(tde.longitud || "—")} bits</span></div>
        <div><span>Avance del cifrado</span><span>${tde.estado === "ENCRYPTED" ? "100" : esc(tde.avance ?? "—")} %</span></div>
        <div><span>Certificado del servidor</span><span class="mono">${esc(cert.name || "—")}</span></div>
        <div><span>Clave privada</span><span>${esc(cert.clave_privada || "—")}</span></div>
        <div><span>Vence</span><span>${esc(cert.vence || "—")}</span></div>
      </div>
      <div class="row" style="margin-top: 14px">
        ${esDba ? `<button class="primary mini" id="c-backup">Respaldar certificado (.cer + .pvk)</button>` : `<span class="muted">Solo administración puede respaldar el certificado.</span>`}
      </div>
      <p class="muted" id="c-msg" style="margin-top: 8px"></p>
    </div>

    <div class="grid-2">
      <div class="card">
        <h3>Certificado de firma</h3>
        <div class="kv">
          <div><span>Nombre</span><span class="mono">${esc(firma.name || "—")}</span></div>
          <div><span>Asunto</span><span>${esc(firma.subject || "—")}</span></div>
          <div><span>Vence</span><span>${esc(firma.vence || "—")}</span></div>
          <div><span>Documentos firmados</span><span>${esc(d.firmados)}</span></div>
        </div>
      </div>
      <div class="card">
        <h3>Qué protege cada capa</h3>
        <div class="kv">
          <div><span>TDE</span><span>robo de disco o de backup</span></div>
          <div><span>DDM</span><span>que un usuario vea datos en pantalla</span></div>
          <div><span>Firma digital</span><span>alteración y repudio del documento</span></div>
          <div><span>Auditoría</span><span>que nadie borre huellas</span></div>
        </div>
        <p class="muted" style="margin-top: 10px">TDE no protege de un DBA que ya está dentro de la instancia: para ese caso están el cifrado por columna y Always Encrypted.</p>
      </div>
    </div>`;

  const btn = $("#c-backup");
  if (btn)
    btn.addEventListener("click", async () => {
      try {
        const r = await api("/api/cifrado/backup-certificado", { method: "POST" });
        $("#c-msg").textContent = "Respaldado en: " + r.archivos.join("  ·  ");
      } catch (ex) {
        $("#c-msg").textContent = ex.message;
      }
    });
}

/* ---------------- cifrado por columna ---------------- */
async function vistaColumnas() {
  let d;
  try {
    d = await api("/api/columnas");
  } catch (ex) {
    $("#vista").innerHTML = `<div class="denegado"><h3>No disponible</h3><pre>${esc(ex.message)}</pre></div>`;
    return;
  }

  const filas = d.filas || [];
  const cuerpo = filas
    .map(
      (f) => `<tr>
        <td>${esc(f.TarjetaID)}</td>
        <td>${esc(f.ClienteID)}</td>
        <td class="mono">•••• ${esc(f.Ultimos4)}</td>
        <td>${esc(f.bytes_numero)} bytes</td>
        <td>${esc(f.bytes_cvv)} bytes</td>
        <td>${esc(f.alta)}</td>
        <td><button class="ghost mini" data-descifrar="${esc(f.TarjetaID)}">Descifrar</button></td>
      </tr>`
    )
    .join("");

  $("#vista").innerHTML = `
    <div class="card">
      <h3>Tarjeta y CVV cifrados con clave simétrica</h3>
      <p class="muted">El valor se guarda cifrado con AES-256 (<span class="mono">EncryptByKey</span>). Tener SELECT sobre la tabla no alcanza: para leerlo hay que poder abrir la clave.</p>
      <div class="row" style="margin-top: 12px">
        <select id="k-cliente">
          <option value="1">Cliente 1</option><option value="2">Cliente 2</option>
          <option value="3">Cliente 3</option><option value="4">Cliente 4</option>
          <option value="5">Cliente 5</option>
        </select>
        <input id="k-numero" placeholder="4532-1122-3344-5566" style="max-width: 220px" />
        <input id="k-cvv" placeholder="123" style="max-width: 90px" />
        <button class="primary mini" id="k-guardar">Guardar cifrada</button>
      </div>
      <p class="muted" id="k-msg" style="margin-top: 8px"></p>
    </div>

    <div class="card">
      <div class="row" style="justify-content: space-between">
        <div>
          <h3>Tarjetas almacenadas</h3>
          <p class="muted">Consultado como <span class="mono">${esc(d.principal)}</span>. Solo se ve el binario cifrado y los últimos 4 como referencia.</p>
        </div>
        <span class="badge ok">${filas.length} registros</span>
      </div>
      <div class="tabla-wrap" style="margin-top: 12px">
        <table class="datos">
          <thead><tr><th>ID</th><th>Cliente</th><th>Tarjeta</th><th>Número cifrado</th><th>CVV cifrado</th><th>Alta</th><th>Prueba</th></tr></thead>
          <tbody>${cuerpo || `<tr><td colspan="7" class="nulo">Sin registros.</td></tr>`}</tbody>
        </table>
      </div>
    </div>

    <div id="k-resultado"></div>`;

  const msg = (t) => ($("#k-msg").textContent = t);

  $("#k-guardar").addEventListener("click", async () => {
    try {
      const r = await api("/api/columnas/guardar", {
        method: "POST",
        body: JSON.stringify({
          clienteId: Number($("#k-cliente").value),
          numero: $("#k-numero").value,
          cvv: $("#k-cvv").value,
        }),
      });
      msg(`Tarjeta ${r.tarjetaId} guardada cifrada.`);
      vistaColumnas();
    } catch (ex) { msg(ex.message); }
  });

  document.querySelectorAll("[data-descifrar]").forEach((b) =>
    b.addEventListener("click", async () => {
      const id = Number(b.dataset.descifrar);
      const caja = $("#k-resultado");
      try {
        const r = await api("/api/columnas/descifrar", { method: "POST", body: JSON.stringify({ tarjetaId: id }) });
        caja.innerHTML = `<div class="card">
          <h3>Descifrado correcto (tarjeta ${id})</h3>
          <p class="muted">Obtenido como <span class="mono">${esc(r.como)}</span> · ${esc(r.principal)}</p>
          <div class="kv" style="margin-top:10px">
            <div><span>Número</span><span class="mono">${esc(r.numero)}</span></div>
            <div><span>CVV</span><span class="mono">${esc(r.cvv)}</span></div>
          </div>
          ${r.aviso ? `<p class="muted" style="margin-top:10px">Como ${esc(r.principal)} la base rechazó abrir la clave: ${esc(r.aviso)}</p>` : ""}
        </div>`;
      } catch (ex) {
        const e = ex.data || {};
        caja.innerHTML = `<div class="denegado">
          <h3>No puede descifrar</h3>
          <p class="muted">El motor rechazó abrir la clave para <span class="mono">${esc(e.principal || state.sesion.principal)}</span>. El registro sigue visible, pero el dato no.</p>
          <pre style="margin-top:10px">${esc(e.error || ex.message)}</pre>
        </div>`;
      }
    })
  );
}

/* ---------------- inicio ---------------- */
if (state.token) iniciar();
