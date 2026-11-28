const state = { sesion: null };
let avisoAdmin = "";

const $ = (sel) => document.querySelector(sel);
const movimientoReducido = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(ruta, opciones = {}) {
  const res = await fetch(ruta, {
    ...opciones,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
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
    await api("/api/login", {
      method: "POST",
      body: JSON.stringify({ usuario: $("#usuario").value, password: $("#password").value }),
    });
    await iniciar();
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
  }
});

$("#btn-salir").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST" }); } catch {}
  state.sesion = null;
  avisoAdmin = "";
  $("#app").hidden = true;
  $("#login").hidden = false;
  $("#password").value = "";
});

/* ---------------- arranque ---------------- */
async function iniciar() {
  try {
    state.sesion = await api("/api/sesion");
  } catch {
    state.sesion = null;
    return;
  }
  const s = state.sesion;
  $("#login").hidden = true;
  $("#app").hidden = false;
  $("#chip-usuario").textContent = `${s.nombre} · ${s.rol}`;
  $("#chip-usuario").title = `${s.nombre} · ${s.rol} · principal ${s.principal}`;
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
  if (s.rol !== "dba") items.push(["inferencia", "Inferencia DDM"]);
  if (s.rol === "cajero" || s.rol === "riesgos" || s.rol === "dba") items.push(["ae", "Always Encrypted"]);
  if (s.rol === "auditor" || s.rol === "dba") items.push(["metadatos", "Metadatos y ACL"]);
  if (s.rol === "auditor" || s.rol === "dba") items.push(["auditoria", "Auditoría"]);
  if (s.rol === "dba") items.push(["sqli", "SQL injection"], ["administracion", "Administración"]);

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
  const nav = $("#nav");
  const activo = nav.querySelector("button.activo");
  if (activo && nav.scrollWidth > nav.clientWidth)
    activo.scrollIntoView({ block: "nearest", inline: "center" });
}

function ir(vista) {
  if (vista !== "administracion") avisoAdmin = "";
  marcarNav(vista);
  if (vista === "resumen") return vistaResumen();
  if (vista === "auditoria") return vistaAuditoria();
  if (vista === "metadatos") return vistaMetadatos();
  if (vista === "administracion") return vistaAdmin();
  if (vista === "firma") return vistaFirma();
  if (vista === "cifrado") return vistaCifrado();
  if (vista === "columnas") return vistaColumnas();
  if (vista === "ae") return vistaAe();
  if (vista === "inferencia") return vistaInferencia();
  if (vista === "sqli") return vistaSqli();
  return vistaTabla(vista);
}

/* ---------------- vistas ---------------- */
async function vistaResumen() {
  const s = state.sesion;
  const roles = (s.roles || []).map((r) => r.rol).join(", ") || "—";
  const permisos = (s.permisos || [])
    .map((p) => `<div><span>${esc(p.permiso)}</span><span class="mono">${esc(p.objeto)}</span></div>`)
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
      ${permisos
        ? `<p class="muted">${s.permisos.length} concesiones reconocidas por el motor para <span class="mono">${esc(s.principal)}</span>.</p>
           <details class="permisos"><summary>Ver el detalle</summary><div class="kv">${permisos}</div></details>`
        : `<p class="muted">Sin permisos explícitos; hereda los del rol.</p>`}
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
    const ocultas = data.columnas_ocultas || [];
    const sensibles = new Set(["NumeroTarjeta", "SaldoCuenta", "Salario", "Email", "EmailCorporativo", "CI", "Telefono"]);

    const cuerpo = filas
      .map((f) => {
        const celdas = cols
          .map((c) => {
            const v = f[c];
            const txt = v === null ? "NULL" : String(v);
            const enmascarado =
              /XXXX|xxx@|\*\*\*\*\*/.test(txt) ||
              ((c === "SaldoCuenta" || c === "Salario") && Number(v) === 0);
            const clase = v === null ? "nulo" : enmascarado ? "mascara" : typeof v === "number" ? "num" : "";
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
          <span class="badge ok">${ocultas.length ? "SELECT por columna" : "SELECT permitido"}</span>
        </div>
        <div class="tabla-wrap" style="margin-top: 14px">
          <table class="datos">
            <thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead>
            <tbody>${cuerpo}</tbody>
          </table>
        </div>
        <p class="muted" style="margin-top: 10px">En ámbar, los valores que SQL Server entrega enmascarados a este usuario.</p>
        ${ocultas.length
          ? `<p class="columnas-ocultas">Columnas denegadas por el motor: <span class="mono">${ocultas.map(esc).join(", ")}</span>. Un <span class="mono">SELECT</span> que las incluya se rechaza con el error 230.</p>`
          : ""}
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
              .map((f) => `<tr>${cols.map((c) => c === "succeeded"
                ? `<td><span class="badge ${Number(f[c]) ? "ok" : "no"}">${Number(f[c]) ? "permitido" : "denegado"}</span></td>`
                : `<td>${esc(f[c])}</td>`).join("")}</tr>`)
              .join("")}</tbody>
          </table>
        </div>
      </div>`;
  } catch (ex) {
    $("#vista").innerHTML = `<div class="denegado"><h3>No disponible</h3><pre>${esc(ex.message)}</pre></div>`;
  }
}

/* ---------------- metadatos y ACL (auditor) ---------------- */
async function vistaMetadatos() {
  $("#vista").innerHTML = `<div class="card"><p class="muted">Leyendo el catálogo en el contexto del auditor…</p></div>`;
  let d;
  try {
    d = await api("/api/metadatos");
  } catch (ex) {
    $("#vista").innerHTML = `<div class="denegado"><h3>Sin acceso a metadatos</h3><pre>${esc(ex.message)}</pre></div>`;
    return;
  }

  const mascaras = d.mascaras || [];
  const permisos = d.permisos || [];
  const columnas = d.columnas || [];
  const roles = d.roles || [];

  $("#vista").innerHTML = `
    <div class="card">
      <div class="row" style="justify-content: space-between">
        <div>
          <h3>Metadatos del modelo</h3>
          <p class="muted">Leído del catálogo como <span class="mono">${esc(d.principal)}</span>. El auditor necesita ver la ACL para auditarla, no los datos.</p>
        </div>
        <span class="badge ${d.view_definition ? "ok" : "no"}">VIEW DEFINITION ${d.view_definition ? "sí" : "no"}</span>
      </div>
      <div class="kv" style="margin-top: 10px">
        <div><span>VIEW DEFINITION</span><span>${d.view_definition ? "concedido por el motor" : "no concedido"}</span></div>
        <div><span>CONTROL de la base</span><span>${d.control ? "sí" : "no"}</span></div>
        <div><span>Máscaras visibles</span><span>${mascaras.length}</span></div>
        <div><span>Permisos visibles</span><span>${permisos.length}</span></div>
        <div><span>Columnas inventariadas</span><span>${columnas.length}</span></div>
      </div>
      <p class="muted" style="margin-top: 10px">Con VIEW DEFINITION el auditor lee la ACL completa; sin CONTROL no puede cambiarla, y sin UNMASK sigue viendo los datos enmascarados.</p>
    </div>

    <div class="card">
      <h3>Máscaras dinámicas</h3>
      <p class="muted">Salida de <span class="mono">sys.masked_columns</span> en el contexto del auditor.</p>
      <div class="tabla-wrap" style="margin-top: 12px">
        <table class="datos apilada">
          <thead><tr><th>Tabla</th><th>Columna</th><th>Función</th></tr></thead>
          <tbody>${mascaras.map((m) => `<tr>
            <td data-col="Tabla">${esc(m.tabla)}</td>
            <td data-col="Columna">${esc(m.columna)}</td>
            <td data-col="Función" class="mono">${esc(m.funcion)}</td>
          </tr>`).join("") || `<tr><td colspan="3" class="nulo">Sin máscaras.</td></tr>`}</tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h3>ACL por principal</h3>
      <p class="muted">GRANT, DENY y REVOKE tal como los registra el motor, incluidas las columnas denegadas.</p>
      <div class="tabla-wrap alta" style="margin-top: 12px">
        <table class="datos apilada">
          <thead><tr><th>Principal</th><th>Permiso</th><th>Estado</th><th>Ámbito</th><th>Objeto / columna</th></tr></thead>
          <tbody>${permisos.map((p) => `<tr>
            <td data-col="Principal">${esc(p.principal)}</td>
            <td data-col="Permiso">${esc(p.permiso)}</td>
            <td data-col="Estado"><span class="badge ${p.estado === "GRANT" ? "ok" : "no"}">${esc(p.estado)}</span></td>
            <td data-col="Ámbito">${esc(p.ambito)}</td>
            <td data-col="Objeto / columna" class="mono">${esc(p.objeto)}${p.columna ? "." + esc(p.columna) : ""}</td>
          </tr>`).join("") || `<tr><td colspan="5" class="nulo">Sin permisos visibles.</td></tr>`}</tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h3>Columnas y cifrado</h3>
      <p class="muted">Inventario de las tablas del modelo, con el tipo de cifrado de Always Encrypted cuando corresponde.</p>
      <div class="tabla-wrap alta" style="margin-top: 12px">
        <table class="datos apilada">
          <thead><tr><th>Tabla</th><th>Columna</th><th>Tipo</th><th>Bytes</th><th>Nulo</th><th>Cifrado</th></tr></thead>
          <tbody>${columnas.map((c) => `<tr>
            <td data-col="Tabla">${esc(c.tabla)}</td>
            <td data-col="Columna" class="mono">${esc(c.columna)}</td>
            <td data-col="Tipo">${esc(c.tipo)}</td>
            <td data-col="Bytes" class="num">${esc(c.bytes)}</td>
            <td data-col="Nulo">${c.nulo ? "sí" : "no"}</td>
            <td data-col="Cifrado">${c.cifrado ? `<span class="badge ok">${esc(c.cifrado)}</span>` : "—"}</td>
          </tr>`).join("") || `<tr><td colspan="6" class="nulo">Sin columnas visibles.</td></tr>`}</tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h3>Roles y miembros</h3>
      <div class="tabla-wrap">
        <table class="datos apilada">
          <thead><tr><th>Rol</th><th>Miembro</th></tr></thead>
          <tbody>${roles.map((r) => `<tr><td data-col="Rol">${esc(r.rol)}</td><td data-col="Miembro" class="mono">${esc(r.miembro)}</td></tr>`).join("") || `<tr><td colspan="2" class="nulo">Sin roles.</td></tr>`}</tbody>
        </table>
      </div>
    </div>`;
}

/* ---------------- Always Encrypted ---------------- */
async function vistaAe() {
  $("#vista").innerHTML = `<div class="card"><p class="muted">Consultando claves y datos cifrados…</p></div>`;

  let d;
  try {
    d = await api("/api/ae/estado");
  } catch (ex) {
    d = { ...(ex.data || {}), denegado: true, error: ex.message };
  }

  const cmk = d.cmk || [];
  const cek = d.cek || [];
  const columnas = d.columnas || [];

  const cabecera = `
    <div class="card">
      <div class="row" style="justify-content: space-between">
        <div>
          <h3>Always Encrypted</h3>
          <p class="muted">El motor guarda el dato cifrado. La clave de cifrado de columna (CEK) se abre con la clave maestra (CMK), que vive en el almacén del cliente y nunca llega a SQL Server.</p>
        </div>
        <span class="badge ${d.disponible ? "ok" : "no"}">${d.disponible ? "configurado" : "sin configurar"}</span>
      </div>
      <div class="kv" style="margin-top: 10px">
        ${cmk.map((k) => `<div><span>CMK</span><span class="mono">${esc(k.name)} · ${esc(k.proveedor)}</span></div>
          <div><span>Ruta de la CMK</span><span class="mono">${esc(k.ruta)}</span></div>`).join("")}
        ${cek.map((k) => `<div><span>CEK</span><span class="mono">${esc(k.nombre || k.name)} · ${esc(k.algoritmo)} · ${esc(k.bytes_cifrados)} bytes</span></div>`).join("")}
      </div>
      ${d.motivo ? `<p class="limite" style="margin-top:10px">${esc(d.motivo)}</p>` : ""}
    </div>`;

  const columnasHtml = columnas.length
    ? `<div class="card">
        <h3>Columnas cifradas</h3>
        <div class="tabla-wrap" style="margin-top: 12px">
          <table class="datos apilada">
            <thead><tr><th>Columna</th><th>Tipo de cifrado</th><th>Algoritmo</th><th>Collation</th></tr></thead>
            <tbody>${columnas.map((c) => `<tr>
              <td data-col="Columna" class="mono">${esc(c.columna)}</td>
              <td data-col="Tipo de cifrado"><span class="badge ok">${esc(c.tipo)}</span></td>
              <td data-col="Algoritmo">${esc(c.algoritmo)}</td>
              <td data-col="Collation" class="mono">${esc(c.collation)}</td>
            </tr>`).join("")}</tbody>
          </table>
        </div>
        <p class="muted" style="margin-top:10px"><span class="mono">CI</span> es determinista: permite igualdad exacta. Nombre, saldo y tarjeta son aleatorios: no se pueden filtrar, ordenar ni agrupar.</p>
      </div>`
    : "";

  if (!d.disponible || d.denegado) {
    $("#vista").innerHTML = `
      ${cabecera}
      ${columnasHtml}
      <div class="denegado">
        <h3>${d.denegado ? "El motor negó la lectura" : "Sin claves configuradas"}</h3>
        <p class="muted">${esc(d.error || d.motivo || "")}</p>
        <p class="muted" style="margin-top:10px">Una tabla con Always Encrypted sigue protegida aunque el rol pida la fila: sin la CMK no hay texto claro.</p>
      </div>`;
    return;
  }

  const recorta = (v) => {
    if (v === null || v === undefined) return "NULL";
    const s = String(v);
    if (/^[A-Za-z0-9+/=]{40,}$/.test(s)) return `${s.slice(0, 44)}… (${s.length} car.)`;
    return s;
  };

  const tablaFilas = (filas, titulo, nota) => {
    if (!filas || !filas.length) return "";
    const cols = Object.keys(filas[0]);
    return `<div class="card">
      <h3>${titulo}</h3>
      <p class="muted">${nota}</p>
      <div class="tabla-wrap" style="margin-top: 12px">
        <table class="datos">
          <thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead>
          <tbody>${filas.map((f) => `<tr>${cols.map((c) => {
            const v = f[c];
            const binario = typeof v === "string" && /^[A-Za-z0-9+/=]{40,}$/.test(v);
            return `<td class="${binario ? "mascara mono" : typeof v === "number" ? "num" : ""}">${esc(recorta(v))}</td>`;
          }).join("")}</tr>`).join("")}</tbody>
        </table>
      </div>
    </div>`;
  };

  $("#vista").innerHTML = `
    ${cabecera}
    ${columnasHtml}
    <div class="grid-2">
      ${tablaFilas(d.cifrada, "Sin Always Encrypted en el cliente",
        "Misma cuenta, mismo SELECT, con la conexión sin descifrado: el driver entrega el binario. Es lo que ve el motor, un backup o un DBA.")}
      ${tablaFilas(d.descifrada, "Con Always Encrypted en el cliente",
        "La conexión pide las claves y el driver descifra en memoria: el texto claro nunca estuvo en el servidor.")}
    </div>

    <div class="card">
      <h3>Guardar un cliente cifrado</h3>
      <p class="muted">El INSERT viaja con los parámetros ya cifrados por el driver.</p>
      <div class="fichas">
        <div class="campo"><label for="ae-ci">CI</label><input id="ae-ci" placeholder="1122334" maxlength="9" /></div>
        <div class="campo"><label for="ae-nombre">Nombre</label><input id="ae-nombre" placeholder="Cliente Always Encrypted" /></div>
        <div class="campo"><label for="ae-saldo">Saldo</label><input id="ae-saldo" type="number" step="0.01" min="0" value="1000" /></div>
        <div class="campo"><label for="ae-tarjeta">Tarjeta</label><input id="ae-tarjeta" placeholder="4532-0000-0000-9999" /></div>
        <div class="campo"><button class="primary mini" id="ae-guardar">Guardar cifrado</button></div>
      </div>
      <p class="muted" id="ae-msg" style="margin-top: 8px"></p>
    </div>

    <div class="card">
      <h3>Buscar por CI</h3>
      <p class="muted">Solo funciona con una columna determinista: el motor compara los binarios cifrados, sin descifrarlos.</p>
      <div class="fichas">
        <div class="campo"><label for="ae-buscar-ci">CI exacta</label><input id="ae-buscar-ci" placeholder="8765432" maxlength="9" /></div>
        <div class="campo"><button class="ghost mini" id="ae-buscar">Buscar</button></div>
      </div>
      <div id="ae-resultado"></div>
    </div>`;

  $("#ae-guardar").addEventListener("click", async () => {
    const msg = $("#ae-msg");
    try {
      const r = await api("/api/ae/guardar", {
        method: "POST",
        body: JSON.stringify({
          ci: $("#ae-ci").value,
          nombre: $("#ae-nombre").value,
          saldo: Number($("#ae-saldo").value),
          tarjeta: $("#ae-tarjeta").value,
        }),
      });
      msg.textContent = `Cliente ${r.clienteId} guardado cifrado.`;
      vistaAe();
    } catch (ex) {
      msg.textContent = ex.message;
    }
  });

  $("#ae-buscar").addEventListener("click", async () => {
    const caja = $("#ae-resultado");
    try {
      const r = await api(`/api/ae/buscar?ci=${encodeURIComponent($("#ae-buscar-ci").value)}`);
      caja.innerHTML = r.filas.length
        ? `<div class="aviso">${r.filas.length} coincidencia(s) para CI ${esc(r.ci)}: ${r.filas.map((f) => `${esc(f.Nombre)} (saldo ${esc(f.SaldoCuenta)})`).join(" · ")}</div>`
        : `<div class="aviso">Sin coincidencias para CI ${esc(r.ci)}.</div>`;
    } catch (ex) {
      caja.innerHTML = `<div class="denegado"><pre>${esc(ex.message)}</pre></div>`;
    }
  });
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

  const opcionesPrincipal = d.usuarios.map((u) => `<option value="${esc(u.principal)}">${esc(u.principal)}</option>`).join("");
  const opcionesTabla = ["clientes", "transacciones", "empleados"]
    .map((t) => `<option value="${t}">${t}</option>`)
    .join("");

  $("#vista").innerHTML = `
    ${avisoAdmin ? `<div class="aviso">${esc(avisoAdmin)}</div>` : ""}
    <div class="card">
      <h3>Máscaras activas</h3>
      <p class="muted">Leídas de <span class="mono">sys.masked_columns</span>. Al quitarlas, el usuario ve el dato real.</p>
      <div class="tabla-wrap" style="margin-top: 12px">
        <table class="datos apilada">
          <thead><tr><th>Tabla</th><th>Columna</th><th>Función</th><th class="acciones"></th></tr></thead>
          <tbody>
            ${d.mascaras
              .map(
                (m) => `<tr>
                  <td data-col="Tabla">${esc(m.tabla)}</td>
                  <td data-col="Columna">${esc(m.columna)}</td>
                  <td data-col="Función" class="mono">${esc(m.funcion)}</td>
                  <td class="acciones"><button class="ghost mini" data-quitar="${esc(m.tabla)}|${esc(m.columna)}">Quitar</button></td>
                </tr>`
              )
              .join("")}
          </tbody>
        </table>
      </div>
      <div class="fichas">
        <div class="campo">
          <label for="m-tabla">Tabla</label>
          <select id="m-tabla"><option value="Clientes">Clientes</option><option value="Empleados">Empleados</option></select>
        </div>
        <div class="campo">
          <label for="m-columna">Columna</label>
          <select id="m-columna">
            ${["NumeroTarjeta", "Email", "Telefono", "SaldoCuenta", "CI"].map((c) => `<option>${c}</option>`).join("")}
          </select>
        </div>
        <div class="campo">
          <label for="m-funcion">Función</label>
          <select id="m-funcion">
            <option value="default()">default()</option>
            <option value="email()">email()</option>
            <option value="partial(0,&quot;XXXX-XXXX-XXXX-&quot;,4)">partial tarjeta</option>
            <option value="partial(0,&quot;XXXX&quot;,4)">partial últimos 4</option>
            <option value="partial(2,&quot;XXXXXXX&quot;,0)">partial primeros 2</option>
            <option value="random(1, 9999)">random(1,9999)</option>
          </select>
        </div>
        <div class="campo">
          <button class="primary mini" id="m-aplicar">Aplicar máscara</button>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>Permisos por principal</h3>
      <p class="muted">El GRANT, DENY o REVOKE lo ejecuta el motor; el efecto aparece al volver a Clientes o Empleados.</p>
      <div class="fichas">
        <div class="campo">
          <label for="p-principal">Principal</label>
          <select id="p-principal">${opcionesPrincipal}</select>
        </div>
        <div class="campo">
          <label for="p-tabla">Tabla</label>
          <select id="p-tabla">${opcionesTabla}</select>
        </div>
        <div class="campo">
          <label for="p-permiso">Permiso</label>
          <select id="p-permiso"><option>SELECT</option><option>INSERT</option><option>UPDATE</option><option>DELETE</option></select>
        </div>
        <div class="campo">
          <label for="p-accion">Acción</label>
          <select id="p-accion"><option>GRANT</option><option>DENY</option><option>REVOKE</option></select>
        </div>
        <div class="campo">
          <button class="primary mini" id="p-aplicar">Ejecutar</button>
        </div>
      </div>
      <div class="tabla-wrap alta" style="margin-top: 14px">
        <table class="datos apilada">
          <thead><tr><th>Principal</th><th>Permiso</th><th>Estado</th><th>Objeto / columna</th></tr></thead>
          <tbody>
            ${d.permisos
              .map(
                (p) => `<tr><td data-col="Principal">${esc(p.principal)}</td>
                <td data-col="Permiso">${esc(p.permiso)}</td>
                <td data-col="Estado">${esc(p.estado)}</td>
                <td data-col="Objeto / columna" class="mono">${esc(p.objeto)}${p.columna ? `.${esc(p.columna)}` : ""}</td></tr>`
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
        <table class="datos apilada">
          <thead><tr><th>Usuario</th><th>Principal BD</th><th>Rol</th><th>Activo</th><th class="acciones"></th></tr></thead>
          <tbody>
            ${d.appUsuarios
              .map(
                (u) => `<tr>
                  <td data-col="Usuario">${esc(u.Usuario)}</td>
                  <td data-col="Principal BD" class="mono">${esc(u.PrincipalBD)}</td>
                  <td data-col="Rol">${esc(u.Rol)}</td>
                  <td data-col="Activo"><span class="badge ${u.Activo ? "ok" : "no"}">${u.Activo ? "sí" : "no"}</span></td>
                  <td class="acciones"><button class="ghost mini" data-toggle="${esc(u.Usuario)}" data-activo="${u.Activo ? "1" : "0"}">
                    ${u.Activo ? "Desactivar" : "Activar"}</button></td>
                </tr>`
              )
              .join("")}
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h3>Roles y sus miembros</h3>
      <div class="tabla-wrap alta">
        <table class="datos apilada">
          <thead><tr><th>Principal</th><th>Tipo</th><th>Rol</th></tr></thead>
          <tbody>
            ${d.usuarios
              .map((u) => `<tr><td data-col="Principal">${esc(u.principal)}</td>
              <td data-col="Tipo">${esc(u.tipo)}</td>
              <td data-col="Rol">${esc(u.rol)}</td></tr>`)
              .join("")}
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h3>Sesiones</h3>
      <p class="muted">${esc(d.sesiones ?? 0)} sesiones vigentes en <span class="mono">dbo.SesionesApp</span>. Se guarda el SHA-256 del token, no el token. La revocación alcanza a cualquier proceso o nodo.</p>
      <button class="ghost" id="btn-revocar">Revocar todas las sesiones</button>
    </div>`;

  const anunciar = (t) => { avisoAdmin = t; };

  $("#m-aplicar").addEventListener("click", async () => {
    try {
      const r = await api("/api/admin/mascara", {
        method: "POST",
        body: JSON.stringify({ tabla: $("#m-tabla").value, columna: $("#m-columna").value, funcion: $("#m-funcion").value }),
      });
      anunciar(`Ejecutado en el motor: ${r.ejecutado}`);
      await vistaAdmin();
    } catch (ex) { anunciar(`El motor rechazó la orden: ${ex.message}`); await vistaAdmin(); }
  });

  $("#vista").querySelectorAll("[data-quitar]").forEach((b) =>
    b.addEventListener("click", async () => {
      const [tabla, columna] = b.dataset.quitar.split("|");
      try {
        const r = await api("/api/admin/mascara", { method: "POST", body: JSON.stringify({ tabla, columna, funcion: "" }) });
        anunciar(`Ejecutado en el motor: ${r.ejecutado}`);
        await vistaAdmin();
      } catch (ex) { anunciar(`El motor rechazó la orden: ${ex.message}`); await vistaAdmin(); }
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
      anunciar(`Ejecutado en el motor: ${r.ejecutado}`);
      await vistaAdmin();
    } catch (ex) { anunciar(`El motor rechazó la orden: ${ex.message}`); await vistaAdmin(); }
  });

  $("#vista").querySelectorAll("[data-toggle]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        await api("/api/admin/usuario", {
          method: "POST",
          body: JSON.stringify({ usuario: b.dataset.toggle, activo: b.dataset.activo !== "1" }),
        });
        anunciar(`Usuario ${b.dataset.toggle} ${b.dataset.activo === "1" ? "desactivado" : "activado"}.`);
        await vistaAdmin();
      } catch (ex) { anunciar(`El motor rechazó la orden: ${ex.message}`); await vistaAdmin(); }
    })
  );

  $("#btn-revocar").addEventListener("click", async () => {
    try {
      const r = await api("/api/admin/revocar-sesiones", { method: "POST" });
      state.sesion = null;
      $("#app").hidden = true;
      $("#login").hidden = false;
      $("#login-error").hidden = false;
      $("#login-error").textContent = `Se revocaron ${r.revocadas} sesiones. Vuelve a entrar.`;
    } catch (ex) {
      anunciar(`No se pudo revocar: ${ex.message}`);
      await vistaAdmin();
    }
  });
}

/* ---------------- inferencia DDM ---------------- */
async function vistaInferencia() {
  let datos;
  try {
    datos = await api("/api/datos/clientes");
  } catch (ex) {
    $("#vista").innerHTML = `<div class="denegado"><h3>Sin acceso</h3><pre>${esc(ex.message)}</pre></div>`;
    return;
  }
  const filas = datos.filas || [];
  const opciones = filas
    .map((f) => `<option value="${esc(f.ClienteID)}">Cliente ${esc(f.ClienteID)} · ${esc(f.Nombre)} — saldo visible ${esc(f.SaldoCuenta)}</option>`)
    .join("");

  $("#vista").innerHTML = `
    <div class="card">
      <h3>Inferencia por <span class="mono">WHERE</span></h3>
      <p class="muted">El enmascaramiento protege lo que se muestra, no lo que se filtra. La consola puede preguntar si el saldo real supera un umbral y recuperar el valor exacto por búsqueda binaria.</p>
      <div class="fichas">
        <div class="campo"><label for="i-cliente">Cliente</label><select id="i-cliente">${opciones}</select></div>
        <div class="campo"><label for="i-umbral">Umbral</label><input id="i-umbral" type="number" step="0.01" value="0" /></div>
        <div class="campo"><button class="primary mini" id="i-probar">Probar umbral</button></div>
        <div class="campo"><button class="ghost mini" id="i-recuperar">Recuperar saldo exacto</button></div>
      </div>
      <div id="i-resultado"></div>
      <p class="muted" style="margin-top:10px">El motor evalúa <span class="mono">SaldoCuenta &gt;= @umbral</span> sobre el valor real; <span class="mono">default()</span> solo cambia la salida.</p>
    </div>`;

  const consultar = async (id, umbral) => {
    const r = await api(`/api/demo/inferencia?clienteId=${id}&umbral=${encodeURIComponent(umbral)}`);
    return Number(r.coincide) > 0;
  };
  const resultado = (html) => { $("#i-resultado").innerHTML = html; };

  $("#i-probar").addEventListener("click", async () => {
    const id = Number($("#i-cliente").value);
    const u = $("#i-umbral").value;
    try {
      const r = await api(`/api/demo/inferencia?clienteId=${id}&umbral=${encodeURIComponent(u)}`);
      resultado(`<div class="aviso">El cliente ${id} ${Number(r.coincide) ? "supera" : "no supera"} el umbral ${esc(r.umbral)}. La consola sigue mostrando el saldo enmascarado.</div>`);
    } catch (ex) {
      resultado(`<div class="denegado"><pre>${esc(ex.message)}</pre></div>`);
    }
  });

  $("#i-recuperar").addEventListener("click", async () => {
    const id = Number($("#i-cliente").value);
    let lo = 0, hi = 1000000;
    try {
      for (let i = 0; i < 42; i++) {
        const mid = (lo + hi) / 2;
        if (await consultar(id, mid.toFixed(2))) lo = mid; else hi = mid;
      }
      resultado(`<div class="denegado"><h3>Saldo inferido</h3><p class="muted">Cliente ${id}: el motor confirma que el saldo real es <span class="mono">${lo.toFixed(2)}</span> aunque la tabla lo muestre enmascarado.</p></div>`);
    } catch (ex) {
      resultado(`<div class="denegado"><pre>${esc(ex.message)}</pre></div>`);
    }
  });
}

/* ---------------- SQL injection ---------------- */
function vistaSqli() {
  $("#vista").innerHTML = `
    <div class="card">
      <h3>SQL injection: concatenación vs. parámetro</h3>
      <p class="muted">Mismo filtro, dos procedimientos. El primero pega el valor en el texto de la consulta; el segundo lo pasa como parámetro.</p>
      <div class="fichas">
        <div class="campo"><label for="s-filtro">Filtro</label><input id="s-filtro" value="' OR 1=1--" /></div>
        <div class="campo"><button class="primary mini" id="s-probar">Ejecutar</button></div>
      </div>
      <div id="s-resultado"></div>
      <p class="muted" style="margin-top:10px">Prueba con <span class="mono">' OR 1=1--</span>: la versión vulnerable devuelve todos los clientes; la parametrizada, ninguno.</p>
    </div>`;

  const tabla = (filas) => `<table class="datos">
      <thead><tr><th>ClienteID</th><th>Nombre</th></tr></thead>
      <tbody>${filas.map((x) => `<tr><td>${esc(x.ClienteID)}</td><td>${esc(x.Nombre)}</td></tr>`).join("")}</tbody>
    </table>`;

  $("#s-probar").addEventListener("click", async () => {
    try {
      const r = await api(`/api/demo/sqli?filtro=${encodeURIComponent($("#s-filtro").value)}`);
      $("#s-resultado").innerHTML = `
        <div class="grid-2" style="margin-top:14px">
          <div class="card"><h3>Vulnerable (concatenación)</h3><p class="muted">${r.vulnerable.length} fila(s)</p><div class="tabla-wrap">${tabla(r.vulnerable)}</div></div>
          <div class="card"><h3>Seguro (parámetro)</h3><p class="muted">${r.seguro.length} fila(s)</p><div class="tabla-wrap">${tabla(r.seguro)}</div></div>
        </div>`;
    } catch (ex) {
      $("#s-resultado").innerHTML = `<div class="denegado"><pre>${esc(ex.message)}</pre></div>`;
    }
  });
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
  const monto = (v) => (v === null || v === undefined || v === "" ? "—" : Number(v).toFixed(2));
  const cuerpo = filas
    .map((f) => {
      const ok = Number(f.FirmaValida) === 1;
      const intacto = f.Integridad === "INTACTO";
      return `<tr>
        <td data-col="Doc" class="num">${esc(f.DocID)}</td>
        <td data-col="Referencia" class="mono">${esc(String(f.Referencia).slice(0, 8))}…</td>
        <td data-col="Cliente" class="num">${esc(f.ClienteID)}</td>
        <td data-col="Monto" class="num">${esc(monto(f.Monto))}</td>
        <td data-col="Tipo">${esc(f.Tipo)}</td>
        <td data-col="Fecha firma">${esc(f.fecha_firma)}</td>
        <td data-col="Firma"><span class="badge ${ok ? "ok" : "no"}">${ok ? "válida" : "inválida"}</span></td>
        <td data-col="Integridad"><span class="badge ${intacto ? "ok" : "no"}">${esc(f.Integridad)}</span></td>
        ${esDba ? `<td class="acciones">
          <button class="ghost mini" data-alterar="${esc(f.DocID)}">Alterar</button>
          <button class="ghost mini" data-restaurar="${esc(f.DocID)}">Restaurar</button></td>` : ""}
      </tr>`;
    })
    .join("");

  $("#vista").innerHTML = `
    <div class="card">
      <h3>Firma una transacción</h3>
      <p class="muted">La base arma el XML, calcula el SHA-256 y lo firma con la clave privada del certificado. Nada se firma en la aplicación.</p>
      <div class="fichas">
        <div class="campo">
          <label for="f-cliente">Cliente</label>
          <select id="f-cliente">
            <option value="1">Cliente 1</option><option value="2">Cliente 2</option>
            <option value="3">Cliente 3</option><option value="4">Cliente 4</option>
            <option value="5">Cliente 5</option>
          </select>
        </div>
        <div class="campo">
          <label for="f-tipo">Tipo</label>
          <select id="f-tipo">
            <option>Transferencia</option><option>Deposito</option>
            <option>Retiro</option><option>Pago servicio</option>
          </select>
        </div>
        <div class="campo">
          <label for="f-monto">Monto</label>
          <input id="f-monto" type="number" step="0.01" min="1" value="2500.00" />
        </div>
        <div class="campo">
          <button class="primary mini" id="f-firmar">Firmar y guardar</button>
        </div>
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
        <table class="datos apilada">
          <thead><tr><th>Doc</th><th>Referencia</th><th>Cliente</th><th>Monto</th><th>Tipo</th><th>Fecha firma</th><th>Firma</th><th>Integridad</th>${esDba ? `<th class="acciones">Demostración</th>` : ""}</tr></thead>
          <tbody>${cuerpo || `<tr><td colspan="${esDba ? 9 : 8}" class="nulo">Todavía no hay documentos firmados.</td></tr>`}</tbody>
        </table>
      </div>
      ${esDba ? `<p class="muted" style="margin-top:10px">Con <b>Alterar</b> se cambia el monto dentro del XML: la firma sigue siendo criptográficamente válida (nadie tocó el hash firmado), pero la integridad pasa a ALTERADO. Por eso se verifican las dos cosas.</p>` : ""}
    </div>

    <div class="card">
      <h3>Firma XMLDSig (W3C)</h3>
      <p class="muted">Firma embebida <span class="mono">&lt;Signature&gt;</span> con RSA-SHA256 y canonicalización Exclusive C14N. El certificado lo emite la CA de <span class="mono">pki/</span> y la cadena se valida contra su raíz.</p>
      <button class="ghost" id="f-xmldsig">Firmar y verificar XML</button>
      <div id="f-xmldsig-out"></div>
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

  $("#vista").querySelectorAll("[data-alterar]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        await api("/api/firma/alterar", { method: "POST", body: JSON.stringify({ docId: Number(b.dataset.alterar) }) });
        vistaFirma();
      } catch (ex) { msg(ex.message); }
    })
  );

  $("#vista").querySelectorAll("[data-restaurar]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        await api("/api/firma/restaurar", { method: "POST", body: JSON.stringify({ docId: Number(b.dataset.restaurar) }) });
        vistaFirma();
      } catch (ex) { msg(ex.message); }
    })
  );

  $("#f-xmldsig").addEventListener("click", async () => {
    try {
      const r = await api("/api/firma/xmldsig");
      $("#f-xmldsig-out").innerHTML = `
        <div class="aviso">Firma ${r.valida ? "válida" : "inválida"} · ${esc(r.algoritmo)}</div>
        <div class="kv" style="margin-top:10px">
          <div><span>Origen</span><span>${esc(r.origen)}</span></div>
          <div><span>Emisor</span><span class="mono">${esc(r.emisor)}</span></div>
          <div><span>Raíz de confianza</span><span class="mono">${esc(r.raiz || "—")}</span></div>
          <div><span>Cadena</span><span class="badge ${r.cadena_valida ? "ok" : "no"}">${r.cadena_valida ? "verificada contra la CA" : "no verificable"}</span></div>
          <div><span>Huella</span><span class="mono">${esc(r.huella)}</span></div>
        </div>
        <pre style="max-height:260px;overflow:auto;margin-top:10px">${esc(r.xml)}</pre>`;
    } catch (ex) {
      $("#f-xmldsig-out").innerHTML = `<div class="denegado"><pre>${esc(ex.message)}</pre></div>`;
    }
  });
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
      ${esDba
        ? `<div class="row" style="margin-top: 14px">
             <button class="primary mini" id="c-backup">Respaldar certificado (.cer + .pvk)</button>
           </div>
           <p class="muted" id="c-msg" style="margin-top: 8px"></p>`
        : `<p class="limite">Respaldo del certificado: solo la cuenta de administración.</p>`}
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
        <div class="kv prosa">
          <div><span>TDE</span><span>robo de disco o de backup</span></div>
          <div><span>DDM</span><span>que un usuario vea datos en pantalla</span></div>
          <div><span>Always Encrypted</span><span>que el propio motor lea el dato</span></div>
          <div><span>Firma digital</span><span>alteración y repudio del documento</span></div>
          <div><span>Auditoría</span><span>que nadie borre huellas</span></div>
        </div>
        <p class="muted" style="margin-top: 10px">TDE no protege de un DBA que ya está dentro de la instancia: para ese caso están el cifrado por columna con clave en el motor y Always Encrypted con la clave fuera de él.</p>
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
        <td data-col="ID" class="num">${esc(f.TarjetaID)}</td>
        <td data-col="Cliente" class="num">${esc(f.ClienteID)}</td>
        <td data-col="Tarjeta" class="mono">•••• ${esc(f.Ultimos4)}</td>
        <td data-col="Número cifrado" class="num">${esc(f.bytes_numero)} bytes</td>
        <td data-col="CVV cifrado" class="num">${esc(f.bytes_cvv)} bytes</td>
        <td data-col="Alta">${esc(f.alta)}</td>
        <td class="acciones"><button class="ghost mini" data-descifrar="${esc(f.TarjetaID)}">Descifrar</button></td>
      </tr>`
    )
    .join("");

  $("#vista").innerHTML = `
    <div class="card">
      <h3>Tarjeta y CVV cifrados con clave simétrica</h3>
      <p class="muted">El valor se guarda cifrado con AES-256 (<span class="mono">EncryptByKey</span>). Tener SELECT sobre la tabla no alcanza: para leerlo hay que poder abrir la clave.</p>
      <div class="fichas">
        <div class="campo">
          <label for="k-cliente">Cliente</label>
          <select id="k-cliente">
            <option value="1">Cliente 1</option><option value="2">Cliente 2</option>
            <option value="3">Cliente 3</option><option value="4">Cliente 4</option>
            <option value="5">Cliente 5</option>
          </select>
        </div>
        <div class="campo">
          <label for="k-numero">Número de tarjeta</label>
          <input id="k-numero" placeholder="4532-1122-3344-5566" />
        </div>
        <div class="campo">
          <label for="k-cvv">CVV</label>
          <input id="k-cvv" placeholder="123" />
        </div>
        <div class="campo">
          <button class="primary mini" id="k-guardar">Guardar cifrada</button>
        </div>
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
        <table class="datos apilada">
          <thead><tr><th>ID</th><th>Cliente</th><th>Tarjeta</th><th>Número cifrado</th><th>CVV cifrado</th><th>Alta</th><th class="acciones">Prueba</th></tr></thead>
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

  $("#vista").querySelectorAll("[data-descifrar]").forEach((b) =>
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
          <h3>No puede descifrar la tarjeta ${id}</h3>
          <p class="muted">El motor rechazó abrir la clave para <span class="mono">${esc(e.principal || state.sesion.principal)}</span>. El registro sigue visible, pero el dato no.</p>
          <pre style="margin-top:10px">${esc(e.error || ex.message)}</pre>
        </div>`;
      }
      // El veredicto se estampa debajo de la tabla: hay que llevarlo a la vista.
      caja.scrollIntoView({ block: "nearest", behavior: movimientoReducido() ? "auto" : "smooth" });
    })
  );
}

/* ---------------- inicio ---------------- */
iniciar();
