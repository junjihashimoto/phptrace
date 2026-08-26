'use strict';
// Design B faithful agent: per-request dynamic attach/detach of a per-call
// PHP tracing hook (dtrace_execute_ex). For 1 in N requests the hook is
// PHYSICALLY attached for the duration of that request only; all other
// requests run with NO interceptor present (baseline speed).
//
// N is templated in by the entrypoint (sed) from env SAMPLE_N.
const N = __SAMPLE_N__;

let reqSeen = 0;      // request-startup count (this process)
let attaches = 0;     // how many times we attached execute_ex
let detaches = 0;
let fires = 0;        // execute_ex onEnter invocations (only while attached)
let listener = null;

function resolve(name) {
  // frida 17 removed the static Module.findExportByName / DebugSymbol helpers;
  // try every API shape defensively.
  try {
    if (typeof Module.findGlobalExportByName === 'function') {
      const a = Module.findGlobalExportByName(name);
      if (a !== null) return a;
    }
  } catch (e) {}
  try {
    if (typeof Module.getGlobalExportByName === 'function') {
      return Module.getGlobalExportByName(name);
    }
  } catch (e) {}
  try {
    if (typeof Module.findExportByName === 'function') {
      const a = Module.findExportByName(null, name);
      if (a !== null) return a;
    }
  } catch (e) {}
  // fallback: scan modules for an instance-level export.
  try {
    const mods = Process.enumerateModules();
    for (let i = 0; i < mods.length; i++) {
      try {
        const a = mods[i].findExportByName(name);
        if (a !== null) return a;
      } catch (e) {}
    }
  } catch (e) {}
  return null;
}

function main() {
  const pExec = resolve('dtrace_execute_ex');
  const pStart = resolve('php_request_startup');
  const pShut = resolve('php_request_shutdown');
  console.log('[fridaB] N=' + N + ' pid=' + Process.id +
    ' exec=' + pExec + ' start=' + pStart + ' shut=' + pShut);
  if (pExec === null || pStart === null || pShut === null) {
    console.log('[fridaB] ERROR: symbol resolution failed');
    return;
  }

  const execOnEnter = function (args) {
    fires++;
  };

  Interceptor.attach(pStart, {
    onEnter: function (args) {
      if ((reqSeen % N) === 0) {
        if (listener === null) {
          listener = Interceptor.attach(pExec, { onEnter: execOnEnter });
          attaches++;
        }
      }
      reqSeen++;
    }
  });

  Interceptor.attach(pShut, {
    onEnter: function (args) {
      if (listener !== null) {
        listener.detach();
        listener = null;
        Interceptor.flush();
        detaches++;
      }
    }
  });

  setInterval(function () {
    console.log('[fridaB] pid=' + Process.id + ' reqSeen=' + reqSeen +
      ' attaches=' + attaches + ' detaches=' + detaches + ' fires=' + fires);
  }, 2000);
}

main();
