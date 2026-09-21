import { load as loadBotD } from '/vendor/botd.esm.js';

const statusEl = document.getElementById('checkStatus');

function setStatus(message) {
  if (statusEl) statusEl.textContent = message;
}

function safeReturnPath() {
  const value = new URLSearchParams(window.location.search).get('return') || '/';
  if (!value.startsWith('/') || value.startsWith('//')) return '/';
  return value;
}

async function detectAutomation() {
  try {
    const detector = await loadBotD({ monitoring: false });
    const result = detector.detect();
    return { bot: Boolean(result?.bot), kind: String(result?.botKind || '') };
  } catch {
    return { bot: false, kind: 'unavailable' };
  }
}

function solve(challenge) {
  return new Promise((resolve, reject) => {
    const worker = new Worker('/workers/browser-proof-worker.js');
    const timeout = setTimeout(() => {
      worker.terminate();
      reject(new Error('timeout'));
    }, 25_000);
    worker.onmessage = event => {
      if (Number.isSafeInteger(event.data?.solution)) {
        clearTimeout(timeout);
        worker.terminate();
        resolve(event.data.solution);
      } else if (event.data?.error) {
        clearTimeout(timeout);
        worker.terminate();
        reject(new Error(event.data.error));
      }
    };
    worker.onerror = () => {
      clearTimeout(timeout);
      worker.terminate();
      reject(new Error('worker-error'));
    };
    worker.postMessage(challenge);
  });
}

async function run() {
  const [challengeResponse, botD] = await Promise.all([
    fetch('/api/browser/challenge', { credentials: 'same-origin', cache: 'no-store' }),
    detectAutomation()
  ]);
  if (!challengeResponse.ok) throw new Error('challenge');
  const challengeBody = await challengeResponse.json();
  const challenge = challengeBody?.data?.challenge;
  if (!challenge) throw new Error('challenge-data');
  setStatus('正在进行本地静默校验…');
  const solution = await solve(challenge);
  const verifyResponse = await fetch('/api/browser/verify', {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      challengeId: challenge.challengeId,
      solution,
      webdriver: navigator.webdriver === true,
      botD
    })
  });
  if (!verifyResponse.ok) throw new Error('verify');
  setStatus('校验完成，正在进入…');
  window.location.replace(safeReturnPath());
}

run().catch(() => {
  setStatus('暂时无法完成安全连接，请稍后刷新页面。');
});
