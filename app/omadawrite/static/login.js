document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  const err = document.getElementById('err');
  const btn = f.querySelector('button');
  err.textContent = '';
  btn.disabled = true;
  try {
    const r = await fetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-OW-CSRF': '1' },
      body: JSON.stringify({ username: f.username.value, password: f.password.value }),
    });
    if (r.ok) { location.href = '/'; return; }
    const j = await r.json().catch(() => ({}));
    err.textContent = j.detail || `Sign-in failed (HTTP ${r.status})`;
  } catch (ex) {
    err.textContent = ex.message;
  } finally {
    btn.disabled = false;
  }
});
