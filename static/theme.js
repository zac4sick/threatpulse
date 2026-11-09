// Applied before first paint so the saved theme never flashes. Kept tiny and synchronous.
try { const t = localStorage.getItem("tp-theme"); if (t === "light" || t === "dark") document.documentElement.dataset.theme = t; } catch (e) { /* storage blocked */ }
