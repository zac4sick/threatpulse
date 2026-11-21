// Runs before first paint (synchronous, tiny).
// 1) Anti-clickjacking: GitHub Pages can't send X-Frame-Options / frame-ancestors headers,
//    so refuse to render inside another site's frame.
if (window.top !== window.self) {
  document.documentElement.style.display = "none";
  try { window.top.location.replace(window.self.location.href); } catch (e) { /* cross-origin: stay hidden */ }
}
// 2) Apply the saved theme so it never flashes.
try { const t = localStorage.getItem("tp-theme"); if (t === "light" || t === "dark") document.documentElement.dataset.theme = t; } catch (e) { /* storage blocked */ }
