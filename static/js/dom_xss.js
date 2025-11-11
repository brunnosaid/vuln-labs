// small demo to show DOM-based injection when clicking the button
document.addEventListener('DOMContentLoaded', function() {
  const btn = document.getElementById('domBtn');
  if (!btn) return;
  btn.addEventListener('click', function() {
    const input = document.getElementById('domInput').value || '';
    // intentionally insecure insertion to demonstrate DOM XSS
    document.getElementById('domOutput').innerHTML = "User said: " + input;
  });
});
