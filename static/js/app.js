/**
 * app.js — NetUserClassify UI helpers
 * Features:
 *   - Dark/Light mode toggle with localStorage persistence
 *   - Smooth number counter animation
 *   - Drag-and-drop upload zone enhancement
 */

/* ══════════════════════════════════════════════════════════════
   THEME TOGGLE
══════════════════════════════════════════════════════════════ */
(function initTheme() {
    const stored = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const theme = stored || (prefersDark ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', theme);
})();

function toggleTheme() {
    const html = document.documentElement;
    const current = html.getAttribute('data-theme') || 'light';
    const next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    updateToggleIcon(next);
}

function updateToggleIcon(theme) {
    const btn = document.getElementById('theme-toggle');
    if (!btn) return;
    const isDark = theme === 'dark';
    btn.innerHTML = isDark
        ? '<i class="fas fa-sun"></i>'
        : '<i class="fas fa-moon"></i>';
    btn.title = isDark ? 'Yorug\' rejimga o\'tish' : 'Qorong\'i rejimga o\'tish';
}

document.addEventListener('DOMContentLoaded', () => {
    const current = document.documentElement.getAttribute('data-theme') || 'light';
    updateToggleIcon(current);
});

/* ══════════════════════════════════════════════════════════════
   SMOOTH NUMBER COUNTER
══════════════════════════════════════════════════════════════ */
function animateCounter(el, target, duration = 700) {
    const start = performance.now();
    const startVal = 0;

    function step(timestamp) {
        const elapsed = timestamp - start;
        const progress = Math.min(elapsed / duration, 1);
        // Ease out cubic
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(startVal + (target - startVal) * eased).toLocaleString();
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

// Export for use in results.html
window.animateCounter = animateCounter;

/* ══════════════════════════════════════════════════════════════
   DRAG-AND-DROP UPLOAD ZONE
══════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('csvFile');
    if (!dropZone || !fileInput) return;

    ['dragenter', 'dragover'].forEach(evt => {
        dropZone.addEventListener(evt, e => {
            e.preventDefault();
            dropZone.classList.add('drag-over');
        });
    });

    ['dragleave', 'drop'].forEach(evt => {
        dropZone.addEventListener(evt, () => dropZone.classList.remove('drag-over'));
    });

    dropZone.addEventListener('drop', e => {
        e.preventDefault();
        const files = e.dataTransfer?.files;
        if (files && files.length > 0) {
            fileInput.files = files;
            fileInput.dispatchEvent(new Event('change'));
        }
    });

    dropZone.addEventListener('click', () => fileInput.click());
});
