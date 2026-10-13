/**
 * PrivacyVault AI - Core Client Scripts
 * Handles theme toggling, notification toasts, clipboard copy, and UI helpers.
 */

document.addEventListener("DOMContentLoaded", () => {
    initTheme();
});

// Theme Management
function initTheme() {
    const savedTheme = localStorage.getItem("pv_theme") || "dark";
    setTheme(savedTheme);
    
    const themeBtn = document.getElementById("theme-toggle-btn");
    if (themeBtn) {
        themeBtn.addEventListener("click", () => {
            const currentTheme = document.documentElement.getAttribute("data-theme") || "dark";
            const newTheme = currentTheme === "dark" ? "light" : "dark";
            setTheme(newTheme);
            localStorage.setItem("pv_theme", newTheme);
        });
    }
}

function setTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    const icon = document.getElementById("theme-icon");
    if (icon) {
        if (theme === "light") {
            icon.className = "bi bi-sun-fill text-warning";
        } else {
            icon.className = "bi bi-moon-stars text-cyan";
        }
    }
}

// Global Toast Notification Helper
function showToast(message, isError = false) {
    const toastEl = document.getElementById("appToast");
    const toastBody = document.getElementById("toastMessage");
    if (!toastEl || !toastBody) return;
    
    toastBody.textContent = message;
    toastEl.classList.remove("bg-dark", "bg-danger", "bg-success");
    
    if (isError) {
        toastEl.classList.add("bg-danger");
    } else {
        toastEl.classList.add("bg-dark");
    }
    
    const toast = new bootstrap.Toast(toastEl, { delay: 4000 });
    toast.show();
}

// Copy to Clipboard Utility
function copyToClipboard(text, successMsg = "Copied to clipboard!") {
    if (!navigator.clipboard) {
        showToast("Clipboard access not available in this browser", true);
        return;
    }
    navigator.clipboard.writeText(text).then(() => {
        showToast(successMsg);
    }).catch(err => {
        showToast("Failed to copy: " + err, true);
    });
}
