/**
 * PrivacyVault AI - Upload & Scanning Controller
 * Handles drag & drop, client validation, animated scanning progress, and sample triggers.
 */

document.addEventListener("DOMContentLoaded", () => {
    initDropzone();
});

let selectedFile = null;

function initDropzone() {
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("file-input");
    const previewCard = document.getElementById("file-preview-card");
    const fileNameEl = document.getElementById("selected-file-name");
    const fileSizeEl = document.getElementById("selected-file-size");
    const removeBtn = document.getElementById("btn-remove-file");
    const submitBtn = document.getElementById("btn-submit-scan");
    const uploadForm = document.getElementById("upload-form");

    if (!dropzone || !fileInput) return;

    // Click to select
    dropzone.addEventListener("click", () => fileInput.click());

    // Drag over & leave
    dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropzone.classList.add("dragover");
    });
    
    ["dragleave", "dragend"].forEach(type => {
        dropzone.addEventListener(type, () => dropzone.classList.remove("dragover"));
    });

    // Drop
    dropzone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            handleFileSelection(e.dataTransfer.files[0]);
        }
    });

    // File input change
    fileInput.addEventListener("change", (e) => {
        if (e.target.files && e.target.files.length > 0) {
            handleFileSelection(e.target.files[0]);
        }
    });

    // Remove file
    if (removeBtn) {
        removeBtn.addEventListener("click", () => {
            selectedFile = null;
            fileInput.value = "";
            previewCard.classList.add("d-none");
            submitBtn.disabled = true;
        });
    }

    // Submit Scan
    if (uploadForm) {
        uploadForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (!selectedFile) return;

            submitBtn.disabled = true;
            const progressWrapper = document.getElementById("scan-progress-wrapper");
            const progressBar = document.getElementById("scan-progress-bar");
            const statusText = document.getElementById("scan-status-text");
            const percentText = document.getElementById("scan-percent-text");

            if (progressWrapper) progressWrapper.classList.remove("d-none");

            // Animated progress simulation
            let progress = 15;
            const interval = setInterval(() => {
                progress += Math.floor(Math.random() * 15) + 5;
                if (progress > 90) progress = 90;
                if (progressBar) progressBar.style.width = progress + "%";
                if (percentText) percentText.textContent = progress + "%";
                
                if (progress > 30 && statusText) statusText.textContent = "Extracting structure & tabular coordinates...";
                if (progress > 60 && statusText) statusText.textContent = "Executing regex & cryptographic validators...";
                if (progress > 80 && statusText) statusText.textContent = "Running ML confidentiality classifier & risk scoring...";
            }, 300);

            // FormData upload
            const formData = new FormData();
            formData.append("file", selectedFile);

            try {
                const response = await fetch("/api/upload", {
                    method: "POST",
                    body: formData
                });
                const result = await response.json();
                clearInterval(interval);

                if (progressBar) progressBar.style.width = "100%";
                if (percentText) percentText.textContent = "100%";
                if (statusText) statusText.textContent = "Scan complete! Redirecting to report...";

                if (result.success) {
                    setTimeout(() => {
                        window.location.href = result.redirect_url;
                    }, 500);
                } else {
                    showToast("Scan Error: " + (result.error || "Unknown error"), true);
                    submitBtn.disabled = false;
                }
            } catch (err) {
                clearInterval(interval);
                showToast("Upload network failure: " + err, true);
                submitBtn.disabled = false;
            }
        });
    }

    function handleFileSelection(file) {
        // Validate extension
        const allowedExts = ["pdf", "docx", "txt", "csv", "json"];
        const ext = file.name.split('.').pop().toLowerCase();
        if (!allowedExts.includes(ext)) {
            showToast(`Unsupported format '.${ext}'. Supported formats: PDF, DOCX, TXT, CSV, JSON`, true);
            return;
        }

        // Validate size (25MB)
        if (file.size > 25 * 1024 * 1024) {
            showToast("File exceeds maximum allowed size of 25MB", true);
            return;
        }

        selectedFile = file;
        fileNameEl.textContent = file.name;
        fileSizeEl.textContent = (file.size / 1024 > 1024) 
            ? (file.size / (1024 * 1024)).toFixed(2) + " MB" 
            : (file.size / 1024).toFixed(1) + " KB";

        previewCard.classList.remove("d-none");
        submitBtn.disabled = false;
    }
}

// 1-Click Synthetic Sample Scanner
async function triggerSampleScan(sampleKey) {
    showToast(`Launching scan on synthetic ${sampleKey.toUpperCase()} sample...`);
    try {
        const res = await fetch("/api/scan-sample", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sample_key: sampleKey })
        });
        const data = await res.json();
        if (data.success) {
            window.location.href = data.redirect_url;
        } else {
            showToast("Sample scan failed: " + data.error, true);
        }
    } catch (e) {
        showToast("Error triggering sample scan: " + e, true);
    }
}
