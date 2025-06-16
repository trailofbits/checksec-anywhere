import { checksec } from './pkg/checksec.js';
import { displayResult } from './display.js';
import { showError, hideError } from './utils.js';
import { getIsViewingSharedReport, setIsViewingSharedReport } from './share.js';

const fileInput = document.getElementById("fileInput");
const fileInputWrapper = document.getElementById("fileInputWrapper");
const loading = document.getElementById("loading");
const resultsSection = document.getElementById("resultsSection");

export async function handleFile(file) {
    // window related cleanup
    hideError();
    loading.style.display = "block";
    resultsSection.style.display = "none";
    
    // Clean up shared report state if user is uploading a new file
    if (getIsViewingSharedReport()) {
        // Remove shared report message
        const sharedReportMessage = document.querySelector('.shared-report-message');
        if (sharedReportMessage) {
            sharedReportMessage.remove();
        }
        
        // Clear URL hash
        if (window.location.hash.startsWith('#data=')) {
            window.history.replaceState(null, null, window.location.pathname);
        }
        
        // Reset shared report flag
        setIsViewingSharedReport(false);
    }
    
    try {
        const buffer = await file.arrayBuffer();
        const uint8Array = new Uint8Array(buffer);
        
        // Run checksec analysis
        const result = await checksec(uint8Array, file.name);
        console.log("Checksec result:", result);
        
        loading.style.display = "none";
        displayResult(result);
    } catch (err) {
        console.error("Checksec error:", err);
        showError(err.message || "Failed to analyze binary");
    }
}

export function setupFileInputListeners() {
    fileInputWrapper.addEventListener('dragover', (e) => {
        e.preventDefault();
        fileInputWrapper.classList.add('dragover');
    });

    fileInputWrapper.addEventListener('dragleave', () => {
        fileInputWrapper.classList.remove('dragover');
    });

    fileInputWrapper.addEventListener('drop', (e) => {
        e.preventDefault();
        fileInputWrapper.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFile(files[0]);
        }
    });

    fileInputWrapper.addEventListener('click', () => {
        fileInput.click();
    });

    fileInput.addEventListener("change", async (event) => {
        const file = event.target.files[0];
        if (file) {
            await handleFile(file);
        }
    });
} 