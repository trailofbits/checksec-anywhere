import { checksec } from './pkg/checksec.js';
import { displayResults } from './display.js';
import { showError, hideError } from './utils.js';
import { getIsViewingSharedReport, setIsViewingSharedReport } from './share.js';

const fileInput = document.getElementById("fileInput");
const fileInputWrapper = document.getElementById("fileInputWrapper");
const batchLoading = document.getElementById("batchLoading");
const currentFileSpan = document.getElementById("currentFile");
const totalFilesSpan = document.getElementById("totalFiles");
const resultsSection = document.getElementById("resultsSection");

export async function handleFiles(files) {
    // window related cleanup
    hideError();
    document.getElementById("tabsContainer").style.display = "none";
    
    // Clean up shared report state if user is uploading new files
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
    
    // Convert FileList to array
    const fileArray = Array.from(files);
    
    await handleFileInput(fileArray);
}

export async function handleFileInput(files) {
    batchLoading.style.display = "block";
    const batchStartTime = performance.now();
    try {
        const results = [];
        const totalFiles = files.length;
        totalFilesSpan.textContent = totalFiles;
        
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            currentFileSpan.textContent = i + 1;
            
            try {
                const buffer = await file.arrayBuffer();
                const uint8Array = new Uint8Array(buffer);
                
                // Run checksec analysis
                const result = await checksec(uint8Array, file.name);
                results.push({ result, file, success: true });
            } catch (err) {
                results.push({ 
                    result: { error: err || "Failed to analyze binary" }, 
                    file, 
                    success: false 
                });
            }
        }
        
        batchLoading.style.display = "none";
        displayResults(results);
    } catch (err) {
        console.error("File processing error:", err);
        batchLoading.style.display = "none";
        showError(err.message || "Failed to process files");
    }
    const batchEndTime = performance.now();
    const totalBatchTime = batchEndTime - batchStartTime;
    console.log(`BATCH TIME: ${totalBatchTime}`);
}

export function setupFileInputListeners() {
    // Unified file upload handling
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
            handleFiles(files);
        }
    });

    fileInputWrapper.addEventListener('click', () => {
        fileInput.click();
    });

    fileInput.addEventListener("change", async (event) => {
        const files = event.target.files;
        if (files.length > 0) {
            await handleFiles(files);
        }
    });
} 