import { checksec_web } from './pkg/checksec.js';
import { displayResults } from './display.js';
import { showError, hideError } from './utils.js';
import { getIsViewingSharedReport, setIsViewingSharedReport } from './share.js';

const fileInput = document.getElementById("fileInput");
const fileInputWrapper = document.getElementById("fileInputWrapper");
const batchLoading = document.getElementById("batchLoading");
const currentFileSpan = document.getElementById("currentFile");
const totalFilesSpan = document.getElementById("totalFiles");
const resultsSection = document.getElementById("resultsSection");

// Upload type state
let currentUploadType = 'file'; // 'file', 'directory'

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
        const reports = [];
        let results = [];
        const totalFiles = files.length;
        totalFilesSpan.textContent = totalFiles;
        
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            currentFileSpan.textContent = i + 1;
            
            const buffer = await file.arrayBuffer();
            const uint8Array = new Uint8Array(buffer);
            try{
                results.push(await checksec_web(uint8Array, file.name));
            }
            catch (err) {
                console.log("Error message: ", err);
                reports.push({ result: { error: "Failed to analyze binary", filename: file.name} , success: false }); //serde-wasm error
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

function updateFileInputAttributes() {
    // Remove all existing attributes
    fileInput.removeAttribute('multiple');
    fileInput.removeAttribute('webkitdirectory');
    fileInput.removeAttribute('directory');
    
    // Set attributes based on current upload type
    switch (currentUploadType) {
        case 'file':
            fileInput.setAttribute('multiple', '');
            break;
        case 'directory':
            fileInput.setAttribute('webkitdirectory', '');
            fileInput.setAttribute('directory', '');
            break;
    }
}

function updateUploadTypeButtons() {
    // Remove active class from all buttons
    document.querySelectorAll('.upload-type-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Add active class to current type button
    const activeButton = document.querySelector(`[data-upload-type="${currentUploadType}"]`);
    if (activeButton) {
        activeButton.classList.add('active');
    }
}

function createUploadTypeButtons() {
    // Create button container if it doesn't exist
    let buttonContainer = document.querySelector('.upload-type-buttons');
    if (!buttonContainer) {
        buttonContainer = document.createElement('div');
        buttonContainer.className = 'upload-type-buttons';
        fileInputWrapper.insertBefore(buttonContainer, fileInputWrapper.firstChild);
    }
    
    buttonContainer.innerHTML = `
        <button class="upload-type-btn active" data-upload-type="file">
            <span>File(s)</span>
        </button>
        <button class="upload-type-btn" data-upload-type="directory">
            <span>Directory</span>
        </button>
    `;
    
    // Add click handlers
    buttonContainer.querySelectorAll('.upload-type-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            currentUploadType = btn.dataset.uploadType;
            updateFileInputAttributes();
            updateUploadTypeButtons();
        });
    });
}

export function setupFileInputListeners() {
    // Create upload type selection buttons
    createUploadTypeButtons();
    
    // Set initial file input attributes
    updateFileInputAttributes();
    
    // File upload handling
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