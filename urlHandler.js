import { checksec } from './pkg/checksec.js';
import { displayResult } from './display.js';
import { showError, hideError } from './utils.js';
import { getIsViewingSharedReport, setIsViewingSharedReport } from './share.js';

const urlInput = document.getElementById('urlInput');
const analyzeUrlBtn = document.getElementById('analyzeUrlBtn');
const loading = document.getElementById('loading');

export function setupUrlInputListeners() {
    analyzeUrlBtn.addEventListener('click', handleUrlAnalysis);
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            handleUrlAnalysis();
        }
    });
}

async function handleUrlAnalysis() {
    const url = urlInput.value.trim();
    if (!url) {
        showError('Please enter a valid URL');
        return;
    }

    // Clean up shared report state if user is analyzing a new URL
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

    hideError();
    loading.style.display = 'block';
    analyzeUrlBtn.disabled = true;

    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`Failed to fetch file: ${response.statusText}`);
        }

        const arrayBuffer = await response.arrayBuffer();
        const uint8Array = new Uint8Array(arrayBuffer);
        
        // Extract filename from URL
        const filename = url.split('/').pop() || 'downloaded_file';
        
        // Run checksec analysis
        const result = await checksec(uint8Array, filename);
        console.log("Checksec result:", result);
        
        loading.style.display = 'none';
        displayResult(result);
    } catch (err) {
        console.error("URL analysis error:", err);
        showError(err.message || "Failed to analyze file from URL");
    } finally {
        analyzeUrlBtn.disabled = false;
    }
} 