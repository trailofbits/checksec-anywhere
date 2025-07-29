import { checksec_compress, checksec_decompress } from "./pkg/checksec.js";
import { displayResults } from "./display.js";
import { showError } from "./utils.js";

// Global variable to store current analysis data for sharing
let isViewingSharedReport = false;
export async function generateShareableURL(analysisResult) {
    try {
        const compressedData = await checksec_compress(analysisResult);
        const currentURL = new URL(window.location);
        currentURL.hash = `data=${compressedData}`;
        return currentURL.toString();
    } catch (err) {
        console.error('Failed to compress data:', err);
        throw new Error('Failed to generate shareable URL');
    }
}

// Load report from URL fragment with gzip decompression
export async function loadReportFromURL() {
    const hash = window.location.hash;
    if (hash.startsWith('#data=')) {
        try {
            const compressedData = hash.substring(6); // Remove '#data='
            const bytes = new Uint8Array(compressedData.length);
            for (let i = 0; i < compressedData.length; i++) {
                bytes[i] = compressedData.charCodeAt(i);
            }
            const result = await checksec_decompress(bytes);
            // Display the loaded report
            isViewingSharedReport = true;
            displayResults([await checksec_decompress(bytes)]);
            
        } catch (err) {
            console.error('Failed to load report from URL:', err);
            showError('Invalid or corrupted report link');
        }
    }
}

export async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (err) {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        const success = document.execCommand('copy');
        document.body.removeChild(textArea);
        return success;
    }
}

export function getIsViewingSharedReport() {
    return isViewingSharedReport;
}

export function setIsViewingSharedReport(value) {
    isViewingSharedReport = value;
} 