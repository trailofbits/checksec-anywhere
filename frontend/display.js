import { getSecurityClass, formatSecurityValue, formatSecurityName } from './security.js';
import { addPathDetails, addDynLibDetails } from './utils.js';
import { generateShareableURL, copyToClipboard } from './share.js';
import { generate_sarif_report } from './pkg/checksec.js';

const output = document.getElementById("output");
const resultsTitle = document.getElementById("resultsTitle");
const resultsSection = document.getElementById("resultsSection");

export function displayFileType(binaryType, bitness) {
    let binary_str = "";
    switch (binaryType){
        case "Macho":
            binary_str = "Mach-O";
            break;
        case "Elf":
            binary_str = "ELF";
            break;
        case "Pe":
            binary_str = "PE";
            break;
        default:
            binary_str = "Unknown File" // We should never hit this default case
    }
    resultsTitle.textContent = `${binary_str} (${bitness} bit) Security Analysis`;
    
    const fileTypeItem = document.createElement("li");
    fileTypeItem.className = "security-item";
    fileTypeItem.innerHTML = `
        <div class="security-item-main">
            <span class="security-name">File Type</span>
            <span class="security-value info">${binary_str}</span>
        </div>
    `;
    output.appendChild(fileTypeItem);
    return binary_str;
}

export function displayFilename(filename) {
    const filenameItem = document.createElement("li");
    filenameItem.className = "security-item";
    filenameItem.innerHTML = `
        <div class="security-item-main">
            <span class="security-name">Filename</span>
            <span class="security-value info">${filename}</span>
        </div>
    `;
    output.appendChild(filenameItem);
}

export function displayBinaryData(binaryData) {
    for (const [key, value] of Object.entries(binaryData)) {
        const item = document.createElement("li");
        item.className = "security-item";
        
        const formattedName = formatSecurityName(key);
        if (!formattedName) { // not necessarily information we want to include as a row in the report
            continue;
        }
        const securityClass = getSecurityClass(key, value);
        const formattedValue = formatSecurityValue(key, value);
        

        item.innerHTML = `
            <div class="security-item-main">
                <span class="security-name">${formattedName}</span>
                <span class="security-value ${securityClass}">${formattedValue}</span>
            </div>
        `;
        
        // Add rpath details if applicable
        if (key === 'rpath' || key === 'runpath'){
            addPathDetails(item, key, value);
        }

        // Add dynamic library details if applicable
        if (key === 'dynlibs' && Array.isArray(value) && value.length > 0) {
            addDynLibDetails(item, value);
        }
        
        output.appendChild(item);
    }
}

export function displayShareFunctionality(result, isSharedReport) {
    // Add SARIF download functionality for all reports (shared and non-shared)
    const sarifItem = document.createElement("li");
    sarifItem.className = "security-item sarif-item";
    sarifItem.innerHTML = `
        <div class="security-item-main">
            <span class="security-name">Export SARIF</span>
            <span class="security-value info">
                <button id="downloadSarifBtn" class="sarif-btn">Download SARIF Report</button>
            </span>
        </div>
    `;
    output.appendChild(sarifItem);

    // Add SARIF download functionality
    const downloadSarifBtn = document.getElementById('downloadSarifBtn');
    
    downloadSarifBtn.addEventListener('click', async () => {
        downloadSarifBtn.textContent = 'Generating...';
        downloadSarifBtn.disabled = true;
        try {
            const sarifJson = await generate_sarif_report(result);
            const filename = result.filename + "_checksec-report" || 'checksec-report';
            const blob = new Blob([sarifJson], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${filename}.sarif`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            downloadSarifBtn.textContent = 'Downloaded!';
            downloadSarifBtn.classList.add('downloaded');
            setTimeout(() => {
                downloadSarifBtn.textContent = 'Download SARIF Report';
                downloadSarifBtn.classList.remove('downloaded');
                downloadSarifBtn.disabled = false;
            }, 2000);
        } catch (err) {
            console.error('Failed to generate SARIF report:', err);
            downloadSarifBtn.textContent = 'Error - Try Again';
            downloadSarifBtn.disabled = false;
        }
    });

    // Only show share functionality for non-shared reports
    if (!isSharedReport) {
        const shareItem = document.createElement("li");
        shareItem.className = "security-item share-item";
        shareItem.innerHTML = `
            <div class="security-item-main">
                <span class="security-name">Share Report</span>
                <span class="security-value info">
                    <button id="shareReportBtn" class="share-btn">Generate Link</button>
                    <button id="copyLinkBtn" class="copy-btn" style="display: none;">Copy Link</button>
                </span>
            </div>
            <div id="shareUrl" class="share-url" style="display: none;"></div>
        `;
        output.appendChild(shareItem);
        
        // Add share functionality
        const shareBtn = document.getElementById('shareReportBtn');
        const copyBtn = document.getElementById('copyLinkBtn');
        const shareUrlDiv = document.getElementById('shareUrl');
        
        shareBtn.addEventListener('click', async () => {
            shareBtn.textContent = 'Generating...';
            shareBtn.disabled = true;
            try {
                const shareableUrl = await generateShareableURL(result);
                shareUrlDiv.textContent = shareableUrl;
                shareUrlDiv.style.display = 'block';
                shareBtn.style.display = 'none';
                copyBtn.style.display = 'inline-block';
            } catch (err) {
                console.error('Failed to generate share URL:', err);
                shareBtn.textContent = 'Error - Try Again';
                shareBtn.disabled = false;
            }
        });
        
        copyBtn.addEventListener('click', async () => {
            copyBtn.textContent = 'Copying...';
            copyBtn.disabled = true;
            try {
                const shareableUrl = shareUrlDiv.textContent;
                const success = await copyToClipboard(shareableUrl);
                if (success) {
                    copyBtn.textContent = 'Copied!';
                    copyBtn.classList.add('copied');
                    setTimeout(() => {
                        copyBtn.textContent = 'Copy Link';
                        copyBtn.classList.remove('copied');
                        copyBtn.disabled = false;
                    }, 2000);
                } else {
                    copyBtn.textContent = 'Failed - Try Again';
                    copyBtn.disabled = false;
                }
            } catch (err) {
                console.error('Failed to copy URL:', err);
                copyBtn.textContent = 'Error - Try Again';
                copyBtn.disabled = false;
            }
        });
    }
}

export function displayResultV1(result, isSharedReport = false) {
    output.innerHTML = "";
    
    const { version, filename, data } = result;
    console.log("received data", data);
    const [binaryType, binaryData] = Object.entries(data)[0];
    
    displayFileType(binaryType, binaryData["bitness"]);
    displayFilename(filename);
    displayBinaryData(binaryData);
    displayShareFunctionality(result, isSharedReport);
    
    resultsSection.style.display = "block";
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

export function displayResult(result, isSharedReport = false) {
    const version = result.version || '1';
    console.log('Displaying result with version:', version);
    
    switch (version) {
        case '0.1.0':
            displayResultV1(result, isSharedReport);
            break;
        default:
            console.warn(`Unknown version ${version}, falling back to v1 display`);
            displayResultV1(result, isSharedReport);
    }
} 