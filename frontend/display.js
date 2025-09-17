import { getSecurityClass, formatSecurityValue, formatSecurityName } from './security.js';
import { addPathDetails, addDynLibDetails } from './utils.js';
import { generateShareableURL, copyToClipboard } from './share.js';
import { generate_sarif_report } from './pkg/checksec.js';

const tabsContainer = document.getElementById("tabsContainer");
const tabsHeader = document.getElementById("tabsHeader");
const tabsContent = document.getElementById("tabsContent");

// Global storage for tab results
const tabResults = new Map();

export function displayFileHeader(binaryType, filename, container) {
    let binary_str = "";
    switch (binaryType){
        case "Elf32":
            binary_str = "ELF (32 Bit)";
            break;
        case "Elf64":
            binary_str = "ELF (64 Bit)";
            break;
        case "PE64":
            binary_str = "PE (64 Bit)";
            break;
        case "PE32":
            binary_str = "PE (32 Bit)";
            break;
        case "MachO64":
            binary_str = "Mach-O (64 Bit)";
            break;
        case "MachO32":
            binary_str = "Mach-O (32 Bit)";
            break;
        default:
            binary_str = "Unknown File" // We should never hit this default case
    }

    // Create the header element
    const headerElement = document.createElement("h2");
    headerElement.className = "report_header";
    headerElement.textContent = `${binary_str} Security Analysis - ${filename}`;
    container.appendChild(headerElement);
    
    // Create information section header
    const infoHeader = document.createElement("h3");
    infoHeader.className = "section-header";
    infoHeader.textContent = "File Information";
    container.appendChild(infoHeader);
    
    // Create information list container
    const infoList = document.createElement("ul");
    infoList.className = "security-list";
    
    const fileTypeItem = document.createElement("li");
    fileTypeItem.className = "security-item";
    fileTypeItem.innerHTML = `
        <div class="security-item-main">
            <span class="security-name">File Type</span>
            <span class="security-value info">${binary_str}</span>
        </div>
    `;
    infoList.appendChild(fileTypeItem);
    container.appendChild(infoList);
    return binary_str;
}

export function displayFileRow(filename, container) {
    // Find the existing info list (created in displayFileHeader)
    const infoList = container.querySelector('.security-list');
    if (infoList) {
        const filenameItem = document.createElement("li");
        filenameItem.className = "security-item";
        filenameItem.innerHTML = `
            <div class="security-item-main">
                <span class="security-name">Filename</span>
                <span class="security-value info">${filename}</span>
            </div>
        `;
        infoList.appendChild(filenameItem);
    }
}

export function displayBinaryData(binaryData, container) {
    // Check if dynamic linking is enabled
    const isDynamicLinkingEnabled = binaryData.dyn_linking === true;
    
    // Define binary info fields
    const binaryInfoFields = ['architecture', 'bitness', 'endianness'];
    
    // Add binary info fields to the information section
    const infoList = container.querySelector('.security-list');
    if (infoList) {
        binaryInfoFields.forEach(field => {
            if (binaryData[field] !== undefined) {
                const item = document.createElement("li");
                item.className = "security-item";
                
                const formattedName = formatSecurityName(field);
                const formattedValue = formatSecurityValue(field, binaryData[field]);
                
                item.innerHTML = `
                    <div class="security-item-main">
                        <span class="security-name">${formattedName}</span>
                        <span class="security-value info">${formattedValue}</span>
                    </div>
                `;
                infoList.appendChild(item);
            }
        });
    }
    
    // Create security section header
    const securityHeader = document.createElement("h3");
    securityHeader.className = "section-header";
    securityHeader.textContent = "Security Properties";
    container.appendChild(securityHeader);
    
    // Create security list container
    const securityList = document.createElement("ul");
    securityList.className = "security-list";
    
    for (const [key, value] of Object.entries(binaryData)) {
        // Skip info fields (they're displayed in the info section)
        if (['filename', 'dyn_linking', 'endianness', 'bitness', 'architecture'].includes(key)) {
            continue;
        }
        
        // Skip dynamic libraries row entirely if dynamic linking is disabled
        if ((key === 'dynlibs' || key === "interpreter") && !isDynamicLinkingEnabled) {
            continue;
        }
        
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

        // Add dynamic library details only if dynamic linking is enabled
        if (key === 'dynlibs' && Array.isArray(value) && value.length > 0 && isDynamicLinkingEnabled) {
            addDynLibDetails(item, value);
        }
        
        securityList.appendChild(item);
    }
    
    container.appendChild(securityList);
}

export function displayShareFunctionality(blob, filename, version, container) {
    // Generate unique IDs for this tab's buttons
    const uniqueId = Date.now() + Math.random().toString(36).substr(2, 9);
    const sarifBtnId = `downloadSarifBtn_${uniqueId}`;
    const shareBtnId = `shareReportBtn_${uniqueId}`;
    const copyBtnId = `copyLinkBtn_${uniqueId}`;
    const shareUrlId = `shareUrl_${uniqueId}`;
    
    // Add SARIF download functionality for all reports (shared and non-shared)
    const sarifItem = document.createElement("li");
    sarifItem.className = "security-item sarif-item";
    sarifItem.innerHTML = `
        <div class="security-item-main">
            <span class="security-name">Export SARIF</span>
            <span class="security-value info">
                <button id="${sarifBtnId}" class="sarif-btn">Download SARIF Report</button>
            </span>
        </div>
    `;
    container.appendChild(sarifItem);

    // Add SARIF download functionality
    const downloadSarifBtn = container.querySelector(`#${sarifBtnId}`);
    
    downloadSarifBtn.addEventListener('click', async () => {
        downloadSarifBtn.textContent = 'Generating...';
        downloadSarifBtn.disabled = true;
        try {
            const sarifJson = await generate_sarif_report([{file: filename, blobs: [blob], libraries: []}]);
            const urlblob = new Blob([sarifJson], { type: 'application/json' });
            const url = URL.createObjectURL(urlblob);
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

    const shareItem = document.createElement("li");
    shareItem.className = "security-item";
    shareItem.innerHTML = `
        <div class="security-item-main">
            <span class="security-name">Share Report</span>
            <span class="security-value info">
                <button id="${shareBtnId}" class="share-btn">Generate Link</button>
                <button id="${copyBtnId}" class="copy-btn" style="display: none;">Copy Link</button>
            </span>
        </div>
        <div id="${shareUrlId}" class="share-url" style="display: none;"></div>
    `;
    container.appendChild(shareItem);
    
    // Add share functionality
    const shareBtn = container.querySelector(`#${shareBtnId}`);
    const copyBtn = container.querySelector(`#${copyBtnId}`);
    const shareUrlDiv = container.querySelector(`#${shareUrlId}`);
    
    shareBtn.addEventListener('click', async () => {
        shareBtn.textContent = 'Generating...';
        shareBtn.disabled = true;
        try {
            const shareableUrl = await generateShareableURL({version, report: {file: filename, blobs: [blob], libraries: []}});
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

export function display_error_handler(filename, error_msg, container){
    container.innerHTML = `
    <h2 class=failure-message></h2>
    <div class="error-message">
        <p><strong>Error:</strong> ${error_msg}</p>
    </div>
    `;
container.querySelector(".failure-message").textContent = `Analysis Failed - ${filename}`    
}

export function setupResultTab(filename){
    const index = document.querySelectorAll(".tab-button").length;
    // Create tab button
    const tabButton = document.createElement("button");
    tabButton.className = "tab-button";
    tabButton.innerHTML = `
        <span class="tab-text"></span>
        <span class="tab-close" title="Close tab">×</span>
    `;
    // Set the filename as text content (safe)
    tabButton.querySelector('.tab-text').textContent = filename;
    tabButton.dataset.tabIndex = index;

    const tabContent = document.createElement("div");
    tabContent.className = "tab-content";
    tabContent.dataset.tabIndex = index;

    // Add click handler for tab switching
    tabButton.addEventListener('click', (e) => {
        // Don't switch tabs if clicking the close button
        if (e.target.classList.contains('tab-close')) {
            return;
        }
        
        // Remove active class from all tabs
        document.querySelectorAll(".tab-button").forEach(btn => btn.classList.remove("active"));
        document.querySelectorAll(".tab-content").forEach(content => content.classList.remove("active"));
        
        // Add active class to clicked tab
        tabButton.classList.add("active");
        tabContent.classList.add("active");
        
        // Scroll to the active tab
        scrollToActiveTab();
    });
    
    // Add close button handler
    const closeButton = tabButton.querySelector('.tab-close');
    closeButton.addEventListener('click', (e) => {
        e.stopPropagation(); // Prevent tab switching
        closeTab(tabButton, tabContent);
    });
    
    // Add to DOM
    tabsHeader.appendChild(tabButton);
    tabsContent.appendChild(tabContent);

    return tabContent;
}

function closeTab(tabButton, tabContent) {
    const isActive = tabButton.classList.contains('active');
    const allTabs = tabsHeader.querySelectorAll('.tab-button');
    
    const tabIndex = tabButton.dataset.tabIndex;
    let closedIndex = tabIndex == 0 ? 1 : tabIndex

    tabResults.delete(tabIndex);
    tabResults.delete(tabIndex);
    
    // Remove the tab and content
    tabButton.remove();
    tabContent.remove();
    
    // Update tab indices for remaining tabs trying to activate next tab
    updateTabIndices();
    
    // If no tabs left, hide the tabs container
    if (tabsHeader.children.length === 0) {
        tabsContainer.style.display = 'none';
        tabResults.clear();
        tabResults.clear();
    } else {
        const remainingTabs = tabsHeader.querySelectorAll('.tab-button');
        const remainingContents = tabsContent.querySelectorAll('.tab-content');

        let hasActiveTab = false;

        for (const tab of remainingTabs) {
            if (tab.classList.contains('active')) {
                hasActiveTab = true;
                return;
            }
        }   

        // Activate remaining tab
        const chosenTab = remainingTabs[closedIndex - 1];
        const chosenContent = remainingContents[closedIndex - 1];
        if (chosenTab && chosenContent) {
            chosenTab.classList.add('active');
            chosenContent.classList.add('active');
            scrollToActiveTab();
        }
    }
}

function updateTabIndices() {
    const allTabs = tabsHeader.querySelectorAll('.tab-button');
    const allContents = tabsContent.querySelectorAll('.tab-content');
    
    allTabs.forEach((tab, index) => {
        tab.dataset.tabIndex = index;
    });

    allContents.forEach((content, index) => {
        content.dataset.tabIndex = index;
    });
}

function scrollToActiveTab() {
    const activeTab = tabsHeader.querySelector(".tab-button.active");
    if (activeTab) {
        // Calculate the scroll position to center the active tab
        const headerWidth = tabsHeader.offsetWidth;
        const tabWidth = activeTab.offsetWidth;
        const tabLeft = activeTab.offsetLeft;
        
        // Calculate the center position of the active tab
        const tabCenter = tabLeft + (tabWidth / 2);
        const headerCenter = headerWidth / 2;
        
        // Calculate the target scroll position
        const targetScroll = tabCenter - headerCenter;
        
        // Ensure we don't scroll past the beginning
        const maxScroll = tabsHeader.scrollWidth - headerWidth;
        const finalScroll = Math.max(0, Math.min(targetScroll, maxScroll));
        
        // Smooth scroll to the target position
        tabsHeader.scrollTo({
            left: finalScroll,
            behavior: 'smooth'
        });
    }
}

export function displayResultV1(filename, blob, container) {
    const VERSION = '0.1.0';
    container.innerHTML = "";
    const [bt, binaryData] = Object.entries(blob.properties)[0];
    
    displayFileHeader(blob.binarytype, filename, container);
    displayFileRow(filename, container);
    displayBinaryData(binaryData, container);
    displayShareFunctionality(blob, filename, VERSION, container);
}

export function displayResult(entry) {

    const filename = entry.report.file // use filename reported in shared url

    let display_result_handler = null;
    switch (entry.version) {
        case '0.1.0':
            display_result_handler = displayResultV1
            break;
        default:
            console.warn(`Unknown version ${entry.result.version}, falling back to v1 display`);
            display_result_handler = displayResultV1;
    }

    entry.report.blobs.forEach((blob, index) => {
        let container = setupResultTab(filename);
        if (blob.binarytype == "Error"){
            display_error_handler(filename, blob.properties.Error, container);
        }
        else{
            const tabIndex = container.dataset.tabIndex;
            tabResults.set(tabIndex, {filename, blob});
            display_result_handler(filename, blob, container);
        }
    });
}

export function displayResults(batchResults) {
    batchResults.forEach(entry => {
        displayResult(entry)
    });

    // deactivate all other active tabs
    const allTabButtons = tabsHeader.querySelectorAll(".tab-button");
    const allTabContents = tabsContent.querySelectorAll(".tab-content");
    
    const lastTabIndex = allTabButtons.length - 1;
    
    allTabButtons.forEach((btn, index) => {
        if (index !== lastTabIndex) {
            btn.classList.remove("active");
        }
    });
    
    allTabContents.forEach((content, index) => {
        if (index !== lastTabIndex) {
            content.classList.remove("active");
        }
    });
    
    // Activate the last tab and content
    if (allTabButtons[lastTabIndex] && allTabContents[lastTabIndex]) {
        allTabButtons[lastTabIndex].classList.add("active");
        allTabContents[lastTabIndex].classList.add("active");
        
        // Scroll to the newly active tab
        setTimeout(() => {
            scrollToActiveTab();
        }, 100); // Small delay to ensure DOM is updated
    }

    tabsContainer.style.display = "block";
    tabsContainer.scrollIntoView({ behavior: 'smooth' });
    addHeaderButtons();
}

function addHeaderButtons() {
    const allTabs = tabsHeader.querySelectorAll(".tab-button");
    
    // Only show buttons if there are multiple tabs
    if (allTabs.length <= 1) {
        return;
    }
    
    // Check if button container already exists
    const existingContainer = document.querySelector('.tabs-button-container');
    if (existingContainer) {
        // Update existing SARIF button if it exists
        const existingSarifButton = document.getElementById('combinedSarifBtn');
        if (existingSarifButton) {
            updateCombinedButtonCount(existingSarifButton);
        }
        return;
    }
    
    // Count successful results only
    const successfulResults = [];
    tabResults.forEach((entry, tabIndex) => {
        if (!(entry.blob.binarytype === "Error")) {
            successfulResults.push({file: entry.filename, blobs: [entry.blob], libraries: []});
        }
    });
    
    // Create button container for horizontal layout
    const buttonContainer = document.createElement("div");
    buttonContainer.className = "tabs-button-container";
    
    // Create close all reports button (always show this)
    const closeAllButton = document.createElement("button");
    closeAllButton.id = "closeAllReportsBtn";
    closeAllButton.className = "close-all-reports-btn";
    closeAllButton.innerHTML = '<span>Close All Reports</span>';
    
    // Add click handler for close all button
    closeAllButton.addEventListener('click', () => {
        // Close all tabs
        const allTabButtons = tabsHeader.querySelectorAll('.tab-button');
        const allTabContents = tabsContent.querySelectorAll('.tab-content');
        
        // Remove all tabs
        allTabButtons.forEach(button => button.remove());
        allTabContents.forEach(content => content.remove());
        
        // Clear tab results
        tabResults.clear();
        
        // Hide tabs container
        tabsContainer.style.display = 'none';
        
        // Remove button container
        buttonContainer.remove();
    });
    
    // Add close all button to container
    buttonContainer.appendChild(closeAllButton);
    
    // Only create SARIF button if there are successful results
    if (successfulResults.length > 0) {
        const combinedButton = document.createElement("button");
        combinedButton.id = "combinedSarifBtn";
        combinedButton.className = "combined-sarif-btn";
        combinedButton.innerHTML = `
            <span>Download Combined SARIF Report (${successfulResults.length} files)</span>
        `;
        
        // Add click handler for combined SARIF button
        combinedButton.addEventListener('click', async () => {
            combinedButton.disabled = true;
            combinedButton.innerHTML = '<span>Generating combined report...</span>';
            
            try {
                // Generate combined SARIF report with only successful results
                const combinedSarif = await generate_sarif_report(successfulResults);
                
                // Download the combined report
                const filename = `combined-checksec-report-${new Date().toISOString().split('T')[0]}`;
                const blob = new Blob([combinedSarif], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${filename}.sarif`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                
                combinedButton.innerHTML = '<span>Combined report downloaded</span>';
            } catch (err) {
                console.error('Failed to generate combined SARIF report:', err);
                combinedButton.innerHTML = '<span>Error - Try Again</span>';
            }
        });
        
        // Insert SARIF button before close all button
        buttonContainer.insertBefore(combinedButton, closeAllButton);
    }
    
    // Position the button container above the tabs
    tabsContainer.insertBefore(buttonContainer, tabsHeader);
}

function updateCombinedButtonCount(button) {
    const successfulResults = [];
    tabResults.forEach((entry, tabIndex) => {
        if (!(entry.blob.binarytype === "Error")) {
            successfulResults.push({file: entry.filename, blobs: [entry.blob], libraries: []});
        }
    });
    
    button.innerHTML = `<span>Download Combined SARIF Report (${successfulResults.length} files)</span>`;
    button.disabled = false;
}