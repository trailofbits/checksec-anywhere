import { getSecurityClass, formatSecurityValue, formatSecurityName } from './security.js';
import { addPathDetails, addDynLibDetails } from './utils.js';
import { generateShareableURL, copyToClipboard } from './share.js';
import { generate_sarif_report } from './pkg/checksec.js';

const tabsContainer = document.getElementById("tabsContainer");
const tabsHeader = document.getElementById("tabsHeader");
const tabsContent = document.getElementById("tabsContent");

export function displayFileHeader(binaryType, bitness, filename, container) {
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

    container.innerHTML = `<h2>${binary_str} (${bitness} bit) Security Analysis - ${filename}</h2>`;
    
    const fileTypeItem = document.createElement("li");
    fileTypeItem.className = "security-item";
    fileTypeItem.innerHTML = `
        <div class="security-item-main">
            <span class="security-name">File Type</span>
            <span class="security-value info">${binary_str}</span>
        </div>
    `;
    container.appendChild(fileTypeItem);
    return binary_str;
}

export function displayFileRow(filename, container) {
    const filenameItem = document.createElement("li");
    filenameItem.className = "security-item";
    filenameItem.innerHTML = `
        <div class="security-item-main">
            <span class="security-name">Filename</span>
            <span class="security-value info">${filename}</span>
        </div>
    `;
    container.appendChild(filenameItem);
}

export function displayBinaryData(binaryData, container) {
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
        
        container.appendChild(item);
    }
}

export function displayShareFunctionality(result, container) {
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

export function display_error_handler(filename, error_msg, container){
    container.innerHTML = `
    <h2>Analysis Failed - ${filename}</h2>
    <div class="error-message">
        <p><strong>Error:</strong> ${error_msg}</p>
    </div>
`;
}

export function setupResultTab(filename){
    const index = document.querySelectorAll(".tab-button").length;
    // Create tab button
    const tabButton = document.createElement("button");
    tabButton.className = "tab-button";
    tabButton.innerHTML = `
        <span class="tab-text">${filename}</span>
        <span class="tab-close" title="Close tab">×</span>
    `;
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
    
    let closedIndex = tabButton.dataset.tabIndex;

    
    // Remove the tab and content
    tabButton.remove();
    tabContent.remove();
    
    // Update tab indices for remaining tabs trying to activate next tab
    updateTabIndices();
    
    // If no tabs left, hide the tabs container
    if (tabsHeader.children.length === 0) {
        tabsContainer.style.display = 'none';
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

export function displayResultV1(result, container) {
    container.innerHTML = "";

    const [binaryType, binaryData] = Object.entries(result.data)[0];
    
    displayFileHeader(binaryType, binaryData.bitness, result.filename, container);
    displayFileRow(result.filename, container);
    displayBinaryData(binaryData, container);
    displayShareFunctionality(result, container);
}

export function displayResult(entry, isSharedReport = false) {
    let display_result_handler = null;
    switch (entry.result.version) {
        case '0.1.0':
            display_result_handler = displayResultV1
            break;
        default:
            console.warn(`Unknown version ${entry.result.version}, falling back to v1 display`);
            display_result_handler = displayResultV1;
    }

    let filename = "";
    if (!isSharedReport) { 
        filename = entry.file.name // use provided filename, as checksec may error out
    }
    else {
        filename = entry.result.filename // use filename reported in shared url
    }

    let container = setupResultTab(filename);

    if (entry.success) {
        display_result_handler(entry.result, container);
    }
    else {
        display_error_handler(filename, entry.result.error, container);
    }
}

export function displayResults(batchResults, isSharedReport = false) {

    batchResults.forEach(entry => {
        displayResult(entry, isSharedReport)
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
}