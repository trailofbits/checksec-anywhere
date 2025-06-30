import init from "./pkg/checksec.js";
import { handleFiles, setupFileInputListeners } from './fileHandler.js';
import { loadReportFromURL } from './share.js';
import { setupUrlInputListeners } from './urlHandler.js';
import { showError } from './utils.js';

// Initialize WASM and check for shared reports
init().then(async () => {
    await loadReportFromURL();
}).catch(err => {
    console.error("Failed to initialize WASM:", err);
    showError("Failed to initialize application");
});

// Set up file input and URL input listeners
setupFileInputListeners();
setupUrlInputListeners();