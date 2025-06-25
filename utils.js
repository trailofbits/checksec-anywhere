export function showError(message) {
    const error = document.getElementById("error");
    const loading = document.getElementById("loading");
    error.textContent = `Error: ${message}`;
    error.style.display = "block";
    loading.style.display = "none";
}

export function hideError() {
    const error = document.getElementById("error");
    error.style.display = "none";
}

export function addPathDetails(item, key, value) {
    if (value.paths.length > 0) {
        // Only show actual paths if they're not just "None"
        const actualPaths = value.paths.filter(path => {
            if (typeof path === 'string') {
                return path !== 'None';
            }
            if (typeof path === 'object') {
                const pathValue = Object.values(path)[0];
                return true;
            }
        });
        
        if (actualPaths.length > 0) {
            actualPaths.forEach(path => {
                const pathItem = document.createElement("div");
                pathItem.className = "list-details";    
                pathItem.textContent = `• ${Object.values(path)[0]}`;
                item.appendChild(pathItem);
            });
        }
    }
}

export function addDynLibDetails(item, library_list) {
    library_list.forEach(lib => {
        const libItem = document.createElement("div");
        libItem.className = "list-details";
        libItem.textContent = `• ${lib}`;
        item.appendChild(libItem);
    });
} 