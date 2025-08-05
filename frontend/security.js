// Security class handlers for different security features
export function getRelroClass(value) {
    const relroMap = {
        'Full': 'secure',
        'Partial': 'partial',
        'None': 'insecure'
    };
    return relroMap[value] || 'info';
}

export function getAslrClass(value) {
    const aslrMap = {
        'HighEntropyVa': 'secure',
        'DynamicBase': 'partial',
        'None': 'insecure'
    };
    return aslrMap[value] || 'info';
}

export function getNxClass(value) {
    const nxMap = {
        'Enabled': 'secure',
        'na': 'info',
        'Disabled': 'insecure'
    };
    return nxMap[value] || 'info';
}

export function getPieClass(value) {
    if (value === 'PIE') return 'secure';
    if (value === 'DSO' || value === 'REL') return 'partial';
    if (value === 'None') return 'insecure';
    return 'info';
}

export function getFortifyClass(value) {
    const fortifyMap = {
        'Full': 'secure',
        'Partial': 'partial',
        'None': 'insecure'
    };
    return fortifyMap[value] || 'info';
}

export function getPathClass(value) {
    // Special handling for rpath/runpath - None values should be green (secure)
    if (Array.isArray(value.paths) && value.paths.length === 1) {
        const path_elem = value.paths[0];
        if (typeof path_elem === "string" && path_elem === "None") {
            return 'secure';
        }
    }
    return value.paths.length > 0 ? 'insecure' : 'secure';
}

export function getBooleanClass(key, value) {
    if (key === 'asan'){
        return value ? 'insecure': 'secure';
    }
    if (key == 'dyn_linking'){
        return 'info';
    }
    return value ? 'secure' : 'insecure';
}

// Main security class determination function
export function getSecurityClass(key, value) {
    // Handle different value types and security features
    if (typeof value === 'boolean') {
        return getBooleanClass(key, value);
    }

    // Security feature specific handlers
    const securityHandlers = {
        'relro': getRelroClass,
        'aslr': getAslrClass,
        'nx': getNxClass,
        'pie': getPieClass,
        'fortify': getFortifyClass,
        'rpath': getPathClass,
        'runpath': getPathClass
    };

    if (securityHandlers[key]) {
        return securityHandlers[key](value);
    }
    
    if (typeof value === 'number') {
        return 'info';
    }
    
    return 'info';
}

export function formatSecurityValue(key, value) {
    if (typeof value === 'boolean') {
        return value ? 'Enabled' : 'Disabled';
    }
    
    if (key === 'rpath' || key === 'runpath') {
        if (Array.isArray(value.paths) && value.paths.length === 1) {
            const path_elem = value.paths[0];
            if (typeof(path_elem) === "string"){
                if (path_elem === "None"){
                    return 'None';
                }
            }
        }
        if (value.paths.length > 0) {
            return `${value.paths.length} path(s)`;
        }
        return 'None';
    }
    
    if (Array.isArray(value)) {
        return `${value.length} entries`;
    }
    
    return String(value);
}

export function formatSecurityName(key) {
    const nameMap = {
        'filename': 'Filename',
        'sha256': 'SHA256 Hash',
        'canary': 'Stack Canary',
        'clang_cfi': 'Clang CFI',
        'clang_safestack': 'SafeStack',
        'stack_clash_protection': 'Stack Clash Protection',
        'fortify': 'Fortification',
        'fortified': 'Fortified Functions',
        'fortifiable': 'Fortifiable Functions',
        'nx': 'NX Bit',
        'pie': 'Position Independent Executable',
        'relro': 'RELRO',
        'rpath': 'RPATH',
        'runpath': 'RUNPATH',
        'dynlibs': 'Dynamic Libraries',
        'symbol_count': 'Symbol Count',
        'aslr': 'ASLR',
        'authenticode': 'Authenticode',
        'cfg': 'Control Flow Guard',
        'dotnet': '.NET Framework',
        'force_integrity': 'Force Integrity',
        'gs': 'Stack Canary (GS)',
        'high_entropy_va': 'High Entropy VA',
        'isolation': 'Process Isolation',
        'rfg': 'Return Flow Guard',
        'safeseh': 'Safe SEH',
        'seh': 'Structured Exception Handling',
        'cet': 'CET Compatible',
        'arc': 'Automatic Reference Counting',
        'code_signature': 'Code Signature',
        'encrypted': 'Binary Encryption',
        'restrict': 'Restrict Segment',
        'nx_heap': 'NX Heap',
        'nx_stack': 'NX Stack',
        'architecture': 'Architecture',
        'asan': 'Address Sanitizer',
        'bitness': 'Bitness',
        'endianness': 'Endianness',
        'dyn_linking': 'Dynamic Linking',
        'interpreter': 'Interpreter Path',
        'seperate_code': 'Code/Data Separation',
    };
    
    return nameMap[key];
} 