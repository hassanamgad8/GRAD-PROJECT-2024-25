// Add console log to verify script is loaded
console.log('Debug: google.js loaded');

const DORK_QUERIES = [
    {
        name: "SQL errors",
        query: 'intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"'
    },
    {
        name: "Publicly exposed documents",
        query: "ext:doc | ext:docx | ext:odt | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv"
    },
    {
        name: "Directory listing vulnerabilities",
        query: "intitle:index.of"
    },
    {
        name: "Configuration files exposed",
        query: "ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini | ext:env | ext:yml | ext:json"
    },
    {
        name: "Database files exposed",
        query: "ext:sql | ext:dbf | ext:mdb"
    },
    {
        name: "Log files exposed",
        query: "ext:log"
    },
    {
        name: "Backup and old files",
        query: "ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup"
    },
    {
        name: "Login pages",
        query: 'inurl:login | inurl:signin | intitle:Login | intitle:"sign in" | inurl:auth'
    },
    {
        name: "Find Subdomains",
        query: "site:*."
    },
    {
        name: "Find Sub-Subdomains",
        query: "site:*.*."
    },
    {
        name: "PHP errors / warnings",
        query: '"PHP Parse error" | "PHP Warning" | "PHP Error"'
    },
    {
        name: "Search Pastebin.com",
        query: 'site:pastebin.com | site:paste2.org | site:pastehtml.com | site:slexy.org | site:snipplr.com | site:snipt.net | site:textsnip.com | site:bitpaste.app | site:justpaste.it | site:heypasteit.com | site:hastebin.com | site:dpaste.org | site:dpaste.com | site:codepad.org | site:jsitor.com | site:codepen.io | site:jsfiddle.net | site:dotnetfiddle.net | site:phpfiddle.org | site:ide.geeksforgeeks.org | site:repl.it | site:ideone.com | site:paste.debian.net | site:paste.org | site:paste.org.ru | site:codebeautify.org  | site:codeshare.io | site:trello.com'
    },
    {
        name: "phpinfo()",
        query: 'ext:php intitle:phpinfo "published by the PHP Group"'
    },
    {
        name: "Search Github.com",
        query: "site:github.com | site:gitlab.com"
    },
    {
        name: "Search Stackoverflow.com",
        query: "site:stackoverflow.com"
    },
    {
        name: "Signup pages",
        query: "inurl:signup | inurl:register | intitle:Signup"
    },
    {
        name: "Search in WaybackMachine",
        query: "",
        isWayback: true
    },
    {
        name: "Find IP addresses",
        query: "site:*.*.29.* |site:*.*.28.* |site:*.*.27.* |site:*.*.26.* |site:*.*.25.* |site:*.*.24.* |site:*.*.23.* |site:*.*.22.* |site:*.*.21.* |site:*.*.20.* |site:*.*.19.* |site:*.*.18.* |site:*.*.17.* |site:*.*.16.* |site:*.*.15.* |site:*.*.14.* |site:*.*.13.* |site:*.*.12.* |site:*.*.11.* |site:*.*.10.* |site:*.*.9.* |site:*.*.8.* |site:*.*.7.* |site:*.*.6.* |site:*.*.5.* |site:*.*.4.* |site:*.*.3.* |site:*.*.2.* |site:*.*.1.* |site:*.*.0.*",
        multiTab: true
    }
];

// The rest of your code remains the same
function createDorkButtons() {
    console.log('Debug: Creating buttons...');
    const container = document.getElementById('dorkButtons');
    
    if (!container) {
        console.error('Error: dorkButtons container not found!');
        return;
    }

    // Clear any existing content (including debug message)
    container.innerHTML = '';
    
    DORK_QUERIES.forEach((dork, index) => {
        console.log(`Debug: Creating button ${index + 1}: ${dork.name}`);
        const button = document.createElement('button');
        button.className = 'dork-button';
        
        const icon = document.createElement('span');
        icon.className = 'search-icon';
        icon.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>`;
        
        const text = document.createElement('span');
        text.className = 'button-text';
        text.textContent = dork.name;
        
        button.appendChild(icon);
        button.appendChild(text);
        
        button.addEventListener('click', () => handleSearch(dork));
        container.appendChild(button);
    });
    
    console.log('Debug: Button creation complete');
}

function handleSearch(dork) {
    const target = document.getElementById('target').value;
    if (!target) {
        alert('Please enter a target domain');
        return;
    }
    
    if (dork.isWayback) {
        window.open(`https://web.archive.org/web/*/${target}/*`, '_blank');
        return;
    }

    if (dork.multiTab) {
        const queries = dork.query.split('|');
        queries.forEach(q => {
            const url = `https://www.google.com/search?q=${encodeURIComponent(`(${target}) ${q.trim()}`)}`;
            window.open(url, '_blank');
        });
    } else {
        const baseQuery = `site:${target} ${dork.query}`;
        const googleUrl = `https://www.google.com/search?q=${encodeURIComponent(baseQuery)}`;
        window.open(googleUrl, '_blank');
    }
}

// Add both event listeners to ensure the function runs
document.addEventListener('DOMContentLoaded', () => {
    console.log('Debug: DOMContentLoaded event fired');
    createDorkButtons();
});

// Backup in case DOMContentLoaded doesn't fire
window.onload = () => {
    console.log('Debug: window.onload event fired');
    if (!document.querySelector('.dork-button')) {
        console.log('Debug: No buttons found, creating them...');
        createDorkButtons();
    }
};

// Immediate execution attempt
if (document.readyState === 'complete') {
    console.log('Debug: Document already complete, creating buttons immediately');
    createDorkButtons();
}