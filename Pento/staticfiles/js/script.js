document.addEventListener("DOMContentLoaded", function () {
    const newScanBtn = document.getElementById("new-scan-btn");
    const reportsBtn = document.getElementById("reports-btn");
    const dashboardBtn = document.getElementById("dashboard-btn");
    const mainContent = document.getElementById("main-content");
    const attackSurfaceBtn = document.getElementById("attack-surface-btn");
    const assetsBtn = document.getElementById("assets-btn");
    const findingsBtn = document.getElementById("findings-btn");




// Load Assets dynamically
assetsBtn.addEventListener("click", function () {
    mainContent.innerHTML = `
        <header class="dashboard-header">
            <h1>Assets</h1>
            <p class="assets-description">
                An Asset is a hostname or an IP address of the system you want to scan.
            </p>
        </header>
        <table class="data-table">
            <thead>
                <tr>
                    <th>Hostname</th>
                    <th>IP Address</th>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Service</th>
                    <th>Technology</th>
                </tr>
            </thead>
            <tbody id="assets-data">
                <!-- Data will be dynamically loaded here -->
            </tbody>
        </table>
    `;

    // Fetch data for Assets
    fetch("/api/assets/")
        .then((response) => response.json())
        .then((data) => {
            const tableBody = document.getElementById("assets-data");
            if (data.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="6">No assets available.</td></tr>`;
            } else {
            tableBody.innerHTML = data
                .map(
                    (entry) => `
                <tr>
                        <td>${entry.hostname}</td>
                        <td>${entry.ip_address}</td>
                        <td>${entry.port_number || '-'}</td>
                        <td>${entry.protocol || '-'}</td>
                        <td>${entry.service || '-'}</td>
                        <td>${entry.technology.join(", ") || '-'}</td>
                    </tr>
                `
                )
                .join("");
            }
        })
        .catch((error) => {
            console.error("Error fetching assets data:", error);
        });
});

// Load Findings dynamically
findingsBtn.addEventListener("click", function () {
    mainContent.innerHTML = `
        <header class="dashboard-header">
            <h1>Findings</h1>
             <p class="description">
                Findings are the results of scans conducted to detect vulnerabilities.
            </p>
        </header>
        <table class="data-table">
            <thead>
                <tr>
                    <th>Description</th>
                    <th>Target</th>
                    <th>Risk Level</th>
                    <th>Source</th>
                    <th>Scan Date</th>
                </tr>
            </thead>
            <tbody id="findings-data">
                <!-- Data will be dynamically loaded here -->
            </tbody>
        </table>
    `;

    // Fetch data for Findings
    fetch("/api/findings/")
        .then((response) => response.json())
        .then((data) => {
            const tableBody = document.getElementById("findings-data");
            if (data.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="5">No findings available.</td></tr>`;
            } else {
                tableBody.innerHTML = data

                .map(
                    (entry) => `
                <tr>
                    <td>${entry.description}</td>
                    <td>${entry.target.hostname}</td>
                    <td>${entry.risk_level}</td>
                    <td>${entry.source}</td>
                    <td>${new Date(entry.scan_date).toLocaleString()}</td>
                </tr>
            `
                )
                .join("");
            }
        })
        .catch((error) => {
            console.error("Error fetching findings data:", error);
        });


    });


    // Load Attack Surface dynamically
    attackSurfaceBtn.addEventListener("click", function () {
        mainContent.innerHTML = `
            <header class="dashboard-header">
                <h1>Attack Surface</h1>
                <p class="attack-surface-description">
                    The Attack Surface contains a centralized view of all the hosts, ports, services, technologies,
                    and other information for the targets in your current workspace.
                </p>
            </header>
            <table class="attack-surface-table">
                <thead>
                    <tr>
                        <th>Hostname</th>
                        <th>IP Address</th>
                        <th>OS</th>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Service</th>
                        <th>URL</th>
                        <th>Technology</th>
                        <th>Screenshot</th>
                    </tr>
                </thead>
                <tbody id="attack-surface-data">
                    <!-- Data will be dynamically loaded here -->
                </tbody>
            </table>
        `;

        // Fetch data for the Attack Surface
        fetch("/api/attack-surface/")
            .then((response) => response.json())
            .then((data) => {
                const tableBody = document.getElementById("attack-surface-data");
                tableBody.innerHTML = data
                    .map(
                        (entry) => `
                        <tr>
                            <td>${entry.hostname}</td>
                            <td>${entry.ip_address}</td>
                            <td>${entry.os || '-'}</td>
                            <td>${entry.port}</td>
                            <td>${entry.protocol}</td>
                            <td>${entry.service || '-'}</td>
                            <td><a href="${entry.url}" target="_blank">${entry.url}</a></td>
                            <td>${entry.technology.join(", ")}</td>
                            <td>${entry.screenshot || '-'}</td>
                        </tr>
                    `
                    )
                    .join("");
            })
            .catch((error) => {
                console.error("Error fetching attack surface data:", error);
            });
    });

    // Matrix animation (visual effect)
    const canvas = document.getElementById("matrix");
    const ctx = canvas.getContext("2d");

    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    resizeCanvas();
    window.addEventListener("resize", resizeCanvas);

    const characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const fontSize = 16;
    const columns = Math.floor(canvas.width / fontSize);
    const drops = Array(columns).fill(1);

    function drawMatrix() {
        ctx.fillStyle = "rgba(0, 0, 0, 0.08)";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = "#00FF33";
        ctx.font = `${fontSize}px monospace`;

        drops.forEach((y, index) => {
            const text = characters[Math.floor(Math.random() * characters.length)];
            ctx.fillText(text, index * fontSize, y * fontSize);

            if (y * fontSize > canvas.height && Math.random() > 0.975) {
                drops[index] = 0;
            }
            drops[index]++;
        });
    }
    setInterval(drawMatrix, 50);

    // Function to load the Dashboard view
    function loadDashboard() {
        mainContent.innerHTML = `
            <header class="dashboard-header">
                <h1>Security Operations Center</h1>
                <div class="user-controls">
                    <span class="username">Admin</span>
                    <form action="/logout/" method="POST" class="logout-form">
                        <button type="submit" class="logout-button">Logout</button>
                    </form>
                </div>
            </header>
            <div class="attack-surface-summary">
                <h2>Attack Surface Summary</h2>
                <div class="summary-grid">
                    <div class="summary-card">
                        <h3 id="ip-address-count">0</h3>
                        <p>IP ADDRESS</p>
                    </div>
                    <div class="summary-card">
                        <h3 id="hostnames-count">0</h3>
                        <p>HOSTNAMES</p>
                    </div>
                    <div class="summary-card">
                        <h3 id="port-count">0</h3>
                        <p>PORT</p>
                    </div>
                    <div class="summary-card">
                        <h3 id="protocol-count">0</h3>
                        <p>PROTOCOL</p>
                    </div>
                    <div class="summary-card">
                        <h3 id="services-count">0</h3>
                        <p>SERVICES</p>
                    </div>
                    <div class="summary-card">
                        <h3 id="technologies-count">0</h3>
                        <p>TECHNOLOGIES</p>
                    </div>
                </div>
            </div>
            <div class="dashboard-grid">
                <div class="grid-item tool-stats">
                    <h2>Active Scans</h2>
                    <canvas id="active-scans-chart"></canvas>
                </div>
                <div class="grid-item recent-activity">
                    <h2>Recent Activity</h2>
                    <p>No recent activity available.</p>
                </div>
            </div>
        `;

        // Fetch data for the summary
        fetch("/api/dashboard-summary/")
            .then((response) => response.json())
            .then((data) => {
                document.getElementById("ip-address-count").textContent = data.ip_address_count;
                document.getElementById("hostnames-count").textContent = data.hostnames_count;
                document.getElementById("port-count").textContent = data.port_count;
                document.getElementById("protocol-count").textContent = data.protocol_count;
                document.getElementById("services-count").textContent = data.services_count;
                document.getElementById("technologies-count").textContent = data.technologies_count;
            })
            .catch((error) => {
                console.error("Error fetching dashboard summary:", error);
            });

        loadChart(); // Reload chart when Dashboard loads
    }

    // Function to load New Scan view
    function loadNewScan() {
        mainContent.innerHTML = `
            <header class="dashboard-header">
                <h1>New Scan</h1>
                <p>Choose a tool below to start a new scan.</p>
            </header>
            <div class="tools-grid">
                <div class="tool-card">
                    <img src="{% static 'images/port-scanner-icon.png' %}" alt="Port Scanner Icon" class="tool-icon">
                    <h3>Port Scanner</h3>
                    <p>Detect open ports and fingerprint services.</p>
                </div>
                <div class="tool-card">
                    <img src="{% static 'images/domain-finder-icon.png' %}" alt="Domain Finder Icon" class="tool-icon">
                    <h3>Domain Finder</h3>
                    <p>Discover domains related to a target.</p>
                </div>
                <div class="tool-card">
                    <img src="{% static 'images/subdomain-finder-icon.png' %}" alt="Subdomain Finder Icon" class="tool-icon">
                    <h3>Subdomain Finder</h3>
                    <p>Discover subdomains of a domain.</p>
                </div>
                <div class="tool-card">
                    <img src="{% static 'images/website-scanner-icon.png' %}" alt="Website Scanner Icon" class="tool-icon">
                    <h3>Website Scanner</h3>
                    <p>Discover XSS, SQLi, RCE, and 70+ web application issues.</p>
                </div>
                <div class="tool-card">
                    <img src="{% static 'images/whois-lookup-icon.png' %}" alt="Whois Lookup Icon" class="tool-icon">
                    <h3>Whois Lookup</h3>
                    <p>Find the owner of a domain name or IP address and their contact data.</p>
                </div>
                <div class="tool-card">
                    <img src="{% static 'images/dns-lookup-icon.png' %}" alt="Dns Lookup Icon" class="tool-icon">
                    <h3>Dns Lookup</h3>
                    <p>Find the IP of a domain name .</p>
                </div>
            </div>
        `;
    

    }
    

    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }
    
    const csrftoken = getCookie('csrftoken');
    
    fetch('/logout/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrftoken,  // Include the CSRF token
        },
        body: JSON.stringify({}),
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => console.log(data))
    .catch(error => console.error('Error:', error));
    
    


    // Function to load Reports view
    function loadReports() {
        mainContent.innerHTML = `
            <header class="dashboard-header">
                <h1>Reports</h1>
            </header>
            <div class="reports-grid">
                <div class="report-card">
                    <h3>Port Scan</h3>
                    <p>Target: 192.168.1.1</p>
                    <p>Timestamp: 2024-12-30 12:00:00</p>
                    <a href="/download/port-scan-report.pdf" class="download-btn" download>Download</a>
                </div>
                <div class="report-card">
                    <h3>Website Scan</h3>
                    <p>Target: example.com</p>
                    <p>Timestamp: 2024-12-30 14:30:00</p>
                    <a href="/download/website-scan-report.pdf" class="download-btn" download>Download</a>
                </div>
            </div>
        `;
    }

    // Function to load Chart in Dashboard
    function loadChart() {
        const ctx = document.getElementById("active-scans-chart").getContext("2d");
        new Chart(ctx, {
            type: "bar",
            data: {
                labels: ["Running", "Queued", "Completed"],
                datasets: [
                    {
                        label: "# of Scans",
                        data: [3, 2, 5],
                        backgroundColor: ["#00FF00", "#FFFF00", "#FF0000"],
                    },
                ],
            },
        });
    }

    // Event Listeners
    newScanBtn.addEventListener("click", loadNewScan);
    reportsBtn.addEventListener("click", loadReports);
    dashboardBtn.addEventListener("click", loadDashboard);

    // Load Dashboard by default
    loadDashboard();
});
