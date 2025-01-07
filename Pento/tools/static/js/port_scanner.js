// static/js/port_scanner.js

// Define the initialization function
function initializePortScanner() {
    const scanForm = document.getElementById("nmap-scan-form");
    if (scanForm) {
        scanForm.addEventListener("submit", function (event) {
            event.preventDefault(); // Prevent the default form submission

            // Collect form data
            const formData = new FormData(scanForm);
            const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;

            // Disable the Run Scan button to prevent multiple submissions
            const runScanButton = scanForm.querySelector('button[type="submit"]');
            runScanButton.disabled = true;
            runScanButton.textContent = "Running Scan...";

            // Hide previous results if any
            document.getElementById("scan-result-container").style.display = "none";
            document.getElementById("scan-result").textContent = "";
            document.getElementById("terminal").textContent = "";

            // Show the progress container
            const progressContainer = document.getElementById("progress-container");
            const terminal = document.getElementById("terminal");
            progressContainer.style.display = "block";

            // Reset progress bar
            const progressBarFill = document.getElementById("progress-bar-fill");
            const progressText = document.getElementById("progress-text");
            progressBarFill.style.width = "0%";
            progressBarFill.textContent = "0%";
            progressText.textContent = "0%";

            // Send the scan request via AJAX
            fetch(scanForm.action, {
                method: "POST",
                headers: {
                    "X-CSRFToken": csrfToken,
                },
                body: formData,
            })
                .then(response => response.json())
                .then(data => {
                    if (data.scan_id) {
                        const scanId = data.scan_id;
                        // Start polling for progress and terminal output
                        startPolling(scanId, progressBarFill, progressText, terminal, runScanButton);
                    } else if (data.error) {
                        alert(`Error: ${data.error}`);
                        runScanButton.disabled = false;
                        runScanButton.textContent = "Run Scan";
                        progressContainer.style.display = "none";
                    }
                })
                .catch(error => {
                    console.error("Error initiating scan:", error);
                    alert("An error occurred while starting the scan.");
                    runScanButton.disabled = false;
                    runScanButton.textContent = "Run Scan";
                    progressContainer.style.display = "none";
                });
        });
    }
}

// Define the polling function
function startPolling(scanId, progressBarFill, progressText, terminal, runScanButton) {
    const pollInterval = setInterval(() => {
        fetch(`/scan_progress/${scanId}/`)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    console.error("Error fetching scan progress:", data.error);
                    clearInterval(pollInterval);
                    alert("An error occurred while fetching scan progress.");
                    runScanButton.disabled = false;
                    runScanButton.textContent = "Run Scan";
                    document.getElementById("progress-container").style.display = "none";
                    return;
                }

                // Update progress bar
                const progress = data.progress;
                progressBarFill.style.width = `${progress}%`;
                progressBarFill.textContent = `${progress}%`;
                progressText.textContent = `${progress}%`;

                // Update terminal output
                if (data.terminal_output) {
                    terminal.textContent = data.terminal_output;
                    terminal.scrollTop = terminal.scrollHeight; // Auto-scroll to bottom
                }

                // Check if scan is completed
                if (data.status === 'completed') {
                    clearInterval(pollInterval);
                    // Hide the progress container
                    document.getElementById("progress-container").style.display = "none";
                    // Show the scan result container
                    const scanResultContainer = document.getElementById("scan-result-container");
                    scanResultContainer.style.display = "block";
                    // Load the scan result
                    loadResultsPage(scanId, scanResultContainer, runScanButton);
                } else if (data.status === 'failed') {
                    clearInterval(pollInterval);
                    alert("Scan failed. Please check the terminal output for details.");
                    // Re-enable the Run Scan button
                    runScanButton.disabled = false;
                    runScanButton.textContent = "Run Scan";
                    // Hide the progress container
                    document.getElementById("progress-container").style.display = "none";
                }
            })
            .catch(error => {
                console.error("Error polling scan progress:", error);
                clearInterval(pollInterval);
                alert("An error occurred while polling scan progress.");
                runScanButton.disabled = false;
                runScanButton.textContent = "Run Scan";
                document.getElementById("progress-container").style.display = "none";
            });
    }, 1000); // Poll every second
}

// Define the function to load results
function loadResultsPage(scanId, scanResultContainer, runScanButton) {
    fetch(`/scan_result/${scanId}/`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error("Error fetching scan result:", data.error);
                alert("An error occurred while fetching scan results.");
                return;
            }

            // Populate the scan result
            const scanResult = document.getElementById("scan-result");
            scanResult.textContent = data.result;

            // Re-enable the Run Scan button
            runScanButton.disabled = false;
            runScanButton.textContent = "Run Scan";
        })
        .catch(error => {
            console.error("Error fetching scan result:", error);
            alert("An error occurred while fetching scan results.");
            // Re-enable the Run Scan button
            runScanButton.disabled = false;
            runScanButton.textContent = "Run Scan";
        });
}

// Initialize the port scanner when the script is loaded
initializePortScanner();
