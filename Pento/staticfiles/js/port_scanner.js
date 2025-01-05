// static/js/port_scanner.js

document.addEventListener("DOMContentLoaded", function () {
    const scanForm = document.getElementById("nmap-scan-form");
    const mainContent = document.getElementById("main-content");

    scanForm.addEventListener("submit", function (event) {
        event.preventDefault(); // Prevent the default form submission

        // Collect form data
        const formData = new FormData(scanForm);
        const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;

        // Disable the Run Scan button to prevent multiple submissions
        const runScanButton = scanForm.querySelector('button[type="submit"]');
        runScanButton.disabled = true;
        runScanButton.textContent = "Running Scan...";

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
                    // Load the progress page dynamically
                    loadProgressPage(scanId);
                } else if (data.error) {
                    alert(`Error: ${data.error}`);
                    runScanButton.disabled = false;
                    runScanButton.textContent = "Run Scan";
                }
            })
            .catch(error => {
                console.error("Error initiating scan:", error);
                alert("An error occurred while starting the scan.");
                runScanButton.disabled = false;
                runScanButton.textContent = "Run Scan";
            });
    });

    function loadProgressPage(scanId) {
        // Fetch the progress.html template
        fetch('/static/templates/tools/progress.html') // Adjust the path if necessary
            .then(response => response.text())
            .then(html => {
                mainContent.innerHTML = html;
                // Start polling for progress and terminal output
                startPolling(scanId);
            })
            .catch(error => {
                console.error("Error loading progress page:", error);
                alert("An error occurred while loading the progress page.");
            });
    }

    function startPolling(scanId) {
        const progressBarFill = document.getElementById("progress-bar-fill");
        const progressText = document.getElementById("progress-text");
        const terminal = document.getElementById("terminal");

        const pollInterval = setInterval(() => {
            fetch(`/scan_progress/${scanId}/`)
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        console.error("Error fetching scan progress:", data.error);
                        clearInterval(pollInterval);
                        alert("An error occurred while fetching scan progress.");
                        return;
                    }

                    // Update progress bar
                    const progress = data.progress;
                    progressBarFill.style.width = `${progress}%`;
                    progressBarFill.textContent = `${progress}%`;
                    progressText.textContent = `${progress}%`;

                    // Append new terminal output
                    if (data.terminal_output) {
                        terminal.textContent = data.terminal_output;
                        terminal.scrollTop = terminal.scrollHeight; // Auto-scroll to bottom
                    }

                    // Check if scan is completed
                    if (data.status === 'completed') {
                        clearInterval(pollInterval);
                        // Load the results page
                        loadResultsPage(scanId);
                    } else if (data.status === 'failed') {
                        clearInterval(pollInterval);
                        alert("Scan failed. Please check the terminal output for details.");
                        // Optionally, reload the scan page or reset the form
                        loadScanForm();
                    }
                })
                .catch(error => {
                    console.error("Error polling scan progress:", error);
                    clearInterval(pollInterval);
                    alert("An error occurred while polling scan progress.");
                });
        }, 1000); // Poll every second
    }

    function loadResultsPage(scanId) {
        // Fetch the scan result from the backend
        fetch(`/scan_result/${scanId}/`)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    console.error("Error fetching scan result:", data.error);
                    alert("An error occurred while fetching scan results.");
                    return;
                }

                // Fetch the result.html template
                fetch('/static/templates/tools/result.html') // Adjust the path if necessary
                    .then(response => response.text())
                    .then(html => {
                        // Replace {{ result }} with actual result data
                        const resultHtml = html.replace("{{ result }}", data.result);
                        mainContent.innerHTML = resultHtml;
                    })
                    .catch(error => {
                        console.error("Error loading results page:", error);
                        alert("An error occurred while loading the results page.");
                    });
            })
            .catch(error => {
                console.error("Error fetching scan result:", error);
                alert("An error occurred while fetching scan results.");
            });
    }

    function loadScanForm() {
        // Reload the port scanner form
        fetch('/port_scanner/') // Adjust the path if necessary
            .then(response => response.text())
            .then(html => {
                mainContent.innerHTML = html;
            })
            .catch(error => {
                console.error("Error loading scan form:", error);
                alert("An error occurred while loading the scan form.");
            });
    }
});
