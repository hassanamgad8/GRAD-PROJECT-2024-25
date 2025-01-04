// port_scanner.js

document.addEventListener("DOMContentLoaded", function () {
    console.log("port_scanner.js loaded successfully.");

    const form = document.getElementById("nmap-scan-form");
    const progressContainer = document.getElementById("progress-container");
    const progressBarFill = document.getElementById("progress-bar-fill");
    const progressText = document.getElementById("progress-text");
    const scanResult = document.getElementById("scan-result");
    const resultContent = document.getElementById("result-content");

    if (!form) {
        console.error("Form with ID 'nmap-scan-form' not found.");
        return;
    }

    form.addEventListener("submit", function (event) {
        event.preventDefault(); // Prevent the default form submission

        // Hide previous results and reset progress bar
        scanResult.style.display = "none";
        progressContainer.style.display = "block";
        progressBarFill.style.width = "0%";
        progressBarFill.textContent = "0%";
        progressText.textContent = "0%";

        // Gather form data
        const formData = new FormData(form);

        // Get CSRF token from cookies
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

        // Initiate the scan via AJAX
        fetch("/port_scanner/", {
            method: 'POST',
            body: formData,
            headers: {
                "X-CSRFToken": csrftoken,
            },
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.scan_id) {
                const scanId = data.scan_id;
                console.log(`Scan initiated with ID: ${scanId}`);
                // Start polling for progress
                pollProgress(scanId);
            } else if (data.error) {
                alert(`Error: ${data.error}`);
                progressContainer.style.display = "none";
            }
        })
        .catch(error => {
            console.error('Error initiating scan:', error);
            alert('Error initiating scan.');
            progressContainer.style.display = "none";
        });
    });

    // Function to poll for scan progress
    function pollProgress(scanId) {
        const progressUrl = `/scan_progress/${scanId}/`;
        const resultUrl = `/scan_result/${scanId}/`;

        const intervalId = setInterval(() => {
            fetch(progressUrl)
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        clearInterval(intervalId);
                        progressText.textContent = `Error: ${data.error}`;
                        progressBarFill.style.backgroundColor = "#f44336"; // Red color for errors
                        progressContainer.style.display = "none";
                        return;
                    }

                    const progress = data.progress;
                    const status = data.status;

                    progressBarFill.style.width = `${progress}%`;
                    progressBarFill.textContent = `${progress}%`;
                    progressText.textContent = `${progress}%`;

                    if (status === 'completed') {
                        clearInterval(intervalId);
                        console.log(`Scan ${scanId} completed.`);
                        // Fetch and display the result
                        fetch(resultUrl)
                            .then(response => response.json())
                            .then(resultData => {
                                if (resultData.result) {
                                    scanResult.style.display = "block";
                                    resultContent.textContent = resultData.result;
                                } else if (resultData.error) {
                                    progressText.textContent = `Error: ${resultData.error}`;
                                    progressBarFill.style.backgroundColor = "#f44336";
                                    progressContainer.style.display = "none";
                                }
                            })
                            .catch(error => {
                                console.error('Error fetching result:', error);
                                progressText.textContent = 'Error fetching result.';
                                progressContainer.style.display = "none";
                            });
                    } else if (status === 'failed') {
                        clearInterval(intervalId);
                        progressText.textContent = `Scan Failed: ${status}`;
                        progressBarFill.style.backgroundColor = "#f44336"; // Red color for errors
                        progressContainer.style.display = "none";
                    }
                })
                .catch(error => {
                    console.error('Error fetching progress:', error);
                    progressText.textContent = 'Error fetching progress.';
                    progressContainer.style.display = "none";
                });
        }, 1000); // Poll every second
    }
});
