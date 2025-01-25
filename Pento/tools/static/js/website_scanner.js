document.addEventListener("DOMContentLoaded", () => {
    const progressBarFill = document.getElementById("progress-bar-fill");
    const statusElement = document.getElementById("status");
    const terminalOutput = document.getElementById("terminal-output");

    function updateProgress() {
        fetch(`/website-scanner/progress/api/${scanId}/`)
            .then((response) => response.json())
            .then((data) => {
                if (data.error) {
                    console.error(data.error);
                    terminalOutput.textContent += "\nError: " + data.error;
                    return;
                }

                // Update progress bar
                progressBarFill.style.width = `${data.progress}%`;
                progressBarFill.textContent = `${data.progress}%`;

                // Update status
                statusElement.textContent = data.status;

                // Update terminal output
                if (data.terminal_output) {
                    terminalOutput.textContent = data.terminal_output;
                    terminalOutput.scrollTop = terminalOutput.scrollHeight; // Scroll to the bottom
                }

                // Redirect to results page if the scan is completed
                if (data.status === "completed") {
                    clearInterval(progressInterval);
                    window.location.href = `/website-scanner/results/${scanId}/`;
                } else if (data.status === "failed") {
                    clearInterval(progressInterval);
                    terminalOutput.textContent += "\nScan failed!";
                }
            })
            .catch((error) => console.error("Error updating progress:", error));
    }

    // Poll the progress API every 3 seconds
    const progressInterval = setInterval(updateProgress, 3000);
    updateProgress(); // Initial call
});
