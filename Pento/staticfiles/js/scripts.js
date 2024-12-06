// JavaScript for handling modal functionality
document.addEventListener("DOMContentLoaded", function () {
    // Select all tool links
    const toolLinks = document.querySelectorAll("a[href^='/']");
    const modalOverlay = document.createElement("div");
    modalOverlay.classList.add("modal-overlay");
    document.body.appendChild(modalOverlay);

    // Open Modals
    toolLinks.forEach((link) => {
        link.addEventListener("click", function (e) {
            e.preventDefault();

            const url = link.getAttribute("href");

            // Fetch modal content
            fetch(url)
                .then((response) => response.text())
                .then((html) => {
                    const modal = document.createElement("div");
                    modal.classList.add("modal");
                    modal.innerHTML = html;

                    // Add close button
                    const closeButton = document.createElement("button");
                    closeButton.textContent = "Close";
                    closeButton.style.marginTop = "10px";
                    closeButton.addEventListener("click", () => {
                        modal.remove();
                        modalOverlay.classList.remove("overlay-active");
                    });

                    modal.appendChild(closeButton);
                    document.body.appendChild(modal);
                    modalOverlay.classList.add("overlay-active");
                })
                .catch((error) => console.error("Error loading modal content:", error));
        });
    });

    // Close modal when overlay is clicked
    modalOverlay.addEventListener("click", function () {
        const activeModal = document.querySelector(".modal");
        if (activeModal) activeModal.remove();
        modalOverlay.classList.remove("overlay-active");
    });
});
