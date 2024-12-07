document.addEventListener("DOMContentLoaded", function () {
    // Create the canvas for the Matrix rain effect
    const canvas = document.createElement('canvas');
    document.body.appendChild(canvas);
    
    const ctx = canvas.getContext('2d');

    // Set initial canvas size to full screen
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    // Characters for the matrix rain effect
    const characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    const fontSize = 16;
    const scale = 1; // Scale factor to zoom in or out the effect
    const columns = Math.floor(canvas.width / fontSize); // Number of columns for the matrix effect
    const drops = Array(columns).fill(1);  // Initial drop positions

    // Draw the matrix rain effect
    function draw() {
        ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';  // Light background fill for each frame
        ctx.fillRect(0, 0, canvas.width, canvas.height);  // Clear the canvas

        ctx.fillStyle = '#0f0';  // Green color for the matrix
        ctx.font = `${fontSize}px monospace`;  // Font size for the characters

        drops.forEach((y, index) => {
            const text = characters[Math.floor(Math.random() * characters.length)];
            ctx.fillText(text, index * fontSize, y * fontSize);  // Draw the characters

            // Reset the drop when it reaches the bottom
            if (y * fontSize > canvas.height && Math.random() > 0.95) {
                drops[index] = 0;
            }

            drops[index]++;  // Increment drop position
        });
    }

    setInterval(draw, 50);  // Redraw the matrix effect every 50ms

    // Ensure canvas resizes correctly with the window size
    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });


    // Modal functionality for clicking on the tool links
    const toolLinks = document.querySelectorAll("a[href^='/']");
    const modalOverlay = document.createElement("div");
    modalOverlay.classList.add("modal-overlay");
    document.body.appendChild(modalOverlay);

    toolLinks.forEach((link) => {
        link.addEventListener("click", function (e) {
            e.preventDefault();

            // Check if a modal is already open
            if (document.querySelector('.modal')) return;

            const url = link.getAttribute("href");

            fetch(url)
                .then((response) => response.text())
                .then((html) => {
                    const modal = document.createElement("div");
                    modal.classList.add("modal");
                    modal.innerHTML = html;

                    const closeButton = document.createElement("button");
                    closeButton.textContent = "Close";
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

    modalOverlay.addEventListener("click", function () {
        const activeModal = document.querySelector(".modal");
        if (activeModal) activeModal.remove();
        modalOverlay.classList.remove("overlay-active");
    });
});

// CSS for layering the Matrix rain effect as the wallpaper
const style = document.createElement('style');
style.innerHTML = `
    body {
        position: relative;
        margin: 0;
        padding: 0;
        overflow: hidden;
        height: 100vh;  /* Ensure the body takes the full screen height */
        background-color: black;  /* Optional: Sets a fallback background color */
    }

    canvas {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: -1;  /* Ensure the canvas stays behind all content */
    }

    .modal-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.9); /* Darker overlay for modal */
        display: none;
        z-index: 10; /* Overlay above content */
    }

    .overlay-active {
        display: block;
    }

    .modal {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background-color: black; /* Dark background for modal */
        color: white;  /* White text in modal */
        padding: 20px;
        border-radius: 10px;
        z-index: 20; /* Modal above overlay */
        width: 80%;
        max-width: 700px;
        overflow-y: auto; /* Ensures modal content is scrollable if too large */
    }

    .modal button {
        margin-top: 10px;
        padding: 10px;
        background-color: #333;
        color: white;
        border: none;
        cursor: pointer;
        border-radius: 5px;
    }

    .modal button:hover {
        background-color: #444;
    }

    /* Styling for the content */
    header {
        text-align: center;
        margin-top: 20px;
        z-index: 100;  /* Ensure the header stays on top of the canvas */
    }

    h1 {
        font-size: 2em;
        color: #fff;
    }

    ul {
        list-style-type: none;
        padding: 0;
        text-align: center;
        z-index: 100; /* Ensure the list stays above the canvas */
    }

    ul li {
        display: inline-block;
        margin: 10px;
    }

    ul li a {
        font-size: 1.5em;
        color: #fff;
        text-decoration: none;
    }

    ul li a img {
        width: 50px;
        vertical-align: middle;
        margin-right: 10px;
    }
`;
document.head.appendChild(style);
