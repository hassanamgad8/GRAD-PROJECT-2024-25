document.addEventListener("DOMContentLoaded", function () {
    const canvas = document.getElementById('matrix');
    const ctx = canvas.getContext('2d');

    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    const characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    const fontSize = 16;
    const columns = Math.floor(canvas.width / fontSize);
    const drops = Array(columns).fill(1);

    function drawMatrix() {
        ctx.fillStyle = 'rgba(0, 0, 0, 0.08)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#00FF33';
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

    const modalOverlay = document.createElement('div');
    modalOverlay.classList.add('modal-overlay');
    document.body.appendChild(modalOverlay);

    const toolLinks = document.querySelectorAll('.tool-link');

    toolLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();

            const url = link.getAttribute('href');
            fetch(url)
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP error! Status: ${response.status}`);
                    }
                    return response.text();
                })
                .then(html => {
                    const modal = document.createElement('div');
                    modal.classList.add('modal');
                    modal.innerHTML = html;

                    const closeButton = document.createElement('button');
                    closeButton.textContent = 'Close';
                    closeButton.classList.add('modal-close');
                    closeButton.addEventListener('click', closeModal);

                    modal.appendChild(closeButton);
                    document.body.appendChild(modal);
                    modalOverlay.classList.add('active');
                })
                .catch(error => console.error('Error loading modal content:', error));
        });
    });

    modalOverlay.addEventListener('click', closeModal);

    function closeModal() {
        const activeModal = document.querySelector('.modal');
        if (activeModal) activeModal.remove();
        modalOverlay.classList.remove('active');
    }
});
