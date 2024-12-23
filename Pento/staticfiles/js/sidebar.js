document.addEventListener('DOMContentLoaded', function () {
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const toolsList = document.getElementById('tools-list');

    // Toggle visibility of the tools list
    sidebarToggle.addEventListener('click', function () {
        toolsList.classList.toggle('hidden');
    });

    // Sidebar functionality (from previous script)
    const sidebar = document.querySelector('.sidebar');
    if (sidebar) {
        sidebarToggle.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
        });
    }
});
