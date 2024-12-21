document.addEventListener('DOMContentLoaded', function () {
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const toolsList = document.getElementById('tools-list');

    // Toggle visibility of the tools list
    sidebarToggle.addEventListener('click', function () {
        toolsList.classList.toggle('hidden');
    });
});
