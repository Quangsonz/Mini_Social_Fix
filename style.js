document.querySelectorAll('.menu-icon').forEach(function(icon) {
    icon.addEventListener('click', function(e) {
        e.stopPropagation();
        // Ẩn tất cả menu khác
        document.querySelectorAll('.menu-dropdown').forEach(function(menu) {
            menu.style.display = 'none';
        });
        // Hiện menu của post này
        var menu = this.nextElementSibling;
        if(menu) menu.style.display = 'block';
    });
});
// Ẩn menu khi click ra ngoài
window.addEventListener('click', function() {
    document.querySelectorAll('.menu-dropdown').forEach(function(menu) {
        menu.style.display = 'none';
    });
});



document.querySelectorAll('.edit-btn').forEach(function(btn) {
    btn.addEventListener('click', function(e) {
        e.preventDefault();
        var id = this.getAttribute('data-id');
        document.getElementById('content-' + id).style.display = 'none';
        document.getElementById('form-' + id).style.display = 'block';
    });
});
document.querySelectorAll('.cancel-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
        var id = this.getAttribute('data-id');
        document.getElementById('form-' + id).style.display = 'none';
        document.getElementById('content-' + id).style.display = 'block';
    });
});

