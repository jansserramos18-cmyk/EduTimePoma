document.getElementById('buscador').addEventListener('input', function() {
            const query = this.value.toLowerCase();
            const navItems = document.querySelectorAll('#sidebar-nav .nav-item');
            navItems.forEach(item => {
                const text = item.textContent.toLowerCase();
                if (text.includes(query)) {
                    item.style.display = '';
                } else {
                    item.style.display = 'none';
                }
            });
        });