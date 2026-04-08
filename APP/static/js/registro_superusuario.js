function generateUsername() {
        const pNombre = document.getElementById('p_nombre').value.trim();
        const pApellido = document.getElementById('p_apellido').value.trim();
        const matricula = document.getElementById('matricula').value.trim();
        const username = (pNombre + pApellido + matricula).toLowerCase().replace(/\s+/g, '');
        document.getElementById('username').value = username;
        }

        document.getElementById('p_nombre').addEventListener('input', generateUsername);
        document.getElementById('p_apellido').addEventListener('input', generateUsername);
        document.getElementById('matricula').addEventListener('input', generateUsername);
