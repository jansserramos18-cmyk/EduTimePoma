function filtrarMaestros() {
    const fechaHoraInput = document.getElementById('fecha_hora');
    const profesorSelect = document.getElementById('profesor_id');
    const fechaSeleccionada = new Date(fechaHoraInput.value);
    
    if (!fechaSeleccionada || isNaN(fechaSeleccionada)) {
        // Si no hay fecha, mostrar todos
        Array.from(profesorSelect.options).forEach(option => {
            if (option.value) option.style.display = 'block';
        });
        return;
    }
    
    const diasSemana = ['domingo', 'lunes', 'martes', 'miércoles', 'jueves', 'viernes', 'sábado'];
    const diaSeleccionado = diasSemana[fechaSeleccionada.getDay()];
    
    Array.from(profesorSelect.options).forEach(option => {
        if (!option.value) return; // Skip placeholder
        const diasDisponibles = option.getAttribute('data-dias').split(',');
        if (diasDisponibles.includes(diaSeleccionado)) {
            option.style.display = 'block';
        } else {
            option.style.display = 'none';
        }
    });
    

    if (profesorSelect.selectedOptions[0] && profesorSelect.selectedOptions[0].style.display === 'none') {
        profesorSelect.selectedIndex = 0;
    }
}