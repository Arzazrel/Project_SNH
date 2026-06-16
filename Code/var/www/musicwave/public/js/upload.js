/**
 * UPLOAD SCRIPT
 * Handles the UI switching between lyrics and audio upload forms.
 * Kept in an external file to strictly comply with Content Security Policy (CSP).
 */
document.addEventListener('DOMContentLoaded', function() {
    const toggleButtons = document.querySelectorAll('.section-toggle .toggle-btn');
    const panels = document.querySelectorAll('.upload-panel');

    toggleButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');

            // 1. Rimuovi lo stato attivo da tutti i pannelli dei moduli
            panels.forEach(function(panel) {
                panel.classList.remove('active');
            });

            // 2. Disattiva lo stato grafico di selezione su tutti i pulsanti del menu
            toggleButtons.forEach(function(btn) {
                btn.classList.remove('active');
            });

            // 3. Attiva il pannello corrispondente al pulsante cliccato
            const targetPanel = document.getElementById(targetId);
            if (targetPanel) {
                targetPanel.classList.add('active');
            }

            // 4. Attiva lo stato grafico sul pulsante corrente
            this.classList.add('active');
        });
    });
});
