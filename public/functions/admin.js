document.addEventListener('DOMContentLoaded', () => {

    // --- Order Row Expansion ---
    const orderRows = document.querySelectorAll('.admin-order-row');
    orderRows.forEach(row => {
        // Exclude the details section from being a trigger
        const clickableArea = Array.from(row.children).filter(child => !child.classList.contains('admin-order-details'));
        
        clickableArea.forEach(area => {
            area.addEventListener('click', (e) => {
                // Do not expand if a link, button, or form element inside the details was clicked
                if (e.target.closest('a, button, select, form')) return;
                row.classList.toggle('is-expanded');
            });
        });
    });

    // --- Inventory View Switcher ---
    const gridViewBtn = document.getElementById('grid-view-btn');
    const listViewBtn = document.getElementById('list-view-btn');
    const inventoryContainer = document.getElementById('inventory-container');
    if (gridViewBtn && listViewBtn && inventoryContainer) {
        gridViewBtn.addEventListener('click', () => {
            inventoryContainer.classList.remove('list-view');
            inventoryContainer.classList.add('grid-view');
            gridViewBtn.classList.add('active');
            listViewBtn.classList.remove('active');
        });
        listViewBtn.addEventListener('click', () => {
            inventoryContainer.classList.remove('grid-view');
            inventoryContainer.classList.add('list-view');
            listViewBtn.classList.add('active');
            gridViewBtn.classList.remove('active');
        });
    }

    // --- Split Button Dropdown ---
    const splitButtonContainer = document.querySelector('.split-button-container');
    if (splitButtonContainer) {
        const toggle = splitButtonContainer.querySelector('.split-button-toggle');
        toggle.addEventListener('click', () => {
            splitButtonContainer.classList.toggle('is-open');
        });
        document.addEventListener('click', (e) => {
            if (!splitButtonContainer.contains(e.target)) {
                splitButtonContainer.classList.remove('is-open');
            }
        });
    }

    // --- Unified Custom Modal Logic for All Deletions ---
    const modal = document.getElementById('admin-prompt-modal');
    if (modal) {
        const confirmBtn = document.getElementById('admin-confirm-delete-btn');
        const cancelBtn = document.getElementById('admin-cancel-delete-btn');
        const itemNameSpan = document.getElementById('admin-item-name-to-delete');
        const confirmDeleteForm = document.getElementById('admin-confirm-delete-form');
        
        let actionToConfirm = null; // This will hold the function to run on confirm

        const openModal = (itemName, onConfirm) => {
            itemNameSpan.innerHTML = itemName; // Use innerHTML to render <strong> tags
            actionToConfirm = onConfirm;
            modal.classList.add('active');
        };

        const closeModal = () => {
            modal.classList.remove('active');
            actionToConfirm = null;
        };

        confirmBtn.addEventListener('click', () => {
            if (typeof actionToConfirm === 'function') {
                actionToConfirm();
            }
        });

        cancelBtn.addEventListener('click', closeModal);
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal();
        });

        // Event listener for all delete buttons
        document.body.addEventListener('click', (e) => {
            // Case 1: Product/Pack deletion (uses a form)
            const productDeleteBtn = e.target.closest('.btn-delete');
            if (productDeleteBtn) {
                e.preventDefault();
                const form = productDeleteBtn.closest('form');
                const itemName = productDeleteBtn.dataset.itemName;
                const deleteUrl = form.action;

                openModal(`<strong>${itemName}</strong>`, () => {
                    confirmDeleteForm.action = deleteUrl;
                    confirmDeleteForm.submit();
                });
                return; // Stop further execution
            }

            // Case 2: Message deletion (uses Fetch API)
            const messageDeleteBtn = e.target.closest('.btn-delete-message');
            if (messageDeleteBtn) {
                e.preventDefault();
                const row = messageDeleteBtn.closest('.admin-message-row');
                const messageId = row.dataset.messageId;
                const authorName = row.querySelector('.message-from').textContent;
                
                openModal(`le message de <strong>${authorName}</strong>`, async () => {
                    try {
                        const response = await fetch(`/admin/messages/delete/${messageId}`, { method: 'POST' });
                        if (response.ok) {
                            row.style.transition = 'opacity 0.3s ease';
                            row.style.opacity = '0';
                            setTimeout(() => row.remove(), 300);
                        } else { alert('Erreur: Impossible de supprimer le message.'); }
                    } catch (error) { alert('Une erreur de connexion est survenue.'); }
                    closeModal();
                });
                return;
            }

            // Case 3: Review deletion (uses Fetch API)
            const reviewDeleteBtn = e.target.closest('.btn-delete-review');
            if (reviewDeleteBtn) {
                e.preventDefault();
                const row = reviewDeleteBtn.closest('tr');
                const productId = row.dataset.productId;
                const reviewId = row.dataset.reviewId;
                const authorName = row.querySelector('strong')?.textContent || 'cet avis';

                openModal(`l'avis de <strong>${authorName}</strong>`, async () => {
                    try {
                        const response = await fetch(`/api/admin/reviews/${productId}/${reviewId}`, { method: 'DELETE' });
                        const result = await response.json();
                        if (result.success) {
                            row.style.transition = 'opacity 0.3s ease';
                            row.style.opacity = '0';
                            setTimeout(() => row.remove(), 300);
                        } else { alert('Erreur: ' + result.message); }
                    } catch (error) { alert('Une erreur de connexion est survenue.'); }
                    closeModal();
                });
            }
        });
    }

    // --- Admin Message Row Expansion ---
    const messagesContainer = document.querySelector('.admin-messages-list');
    if (messagesContainer) {
        messagesContainer.addEventListener('click', (e) => {
            // Only expand if the click was not on the delete button
            if (!e.target.closest('.btn-delete-message')) {
                const row = e.target.closest('.admin-message-row');
                if (row) {
                    row.classList.toggle('is-expanded');
                }
            }
        });
    }

    // --- Admin Reviews Page Search ---
    const reviewsSearchInput = document.getElementById('admin-reviews-search');
    if (reviewsSearchInput) {
        const tableRows = document.querySelectorAll('.admin-reviews-table tbody tr');
        reviewsSearchInput.addEventListener('input', () => {
            const searchTerm = reviewsSearchInput.value.toLowerCase().trim();
            tableRows.forEach(row => {
                row.style.display = row.textContent.toLowerCase().includes(searchTerm) ? '' : 'none';
            });
        });
    }



// --- Flash Message Close Button Logic ---
    const flashCloseButtons = document.querySelectorAll('.flash-close-btn');
    flashCloseButtons.forEach(button => {
        button.addEventListener('click', () => {
            const flashMessage = button.closest('.flash-message');
            if (flashMessage) {
                flashMessage.style.display = 'none';
            }
        });
    });


});