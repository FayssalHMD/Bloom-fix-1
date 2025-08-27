// public/functions/admin.js (CORRECTED AND REFACTORED)
document.addEventListener('DOMContentLoaded', () => {

    // --- Order Row Expansion ---
    const orderRows = document.querySelectorAll('.admin-order-row');
    orderRows.forEach(row => {
        const clickableArea = Array.from(row.children).filter(child => !child.classList.contains('admin-order-details'));
        clickableArea.forEach(area => {
            area.addEventListener('click', (e) => {
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

        const openModal = (itemName, onConfirm) => {
            itemNameSpan.innerHTML = itemName;
            modal.classList.add('active');

            // This is a cleaner way to handle the confirmation
            const handleConfirm = () => {
                onConfirm();
                closeModal(); // Close modal after action
            };
            
            confirmBtn.addEventListener('click', handleConfirm, { once: true });
            
            // Ensure cancel also removes the confirm listener
            const handleCancel = () => {
                closeModal();
                confirmBtn.removeEventListener('click', handleConfirm);
            };

            cancelBtn.addEventListener('click', handleCancel, { once: true });
            modal.addEventListener('click', (e) => {
                if (e.target === modal) handleCancel();
            }, { once: true });
        };

        const closeModal = () => {
            modal.classList.remove('active');
        };

        // SINGLE, UNIFIED Event listener for all delete buttons on the page
        document.body.addEventListener('click', (e) => {
            const targetButton = e.target.closest('.btn-delete, .btn-delete-message, .btn-delete-review');
            if (!targetButton) return;

            e.preventDefault();

            // Case 1: Generic Form-based Deletion (Products, Packs, FAQ Items, FAQ Categories)
            if (targetButton.classList.contains('btn-delete')) {
                const form = targetButton.closest('form');
                const itemName = targetButton.dataset.itemName || 'cet élément';
                const deleteUrl = form.action;

                openModal(`<strong>${itemName}</strong>`, () => {
                    // The modal's own form is used to submit the request
                    confirmDeleteForm.action = deleteUrl;
                    confirmDeleteForm.submit();
                });
            }
            
            // Case 2: Message deletion (uses Fetch API)
            else if (targetButton.classList.contains('btn-delete-message')) {
                const row = targetButton.closest('.admin-message-row');
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
                });
            }

            // Case 3: Review deletion (uses Fetch API)
            else if (targetButton.classList.contains('btn-delete-review')) {
                const row = targetButton.closest('tr');
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
                });
            }
        });
    }

    // --- Admin Message Row Expansion ---
    const messagesContainer = document.querySelector('.admin-messages-list');
    if (messagesContainer) {
        messagesContainer.addEventListener('click', (e) => {
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

    // --- Custom Select Dropdown Logic ---
    const customSelects = document.querySelectorAll('.custom-select-wrapper');
    customSelects.forEach(wrapper => {
        const select = wrapper.querySelector('select');
        const displayName = wrapper.querySelector('#selected-category-name');
        if (select && displayName) {
            select.addEventListener('change', () => {
                const selectedOption = select.options[select.selectedIndex];
                displayName.textContent = selectedOption.textContent;
            });
        }
    });

    // --- Custom Form Validation for FAQ Forms ---
    const faqForms = document.querySelectorAll('form[action*="/admin/faq/"]');
    faqForms.forEach(faqForm => {
        if (faqForm.method.toUpperCase() === 'POST' && !faqForm.classList.contains('delete-form')) {
            faqForm.setAttribute('novalidate', true);
            faqForm.addEventListener('submit', (e) => {
                let isValid = true;
                const fieldsToValidate = faqForm.querySelectorAll('[required]');
                fieldsToValidate.forEach(field => {
                    field.closest('.form-group').classList.remove('error');
                });
                fieldsToValidate.forEach(field => {
                    if (!field.value) {
                        isValid = false;
                        const formGroup = field.closest('.form-group');
                        if (formGroup) {
                            formGroup.classList.add('error');
                        }
                    }
                });
                if (!isValid) {
                    e.preventDefault();
                    console.log('Validation failed. Please fill all required fields.');
                }
            });
        }
    });
});