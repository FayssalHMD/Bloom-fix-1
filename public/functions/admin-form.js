// public/functions/admin-form.js (REWRITTEN FOR ROBUSTNESS)

document.addEventListener('DOMContentLoaded', () => {
    // --- Universal Image Management Logic ---

    /**
     * Initializes a file input and its preview container.
     * @param {string} inputId The ID of the file input element.
     * @param {string} previewContainerId The ID of the container for image previews.
     */
    function initializeImageUploader(inputId, previewContainerId) {
        const input = document.getElementById(inputId);
        const previewContainer = document.getElementById(previewContainerId);

        if (!input || !previewContainer) return;

        // This object will hold the File objects for new uploads
        const fileStore = new DataTransfer();

        // Function to render previews from the fileStore
        const renderPreviews = () => {
            // Clear only the previews for newly added files
            previewContainer.querySelectorAll('.new-preview').forEach(p => p.remove());

            // Hide existing image if a new one is added to a single-file input
            if (!input.multiple && fileStore.files.length > 0) {
                const existing = previewContainer.querySelector('.img-preview:not(.new-preview)');
                if (existing) existing.style.display = 'none';
            }

            // Create a preview for each file in the store
            Array.from(fileStore.files).forEach(file => {
                const reader = new FileReader();
                reader.onload = (e) => {
                    const previewDiv = document.createElement('div');
                    previewDiv.className = 'img-preview new-preview';
                    // Store the file name to identify it for removal
                    previewDiv.dataset.filename = file.name;
                    previewDiv.innerHTML = `
                        <img src="${e.target.result}" alt="Aperçu de l'image">
                        <button type="button" class="remove-img-btn" aria-label="Supprimer l'image">×</button>
                    `;
                    previewContainer.appendChild(previewDiv);
                };
                reader.readAsDataURL(file);
            });
        };

        // Listen for when the user selects files
        input.addEventListener('change', () => {
            if (input.multiple) {
                // For galleries, add new files to the existing store
                Array.from(input.files).forEach(file => {
                    fileStore.items.add(file);
                });
            } else {
                // For single images, replace the file in the store
                fileStore.items.clear();
                if (input.files.length > 0) {
                    fileStore.items.add(input.files[0]);
                }
            }
            // Update the actual input's file list and render the previews
            input.files = fileStore.files;
            renderPreviews();
        });

        // Use event delegation on the container to handle remove clicks
        previewContainer.addEventListener('click', (e) => {
            if (!e.target.classList.contains('remove-img-btn')) return;
            e.preventDefault();

            const previewToRemove = e.target.closest('.img-preview');
            if (!previewToRemove) return;

            const isNewPreview = previewToRemove.classList.contains('new-preview');
            
            if (isNewPreview) {
                // FIX: This is the logic to correctly remove a NEWLY added file preview
                const filenameToRemove = previewToRemove.dataset.filename;
                
                // Create a new temporary DataTransfer object
                const newFileStore = new DataTransfer();
                // Add all files EXCEPT the one to be removed to the new store
                Array.from(fileStore.files)
                    .filter(file => file.name !== filenameToRemove)
                    .forEach(file => newFileStore.items.add(file));
                
                // Replace the old file store and the input's files with the new one
                fileStore.items.clear();
                Array.from(newFileStore.files).forEach(file => fileStore.items.add(file));
                input.files = fileStore.files;

                // Show the existing image again if we removed the only new one
                if (!input.multiple && fileStore.files.length === 0) {
                    const existing = previewContainer.querySelector('.img-preview:not(.new-preview)');
                    if (existing) existing.style.display = 'flex'; // Use flex to match .img-preview style
                }

            } else {
                // FIX: This is the logic for removing an EXISTING image from the database
                const containerId = previewContainer.id;
                if (containerId === 'gallery-previews') {
                    const hiddenInput = document.getElementById('existingGalleryPaths');
                    if (hiddenInput) {
                        // Get all remaining existing image paths
                        const currentImagePaths = Array.from(previewContainer.querySelectorAll('.img-preview:not(.new-preview)'))
                            .map(div => div.dataset.path)
                            .filter(path => path && path !== previewToRemove.dataset.path); // Exclude the removed one
                        hiddenInput.value = JSON.stringify(currentImagePaths);
                    }
                }
            }

            // Finally, remove the preview element from the DOM
            previewToRemove.remove();
        });
    }

    // Initialize all image uploaders on the page
    initializeImageUploader('mainImage', 'main-image-preview');
    initializeImageUploader('gallery', 'gallery-previews');
    initializeImageUploader('instagramImage', 'instagram-image-preview');
    initializeImageUploader('beforeImage', 'before-image-preview');
    initializeImageUploader('afterImage', 'after-image-preview');


    // --- Tag Input Logic (Unchanged but included for completeness) ---
    function initializeTagInput(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;

        const hiddenInput = container.querySelector('input[type="hidden"]');
        const textInput = container.querySelector('input[type="text"]');
        const tagsContainer = container.querySelector('.tags');

        if (!hiddenInput || !textInput || !tagsContainer) return;

        function createTag(text) {
            const trimmedText = text.trim();
            if (!trimmedText) return;
            const tag = document.createElement('span');
            tag.classList.add('tag');
            tag.innerHTML = `
                ${trimmedText}
                <button type="button" class="remove-tag-btn" aria-label="Remove tag">×</button>
            `;
            tagsContainer.appendChild(tag);
        }

        function updateHiddenInput() {
            const tags = tagsContainer.querySelectorAll('.tag');
            const tagTexts = Array.from(tags).map(t => t.firstChild.textContent.trim());
            hiddenInput.value = tagTexts.join(',');
        }

        if (hiddenInput.value) {
            hiddenInput.value.split(',').forEach(createTag);
        }

        textInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                createTag(textInput.value);
                textInput.value = '';
                updateHiddenInput();
            }
        });

        tagsContainer.addEventListener('click', (e) => {
            if (e.target.classList.contains('remove-tag-btn')) {
                e.target.parentElement.remove();
                updateHiddenInput();
            }
        });
    }

    initializeTagInput('ingredients-tag-input');
    initializeTagInput('how-to-use-tag-input');
});