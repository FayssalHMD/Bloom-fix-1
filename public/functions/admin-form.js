
document.addEventListener('DOMContentLoaded', () => {
    // --- Universal Image Management Logic ---
    function initializeImageUploader(inputId, previewContainerId) {
        const input = document.getElementById(inputId);
        const previewContainer = document.getElementById(previewContainerId);
        if (!input || !previewContainer) return;

        const fileStore = new DataTransfer();

        const renderPreviews = () => {
            previewContainer.querySelectorAll('.new-preview').forEach(p => p.remove());
            if (!input.multiple && fileStore.files.length > 0) {
                const existing = previewContainer.querySelector('.img-preview:not(.new-preview)');
                if (existing) existing.style.display = 'none';
            }
            Array.from(fileStore.files).forEach(file => {
                const reader = new FileReader();
                reader.onload = (e) => {
                    const previewDiv = document.createElement('div');
                    previewDiv.className = 'img-preview new-preview';
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

        input.addEventListener('change', () => {
            if (input.multiple) {
                Array.from(input.files).forEach(file => fileStore.items.add(file));
            } else {
                fileStore.items.clear();
                if (input.files.length > 0) fileStore.items.add(input.files[0]);
            }
            input.files = fileStore.files;
            renderPreviews();
        });

        previewContainer.addEventListener('click', (e) => {
            if (!e.target.classList.contains('remove-img-btn')) return;
            e.preventDefault();

            const previewToRemove = e.target.closest('.img-preview');
            if (!previewToRemove) return;

            if (previewToRemove.classList.contains('new-preview')) {
                const filenameToRemove = previewToRemove.dataset.filename;
                const newFileStore = new DataTransfer();
                Array.from(fileStore.files)
                    .filter(file => file.name !== filenameToRemove)
                    .forEach(file => newFileStore.items.add(file));
                
                fileStore.items.clear();
                Array.from(newFileStore.files).forEach(file => fileStore.items.add(file));
                input.files = fileStore.files;

                if (!input.multiple && fileStore.files.length === 0) {
                    const existing = previewContainer.querySelector('.img-preview:not(.new-preview)');
                    if (existing) existing.style.display = 'flex';
                }
            } else {
                // ==================================================
                //                 START OF NEW LOGIC
                // ==================================================
                // This is for removing an EXISTING image from Cloudinary
                const publicIdToRemove = previewToRemove.dataset.publicId;
                if (publicIdToRemove) {
                    const deleteInput = document.getElementById('images_to_delete');
                    if (deleteInput) {
                        const currentIds = deleteInput.value ? deleteInput.value.split(',') : [];
                        if (!currentIds.includes(publicIdToRemove)) {
                            currentIds.push(publicIdToRemove);
                            deleteInput.value = currentIds.join(',');
                        }
                    }
                }
                // ==================================================
                //                  END OF NEW LOGIC
                // ==================================================
            }
            previewToRemove.remove();
        });
    }

    initializeImageUploader('mainImage', 'main-image-preview');
    initializeImageUploader('gallery', 'gallery-previews');
    initializeImageUploader('instagramImage', 'instagram-image-preview');
    initializeImageUploader('beforeImage', 'before-image-preview');
    initializeImageUploader('afterImage', 'after-image-preview');

    // --- Tag Input Logic (Unchanged) ---
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
            tag.innerHTML = `${trimmedText}<button type="button" class="remove-tag-btn" aria-label="Remove tag">×</button>`;
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