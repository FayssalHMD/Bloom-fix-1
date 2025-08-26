document.addEventListener('DOMContentLoaded', () => {
    let currentQuantity = 1;
    let basePrice = 0;

    const priceEl = document.getElementById('pack-price');
    const quantityDisplay = document.getElementById('quantity-display');
    const quantityMinusBtn = document.getElementById('quantity-minus');
    const quantityPlusBtn = document.getElementById('quantity-plus');
    
    function initializePage() {
        if (!priceEl) return;
        
        basePrice = parseFloat(priceEl.dataset.basePrice || '0');
        
        updatePriceDisplay();
        attachEventListeners();
    }

    function updatePriceDisplay() {
        if (!priceEl || !quantityDisplay) return;
        
        const total = basePrice * currentQuantity;
        priceEl.textContent = `${total.toFixed(2).replace('.', ',')} DA`;
        quantityDisplay.textContent = currentQuantity;
        quantityMinusBtn.disabled = currentQuantity === 1;
    }

    function attachEventListeners() {
        if (quantityPlusBtn) {
            quantityPlusBtn.addEventListener('click', () => {
                currentQuantity++;
                updatePriceDisplay();
            });
        }
        if (quantityMinusBtn) {
            quantityMinusBtn.addEventListener('click', () => {
                if (currentQuantity > 1) {
                    currentQuantity--;
                    updatePriceDisplay();
                }
            });
        }

        // ==================================================
        //          NEW: THUMBNAIL GALLERY LOGIC
        // ==================================================
        const mainProductImage = document.getElementById('main-product-image');
        const thumbnailContainer = document.getElementById('product-thumbnail-container');

        if (mainProductImage && thumbnailContainer) {
            thumbnailContainer.addEventListener('click', (e) => {
                const thumb = e.target.closest('.thumbnail-image');
                if (!thumb || thumb.classList.contains('active')) return;

                // Change the main image source
                mainProductImage.src = thumb.dataset.src;

                // Update the active state on thumbnails
                const currentActive = thumbnailContainer.querySelector('.active');
                if (currentActive) {
                    currentActive.classList.remove('active');
                }
                thumb.classList.add('active');
            });
        }
        // ==================================================
    }

    initializePage();
});