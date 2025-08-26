// public/functions/panier.js (REFACTORED V2)

document.addEventListener('DOMContentLoaded', () => {
    const cartContentWrapper = document.getElementById('cart-content-wrapper');
    if (!cartContentWrapper) return;

    // --- GLOBAL STATE ---
    const isLoggedIn = typeof USER_DETAILS !== 'undefined' && USER_DETAILS !== null;
    let shippingInfoArray = []; // Will hold the ordered array of wilayas
    let shippingInfoMap = new Map(); // Will hold data for fast lookups

    // --- Get All Elements ---
    const emptyCartContainer = document.getElementById('empty-cart-container');
    const itemsContainer = document.getElementById('cart-items-panel');
    const summarySubtotalEl = document.getElementById('summary-subtotal');
    const summaryShippingEl = document.getElementById('summary-shipping');
    const summaryTotalEl = document.getElementById('summary-total');
    const summaryWilayaSelect = document.getElementById('summary-wilaya');
    const deliveryRadios = document.querySelectorAll('input[name="summary-delivery"]');
    const stopDeskRadio = document.querySelector('input[value="stopdesk"]');
    const homeDeliveryRadio = document.querySelector('input[value="home"]');
    const stopDeskInfoBox = document.getElementById('stopdesk-info-box');
    const checkoutBtn = document.getElementById('checkout-btn');
    const checkoutDetailsForm = document.getElementById('checkout-details-form');
    const checkoutAddressGroup = document.getElementById('checkout-address-group');
    const checkoutPhoneInput = document.getElementById('checkout-phone');
    const phoneErrorMessage = document.getElementById('phone-error-message');
    const confirmOrderBtn = document.getElementById('confirm-order-btn');
    
    const deleteModal = document.getElementById('cart-confirm-modal');
    const cancelDeleteBtn = document.getElementById('cart-confirm-cancel-btn');
    const confirmDeleteBtn = document.getElementById('cart-confirm-confirm-btn');
    let itemToDelete = null;

    // --- Utility & Core Functions ---
    const formatPrice = (price) => `${parseFloat(price).toFixed(2)} DA`;

    const getCart = () => {
        if (isLoggedIn) {
            return USER_DETAILS.cart || [];
        } else {
            return JSON.parse(localStorage.getItem('bloomCart')) || [];
        }
    };

    const renderCartPage = () => {
        const cart = getCart();
        
        if (cart.length === 0) {
            cartContentWrapper.style.display = 'none';
            emptyCartContainer.style.display = 'block';
        } else {
            cartContentWrapper.style.display = 'block';
            emptyCartContainer.style.display = 'none';
            itemsContainer.innerHTML = '';
            cart.forEach(item => {
                const itemId = item.productId || item.packId || item.id;
                const itemEl = document.createElement('div');
                itemEl.className = 'cart-page-item';
                itemEl.innerHTML = `
                    <img src="${item.image}" alt="${item.name}" class="cart-page-item-image">
                    <div class="cart-page-item-details">
                        <p class="cart-page-item-name">${item.name}</p>
                        <p class="cart-page-item-price">${formatPrice(item.price)}</p>
                    </div>
                    <div class="quantity-selector">
                        <button class="quantity-btn" data-id="${itemId}" data-is-pack="${item.isPack}" data-action="decrease">-</button>
                        <span>${item.quantity}</span>
                        <button class="quantity-btn" data-id="${itemId}" data-is-pack="${item.isPack}" data-action="increase">+</button>
                    </div>
                    <div class="item-total">${formatPrice(item.price * item.quantity)}</div>
                    <button class="remove-item-btn" data-id="${itemId}" data-is-pack="${item.isPack}">
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                    </button>
                `;
                itemsContainer.appendChild(itemEl);
            });
        }
        updateSummary();
        if (typeof window.updateCartIcon === 'function') {
            window.updateCartIcon();
        }
    };

    const updateSummary = () => {
        const cart = getCart();
        const subtotal = cart.reduce((sum, item) => sum + item.price * item.quantity, 0);
        
        const selectedWilaya = summaryWilayaSelect.value;
        let shippingCost = 0;

        if (selectedWilaya && shippingInfoMap.has(selectedWilaya)) {
            const wilayaData = shippingInfoMap.get(selectedWilaya);
            const deliveryMethod = document.querySelector('input[name="summary-delivery"]:checked').value;

            if (deliveryMethod === 'home') {
                shippingCost = wilayaData.homePrice;
            } else if (deliveryMethod === 'stopdesk' && wilayaData.hasStopdesk) {
                shippingCost = wilayaData.stopdeskPrice;
            }
        }
        
        const total = subtotal + shippingCost;
        summarySubtotalEl.textContent = formatPrice(subtotal);
        summaryShippingEl.textContent = selectedWilaya ? formatPrice(shippingCost) : "0.00 DA";
        summaryTotalEl.textContent = formatPrice(total);
    };

    const populateWilayas = () => {
        if (!summaryWilayaSelect || summaryWilayaSelect.options.length > 1) return;
        // CHANGE: Iterate over the array to maintain the specific order
        shippingInfoArray.forEach(wilaya => {
            const option = new Option(wilaya.name, wilaya.name);
            summaryWilayaSelect.add(option);
        });
    };

    const handleWilayaChange = () => {
        const selectedWilaya = summaryWilayaSelect.value;
        stopDeskInfoBox.style.display = 'none';
        stopDeskInfoBox.innerHTML = '';

        if (selectedWilaya && shippingInfoMap.has(selectedWilaya)) {
            const wilayaData = shippingInfoMap.get(selectedWilaya);

            if (wilayaData.hasStopdesk) {
                stopDeskRadio.disabled = false;
                stopDeskRadio.parentElement.style.opacity = 1;
                stopDeskRadio.parentElement.style.cursor = 'pointer';
            } else {
                stopDeskRadio.disabled = true;
                stopDeskRadio.parentElement.style.opacity = 0.5;
                stopDeskRadio.parentElement.style.cursor = 'not-allowed';
                homeDeliveryRadio.checked = true;
            }
        } else {
            stopDeskRadio.disabled = false;
            stopDeskRadio.parentElement.style.opacity = 1;
            stopDeskRadio.parentElement.style.cursor = 'pointer';
        }
        document.querySelector('input[name="summary-delivery"]:checked').dispatchEvent(new Event('change'));
    };

    const handleDeliveryChange = () => {
        const selectedMethod = document.querySelector('input[name="summary-delivery"]:checked').value;
        const selectedWilaya = summaryWilayaSelect.value;

        checkoutAddressGroup.style.display = selectedMethod === 'home' ? 'block' : 'none';

        if (selectedMethod === 'stopdesk' && selectedWilaya && shippingInfoMap.get(selectedWilaya)?.hasStopdesk) {
            const info = shippingInfoMap.get(selectedWilaya).stopdeskInfo;
            // CHANGE: Simplified the info box content as requested
            stopDeskInfoBox.innerHTML = `
                <p>
                    <strong>Point de collecte Stop Desk :</strong>
                    <a href="${info.gmaps}" target="_blank" rel="noopener noreferrer">
                        Voir sur Google Maps
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
                    </a>
                </p>
            `;
            stopDeskInfoBox.style.display = 'block';
        } else {
            stopDeskInfoBox.style.display = 'none';
            stopDeskInfoBox.innerHTML = '';
        }
        updateSummary();
    };

    const performDelete = async () => {
        if (!itemToDelete) return;
        const { id, isPack } = itemToDelete;

        if (isLoggedIn) {
            const response = await fetch('/api/cart', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ productId: !isPack ? id : undefined, packId: isPack ? id : undefined, isPack })
            });
            const result = await response.json();
            if (result.success) {
                USER_DETAILS.cart = USER_DETAILS.cart.filter(i => (i.productId || i.packId) != id);
                renderCartPage();
            }
        } else {
            let cart = getCart();
            const itemIndex = cart.findIndex(item => item.id === id);
            if (itemIndex > -1) {
                cart.splice(itemIndex, 1);
                localStorage.setItem('bloomCart', JSON.stringify(cart));
                renderCartPage();
            }
        }
        closeDeleteModal();
    };

    const closeDeleteModal = () => {
        deleteModal.classList.remove('active');
        itemToDelete = null;
    };

    // --- Event Listeners ---
    itemsContainer.addEventListener('click', async (e) => {
        const target = e.target.closest('.quantity-btn, .remove-item-btn');
        if (!target) return;

        const id = target.dataset.id;
        const isPack = target.dataset.isPack === 'true';

        if (target.matches('.quantity-btn')) {
            const action = target.dataset.action;
            if (isLoggedIn) {
                const cart = getCart();
                const item = cart.find(i => (i.productId || i.packId) == id);
                let newQuantity = item.quantity;
                if (action === 'increase') newQuantity++;
                else if (action === 'decrease') newQuantity--;

                const response = await fetch('/api/cart', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ productId: !isPack ? id : undefined, packId: isPack ? id : undefined, quantity: newQuantity, isPack })
                });
                const result = await response.json();
                if (result.success) {
                    USER_DETAILS.cart = result.cart;
                    renderCartPage();
                }
            } else {
                let cart = getCart();
                const itemIndex = cart.findIndex(item => item.id === id);
                if (itemIndex === -1) return;
                if (action === 'increase') cart[itemIndex].quantity++;
                else if (action === 'decrease' && cart[itemIndex].quantity > 1) cart[itemIndex].quantity--;
                localStorage.setItem('bloomCart', JSON.stringify(cart));
                renderCartPage();
            }
        } else if (target.matches('.remove-item-btn')) {
            itemToDelete = { id, isPack };
            deleteModal.classList.add('active');
        }
    });

    summaryWilayaSelect.addEventListener('change', handleWilayaChange);
    deliveryRadios.forEach(radio => radio.addEventListener('change', handleDeliveryChange));

    checkoutPhoneInput.addEventListener('input', () => {
        const phoneValue = checkoutPhoneInput.value;
        if (!/^\d*$/.test(phoneValue)) {
            phoneErrorMessage.textContent = 'Ce champ ne doit contenir que des chiffres.';
        } else {
            phoneErrorMessage.textContent = '';
        }
    });

  checkoutBtn.addEventListener('click', () => {
    if (!summaryWilayaSelect.value) {
        window.showToast('Veuillez sélectionner votre wilaya de livraison.', 3000);
        return;
    }
    checkoutBtn.style.display = 'none';
    checkoutDetailsForm.style.display = 'block';

    // ==================================================
    //           START: PRE-FILLING LOGIC
    // ==================================================
    if (isLoggedIn && USER_DETAILS.shippingInfo) {
        const info = USER_DETAILS.shippingInfo;
        document.getElementById('checkout-name').value = info.fullName || '';
        document.getElementById('checkout-phone').value = info.phone || '';
        document.getElementById('checkout-address').value = info.address || '';
        
        // The wilaya is already pre-selected by the initializeCartPage function,
        // so we don't need to set it again here.
    }
    // ==================================================
    //            END: PRE-FILLING LOGIC
    // ==================================================
});

    if (confirmOrderBtn) {
        confirmOrderBtn.addEventListener('click', () => {
            const nameInput = document.getElementById('checkout-name');
            const phoneInput = document.getElementById('checkout-phone');
            const addressInput = document.getElementById('checkout-address');
            const deliveryMethod = document.querySelector('input[name="summary-delivery"]:checked').value;

            if (!nameInput.value.trim() || !phoneInput.value.trim() || !summaryWilayaSelect.value) {
                window.showToast('Veuillez remplir tous les champs requis.', 3000, true); return;
            }
            if (deliveryMethod === 'home' && !addressInput.value.trim()) {
                window.showToast("Veuillez entrer votre adresse pour la livraison à domicile.", 3000, true); return;
            }
            if (phoneErrorMessage.textContent !== '') {
                window.showToast("Veuillez corriger le numéro de téléphone.", 3000, true); return;
            }

            confirmOrderBtn.textContent = 'Confirmation...';
            confirmOrderBtn.disabled = true;

            const sendOrderAction = async () => {
                const cartItemsForServer = getCart().map(item => ({
                    productId: item.isPack ? null : (item.productId || item.id),
                    packId: item.isPack ? (item.packId || item.id) : null,
                    quantity: item.quantity,
                    name: item.name,
                    image: item.image,
                    isPack: item.isPack
                }));

                const orderPayload = {
                    customer: {
                        fullName: nameInput.value.trim(),
                        phone: phoneInput.value.trim(),
                        wilaya: summaryWilayaSelect.value,
                        deliveryMethod: deliveryMethod,
                        address: addressInput.value.trim()
                    },
                    items: cartItemsForServer,
                    shippingCost: parseFloat(summaryShippingEl.textContent) || 0,
                    total: summaryTotalEl.textContent
                };

                try {
                    const response = await fetch('/create-order', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(orderPayload),
                    });
                    const result = await response.json();

                    if (result.success) {
                        window.showToast('Merci ! Votre commande a été reçue.', 4000);
                        if (isLoggedIn) {
                            fetch('/api/cart/clear', { method: 'DELETE' })
                                .then(() => { setTimeout(() => { window.location.href = '/compte'; }, 4000); });
                        } else {
                            localStorage.removeItem('bloomCart');
                            setTimeout(() => { window.location.href = '/'; }, 4000);
                        }
                    } else {
                        window.showToast(result.message || 'Une erreur est survenue.', 3000, true);
                        confirmOrderBtn.textContent = 'Passer Commande';
                        confirmOrderBtn.disabled = false;
                    }
                } catch (error) {
                    console.error('Error submitting order:', error);
                    window.showToast('Une erreur de connexion est survenue.', 3000, true);
                    confirmOrderBtn.textContent = 'Passer Commande';
                    confirmOrderBtn.disabled = false;
                }
            };

            window.showUndoToast('Votre commande sera envoyée dans 10s.', sendOrderAction, confirmOrderBtn);
        });
    }

    if (deleteModal) {
        confirmDeleteBtn.addEventListener('click', performDelete);
        cancelDeleteBtn.addEventListener('click', closeDeleteModal);
        deleteModal.addEventListener('click', (e) => {
            if (e.target === deleteModal) {
                closeDeleteModal();
            }
        });
    }

    // --- ASYNC INITIALIZATION FUNCTION ---
    const initializeCartPage = async () => {
        try {
            const response = await fetch('/api/shipping-info');
            if (!response.ok) throw new Error('Failed to fetch shipping info');
            
            // CHANGE: Store data in both array (for order) and map (for speed)
            shippingInfoArray = await response.json();
            shippingInfoMap = new Map(shippingInfoArray.map(item => [item.name, item]));

            populateWilayas();

            const initialCart = getCart();
            if (initialCart.length > 0) {
                const payload = initialCart.map(item => ({
                    id: item.productId || item.packId || item.id,
                    isPack: item.isPack,
                    quantity: item.quantity
                }));
                const syncResponse = await fetch('/api/cart/sync', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ items: payload })
                });
                if (!syncResponse.ok) throw new Error('Sync request failed');
                const result = await syncResponse.json();
                if (result.success) {
                    if (isLoggedIn) {
                        USER_DETAILS.cart = result.cart;
                    } else {
                        const guestCart = result.cart.map(item => ({
                            id: item.productId || item.packId,
                            name: item.name,
                            price: item.price,
                            image: item.image,
                            isPack: item.isPack,
                            quantity: item.quantity
                        }));
                        localStorage.setItem('bloomCart', JSON.stringify(guestCart));
                    }
                }
            }

            renderCartPage();
            
            if (isLoggedIn && USER_DETAILS.shippingInfo && USER_DETAILS.shippingInfo.wilaya) {
                setTimeout(() => {
                    summaryWilayaSelect.value = USER_DETAILS.shippingInfo.wilaya;
                    summaryWilayaSelect.dispatchEvent(new Event('change'));
                }, 100);
            }

        } catch (error) {
            console.error('Error initializing cart page:', error);
            cartContentWrapper.innerHTML = '<p style="text-align: center; color: #e74c3c;">Impossible de charger les informations de livraison. Veuillez rafraîchir la page.</p>';
        }
    };

    initializeCartPage();
});