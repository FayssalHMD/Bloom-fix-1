// public/functions/cart.js - CORRECTED TO MATCH YOUR EJS

document.addEventListener('DOMContentLoaded', () => {
    const addToCartBtn = document.getElementById('add-to-cart-btn');

    // This function now needs to know if a user is logged in
    window.updateCartIcon = () => {
        let totalItems = 0;
        const isLoggedIn = typeof USER_DETAILS !== 'undefined' && USER_DETAILS !== null;

        if (isLoggedIn) {
            // For logged-in users, the cart is stored on the user object
            const userCart = USER_DETAILS.cart || [];
            totalItems = userCart.reduce((sum, item) => sum + item.quantity, 0);
        } else {
            // For guests, use localStorage
            const cart = JSON.parse(localStorage.getItem('bloomCart')) || [];
            totalItems = cart.reduce((sum, item) => sum + item.quantity, 0);
        }
        
        document.querySelectorAll('.cart-icon').forEach(icon => {
            let countSpan = icon.querySelector('.cart-item-count');
            if (!countSpan) {
                countSpan = document.createElement('span');
                countSpan.className = 'cart-item-count';
                icon.appendChild(countSpan);
            }
            if (totalItems > 0) {
                countSpan.textContent = totalItems;
                countSpan.style.display = 'flex';
            } else {
                countSpan.style.display = 'none';
            }
        });
    };

    const addToCart = async (item) => {
        if (!item || !item.id || !item.name || item.price == null) {
            console.error("Attempted to add an invalid item to the cart:", item);
            alert("Désolé, une erreur s'est produite lors de l'ajout de cet article.");
            return;
        }

        const quantityDisplay = document.getElementById('quantity-display');
        const quantity = quantityDisplay ? parseInt(quantityDisplay.textContent, 10) : 1;
        const isLoggedIn = typeof USER_DETAILS !== 'undefined' && USER_DETAILS !== null;

        if (isLoggedIn) {
            // --- LOGGED-IN USER LOGIC ---
            try {
                const response = await fetch('/api/cart', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        // Use the MongoDB _id as the identifier
                        productId: !item.isPack ? item.id : undefined,
                        packId: item.isPack ? item.id : undefined,
                        quantity: quantity,
                        name: item.name,
                        price: item.price,
                        image: item.image,
                        isPack: item.isPack
                    }),
                });

                const result = await response.json();

                if (result.success) {
                    USER_DETAILS.cart = result.cart;
                    window.showToast(`${quantity} x ${item.name} a été ajouté au panier !`);
                    window.updateCartIcon();
                } else {
                    throw new Error(result.message || 'Server error');
                }
            } catch (error) {
                console.error("Error adding item to database cart:", error);
                alert("Impossible d'ajouter l'article au panier. Veuillez réessayer.");
            }

        } else {
            // --- GUEST USER LOGIC (localStorage) ---
            let cart = JSON.parse(localStorage.getItem('bloomCart')) || [];
            // For guests, the 'id' is the original string ID (e.g., 'huile-eclat-radieux')
            // We need to find the item based on this ID.
            const guestItemId = addToCartBtn.dataset.productId || addToCartBtn.dataset.packId;
            const existingItemIndex = cart.findIndex(cartItem => cartItem.id === guestItemId);

            if (existingItemIndex > -1) {
                cart[existingItemIndex].quantity += quantity;
            } else {
                // For guests, we need to construct the item object differently
                const guestItem = {
                    id: guestItemId,
                    name: item.name,
                    price: item.price,
                    image: item.image,
                    isPack: item.isPack,
                    quantity: quantity
                };
                cart.push(guestItem);
            }

            localStorage.setItem('bloomCart', JSON.stringify(cart));
            window.showToast(`${quantity} x ${item.name} a été ajouté au panier !`);
            window.updateCartIcon();
        }
    };

    if (addToCartBtn) {
        addToCartBtn.addEventListener('click', () => {
            // This object is now built using YOUR data attributes
            const item = {
                // For the database, we use the MongoDB _id
                id: addToCartBtn.dataset.productId, 
                name: addToCartBtn.dataset.productName,
                price: parseFloat(addToCartBtn.dataset.productPrice),
                image: addToCartBtn.dataset.productImage,
                isPack: addToCartBtn.dataset.isPack === 'true' 
            };
            addToCart(item);
        });
    }

    // Initial call on every page load
    // A small delay ensures USER_DETAILS is available from the footer script
    setTimeout(() => {
        window.updateCartIcon();
    }, 100);
});