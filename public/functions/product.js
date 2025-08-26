// public/functions/product.js

document.addEventListener('DOMContentLoaded', () => {
    const product = window.productData || {}; 
    const user = window.USER_DETAILS || null;

    const priceEl = document.getElementById('product-price');
    const quantityDisplay = document.getElementById('quantity-display');
    const quantityMinusBtn = document.getElementById('quantity-minus');
    const quantityPlusBtn = document.getElementById('quantity-plus');
    const reviewsListEl = document.getElementById('reviews-list');
    const leaveReviewBtn = document.getElementById('leave-review-btn');
    
    const reviewModal = document.getElementById('review-modal');
    const reviewModalCloseBtn = document.getElementById('review-modal-close-btn');
    const reviewForm = document.getElementById('review-form');
    const starRatingContainer = document.querySelector('.star-rating-input');
    const ratingInput = document.getElementById('rating-input');
    const reviewCommentInput = document.getElementById('review-comment');
    const reviewFormError = document.getElementById('review-form-error');

    const loginPromptModal = document.getElementById('login-prompt-modal');
    const promptModalCloseBtn = document.getElementById('prompt-modal-close-btn');

    // --- START: ADD NEW VARIABLES FOR DELETE MODAL ---
    const reviewDeleteModal = document.getElementById('review-delete-confirm-modal');
    const reviewDeleteCancelBtn = document.getElementById('review-delete-cancel-btn');
    const reviewDeleteConfirmBtn = document.getElementById('review-delete-confirm-btn');
    let reviewIdToDelete = null; // Variable to store the ID of the review to be deleted
    // --- END: ADD NEW VARIABLES ---

    let currentQuantity = 1;
    const basePrice = parseFloat(product.price) || 0;

    function formatPrice(price) {
        return `${price.toFixed(2).replace('.', ',')} DA`;
    }

    function updatePriceDisplay() {
        if (!priceEl || !quantityDisplay) return;
        const total = basePrice * currentQuantity;
        priceEl.textContent = formatPrice(total);
        quantityDisplay.textContent = currentQuantity;
        if (quantityMinusBtn) {
            quantityMinusBtn.disabled = currentQuantity <= 1;
        }
    }

    function renderReviewStars(rating) {
        let starsHTML = '';
        const starSVG = `<svg fill="currentColor" viewBox="0 0 20 20"><path d="M10 15l-5.878 3.09 1.123-6.545L.489 6.91l6.572-.955L10 0l2.939 5.955 6.572.955-4.756 4.635 1.123 6.545z"/></svg>`;
        for (let i = 0; i < 5; i++) {
            starsHTML += `<div class="star-icon ${i < rating ? '' : 'empty'}">${starSVG}</div>`;
        }
        return `<div class="star-rating-display">${starsHTML}</div>`;
    }

    function createReviewCard(review) {
        const reviewEl = document.createElement('div');
        reviewEl.className = 'review-card';
        const reviewDate = new Date(review.createdAt).toLocaleDateString('fr-FR');
        
        const userIdentifier = review.user && review.user.email 
            ? `<span class="review-card-email">${maskEmail(review.user.email)}</span>`
            : '';

        // Conditionally add the delete button if the review belongs to the current user
        const deleteButtonHTML = (user && review.user && user._id.toString() === review.user._id.toString())
            ? `<button class="review-delete-btn" data-review-id="${review._id}" aria-label="Supprimer mon avis">
                   <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"></path></svg>
               </button>`
            : '';

        reviewEl.innerHTML = `
            ${deleteButtonHTML}
            <div class="review-card-header">
                <div class="review-card-author">
                    <span class="review-card-name">${review.name}</span>
                    ${userIdentifier}
                </div>
                ${renderReviewStars(review.rating)}
            </div>
            <p class="review-card-comment">"${review.comment}"</p>
            <div class="review-card-footer">
                <span class="review-card-date">${reviewDate}</span>
            </div>`;
        return reviewEl;
    }

    function maskEmail(email) {
        if (!email) return '';
        const [name, domain] = email.split('@');
        if (name.length <= 3) {
            return `${name.slice(0, 1)}***@${domain}`;
        }
        return `${name.slice(0, 3)}***@${domain}`;
    }

    function openReviewModal() {
        if (reviewModal) reviewModal.classList.add('active');
    }

    function closeReviewModal() {
        if (reviewModal) reviewModal.classList.remove('active');
    }

    function setupStarRating() {
        if (!starRatingContainer) return;
        starRatingContainer.innerHTML = '';
        for (let i = 1; i <= 5; i++) {
            const star = document.createElement('span');
            star.innerHTML = '★';
            star.dataset.value = i;
            star.classList.add('star');
            starRatingContainer.appendChild(star);
        }

        starRatingContainer.addEventListener('click', e => {
            if (e.target.classList.contains('star')) {
                const rating = e.target.dataset.value;
                ratingInput.value = rating;
                updateStarDisplay(rating);
            }
        });

        starRatingContainer.addEventListener('mouseover', e => {
            if (e.target.classList.contains('star')) {
                updateStarDisplay(e.target.dataset.value, true);
            }
        });

        starRatingContainer.addEventListener('mouseout', () => {
            updateStarDisplay(ratingInput.value);
        });
    }

    function updateStarDisplay(rating, isHover = false) {
        const stars = starRatingContainer.querySelectorAll('.star');
        stars.forEach(star => {
            star.classList.toggle('selected', star.dataset.value <= rating);
            star.classList.toggle('hover', isHover && star.dataset.value <= rating);
        });
    }

    async function handleReviewSubmit(e) {
        e.preventDefault();
        const rating = ratingInput.value;
        const comment = reviewCommentInput.value.trim();

        if (rating === '0' || !comment) {
            reviewFormError.textContent = 'Veuillez fournir une note et un commentaire.';
            reviewFormError.style.display = 'block';
            return;
        }
        reviewFormError.style.display = 'none';

        try {
            const response = await fetch(`/api/products/${product._id}/reviews`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rating, comment })
            });
            const result = await response.json();

            if (result.success) {
                closeReviewModal();
                window.showToast('Avis ajouté avec succès !');
                const newReviewCard = createReviewCard(result.review);
                if (reviewsListEl.querySelector('.no-reviews-message')) {
                    reviewsListEl.innerHTML = '';
                }
                reviewsListEl.prepend(newReviewCard);
            } else {
                reviewFormError.textContent = result.message || 'Une erreur est survenue.';
                reviewFormError.style.display = 'block';
            }
        } catch (err) {
            reviewFormError.textContent = 'Erreur de connexion. Veuillez réessayer.';
            reviewFormError.style.display = 'block';
        }
    }

    function attachEventListeners() {
        quantityPlusBtn?.addEventListener('click', () => {
            currentQuantity++;
            updatePriceDisplay();
        });
        quantityMinusBtn?.addEventListener('click', () => {
            if (currentQuantity > 1) {
                currentQuantity--;
                updatePriceDisplay();
            }
        });

        document.querySelectorAll('.tab-link').forEach(link => {
            link.addEventListener('click', () => {
                document.querySelector('.tab-link.active')?.classList.remove('active');
                document.querySelector('.tab-panel.active')?.classList.remove('active');
                link.classList.add('active');
                const tabPanel = document.getElementById(`tab-${link.dataset.tab}`);
                tabPanel?.classList.add('active');
            });
        });

        const mainProductImage = document.getElementById('main-product-image');
        const thumbnailContainer = document.getElementById('product-thumbnail-container');
        thumbnailContainer?.addEventListener('click', (e) => {
            const thumb = e.target.closest('.thumbnail-image');
            if (!thumb || thumb.classList.contains('active')) return;
            mainProductImage.src = thumb.dataset.src;
            thumbnailContainer.querySelector('.active')?.classList.remove('active');
            thumb.classList.add('active');
        });

        leaveReviewBtn?.addEventListener('click', () => {
            if (user) {
                openReviewModal();
            } else {
                loginPromptModal?.classList.add('active');
            }
        });

        reviewModalCloseBtn?.addEventListener('click', closeReviewModal);
        reviewModal?.addEventListener('click', (e) => {
            if (e.target === reviewModal) closeReviewModal();
        });
        reviewForm?.addEventListener('submit', handleReviewSubmit);

        promptModalCloseBtn?.addEventListener('click', () => loginPromptModal.classList.remove('active'));
        loginPromptModal?.addEventListener('click', (e) => {
            if (e.target === loginPromptModal) loginPromptModal.classList.remove('active');
        });

        // --- START: ADD NEW EVENT LISTENERS FOR DELETION ---

        // Use event delegation on the reviews list for dynamically added/removed reviews
        reviewsListEl?.addEventListener('click', (e) => {
            const deleteBtn = e.target.closest('.review-delete-btn');
            if (deleteBtn) {
                reviewIdToDelete = deleteBtn.dataset.reviewId;
                reviewDeleteModal?.classList.add('active');
            }
        });

        // Close the delete modal
        const closeDeleteModal = () => {
            reviewDeleteModal?.classList.remove('active');
            reviewIdToDelete = null;
        };

        reviewDeleteCancelBtn?.addEventListener('click', closeDeleteModal);
        reviewDeleteModal?.addEventListener('click', (e) => {
            if (e.target === reviewDeleteModal) closeDeleteModal();
        });

        // Handle the final confirmation and API call
        reviewDeleteConfirmBtn?.addEventListener('click', async () => {
            if (!reviewIdToDelete) return;

            try {
                const response = await fetch(`/api/reviews/${reviewIdToDelete}`, {
                    method: 'DELETE',
                });

                const result = await response.json();

                if (result.success) {
                    // Find the review card on the page and remove it with an animation
                    const reviewCardToRemove = document.querySelector(`.review-delete-btn[data-review-id="${reviewIdToDelete}"]`).closest('.review-card');
                    if (reviewCardToRemove) {
                        reviewCardToRemove.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
                        reviewCardToRemove.style.opacity = '0';
                        reviewCardToRemove.style.transform = 'scale(0.95)';
                        setTimeout(() => {
                            reviewCardToRemove.remove();
                        }, 300);
                    }
                    window.showToast(result.message);
                } else {
                    window.showToast(result.message || 'Une erreur est survenue.');
                }
            } catch (error) {
                console.error('Failed to delete review:', error);
                window.showToast('Erreur de connexion. Veuillez réessayer.');
            } finally {
                closeDeleteModal();
            }
        });

        // --- END: ADD NEW EVENT LISTENERS FOR DELETION ---
    }

    function initializePage() {
        updatePriceDisplay();
        setupStarRating();
        attachEventListeners();
    }

    initializePage();
});