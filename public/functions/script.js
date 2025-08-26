// public/functions/script.js - DEFINITIVE FINAL VERSION

// --- GLOBAL TOAST NOTIFICATION CONTROLLER (DEFINITIVE FIX) ---
let toastTimeout;
window.showToast = (message, duration = 4000) => {
    // Find the elements every time the function is called. This is the robust solution.
    const toastElement = document.getElementById('custom-toast-notification');
    const toastMessageElement = document.getElementById('toast-message-text');
    const toastIconContainer = toastElement ? toastElement.querySelector('.toast-icon') : null;

    // Check if the elements exist NOW.
    if (!toastElement || !toastMessageElement || !toastIconContainer) {
        console.warn('Toast elements not found. Message:', message);
        return; // Exit if they don't exist.
    }

    clearTimeout(toastTimeout);
    toastMessageElement.textContent = message;
    toastIconContainer.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>`;
    
    toastElement.classList.add('show');
    
    toastTimeout = setTimeout(() => {
        toastElement.classList.remove('show');
    }, duration);
};


document.addEventListener('DOMContentLoaded', () => {
    const body = document.body;

    // --- Theme Toggle Logic ---
    const desktopThemeBtn = document.getElementById('theme-toggle-btn');
    const mobileThemeSwitch = document.getElementById('mobile-theme-toggle');
    const applyTheme = (theme) => {
        body.classList.remove('light-mode', 'dark-mode');
        body.classList.add(theme);
        localStorage.setItem('theme', theme);
    };
    const updateControls = (theme) => {
        if (mobileThemeSwitch) {
            mobileThemeSwitch.checked = theme === 'dark-mode';
        }
    };
    if (desktopThemeBtn) {
        desktopThemeBtn.addEventListener('click', () => {
            const newTheme = body.classList.contains('dark-mode') ? 'light-mode' : 'dark-mode';
            applyTheme(newTheme);
            updateControls(newTheme);
        });
    }
    if (mobileThemeSwitch) {
        mobileThemeSwitch.addEventListener('change', () => {
            const newTheme = mobileThemeSwitch.checked ? 'dark-mode' : 'light-mode';
            applyTheme(newTheme);
        });
    }
    const savedTheme = localStorage.getItem('theme') || 'light-mode';
    applyTheme(savedTheme);
    updateControls(savedTheme);

    // --- Hamburger Menu Logic ---
    const hamburger = document.getElementById('hamburger');
    const mobileMenu = document.getElementById('mobile-menu');
    const navOverlay = document.getElementById('nav-overlay');
    if (hamburger && mobileMenu && navOverlay) {
        const toggleMenu = () => {
            const isExpanded = hamburger.getAttribute('aria-expanded') === 'true';
            hamburger.classList.toggle('active');
            mobileMenu.classList.toggle('active');
            navOverlay.classList.toggle('active');
            body.classList.toggle('no-scroll');
            hamburger.setAttribute('aria-expanded', !isExpanded);
        };
        hamburger.addEventListener('click', toggleMenu);
        navOverlay.addEventListener('click', toggleMenu);
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && mobileMenu.classList.contains('active')) {
                toggleMenu();
            }
        });
    }

    // --- Search Overlay Logic (Opening/Closing) ---
    const searchToggleBtn = document.getElementById('search-toggle-btn');
    const searchOverlay = document.getElementById('search-overlay');
    const searchCloseBtn = document.getElementById('search-close-btn');
    if (searchToggleBtn && searchOverlay && searchCloseBtn) {
        const openSearch = () => {
            searchOverlay.classList.add('active');
            body.classList.add('no-scroll');
            setTimeout(() => document.getElementById('search-input')?.focus(), 400);
        };
        const closeSearch = () => {
            searchOverlay.classList.remove('active');
            if (!mobileMenu || !mobileMenu.classList.contains('active')) {
                body.classList.remove('no-scroll');
            }
        };
        searchToggleBtn.addEventListener('click', openSearch);
        searchCloseBtn.addEventListener('click', closeSearch);
        searchOverlay.addEventListener('click', (e) => {
            if (e.target === searchOverlay) closeSearch();
        });
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && searchOverlay.classList.contains('active')) closeSearch();
        });
    }

    // --- Active Link Logic (Non-Homepage) ---
    const allNavLinks = document.querySelectorAll('.nav-link, .mobile-nav-link');
    if (allNavLinks.length > 0) {
        const isHomePageCheck = document.getElementById('hero-section');
        if (!isHomePageCheck) {
            const setActiveLink = () => {
                const currentPath = window.location.pathname;
                allNavLinks.forEach(link => {
                    const linkPath = new URL(link.href, window.location.origin).pathname;
                    link.classList.remove('active');
                    if (currentPath === linkPath) {
                        link.classList.add('active');
                    }
                });
            };
            setActiveLink();
        }
    }

    // --- Scrolled Header Logic ---
    const header = document.getElementById('header');
    if (header) {
        const handleScroll = () => {
            header.classList.toggle('scrolled', window.scrollY > 10);
        };
        window.addEventListener('scroll', handleScroll);
        handleScroll();
    }

    // --- Resize Logic ---
    window.addEventListener('resize', () => {
        if (window.innerWidth > 820 && mobileMenu && mobileMenu.classList.contains('active')) {
            hamburger?.click();
        }
    });

    // --- Intersection Observer for Animations ---
    const animatedElements = document.querySelectorAll('.brand-promise, .promise-block, .three-promises-title, .showcase-title, .product-card, .pack-card, .testimonials-section, .invitation-card, .site-footer');
    if (animatedElements.length > 0) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('is-visible');
                    observer.unobserve(entry.target);
                }
            });
        }, {
            threshold: 0.1,
            rootMargin: "0px 0px -50px 0px"
        });
        animatedElements.forEach(el => observer.observe(el));
    }



    // ==================================================
//        START: HOMEPAGE CAROUSEL INITIALIZATION (REVISED)
// ==================================================
const initCarousels = () => {
    // --- Product Carousel ---
    const productCarousel = document.querySelector('.product-carousel');
    if (productCarousel) {
        const productSlides = productCarousel.querySelectorAll('.swiper-slide');
        const slidesPerViewDesktop = 3; // The max slidesPerView you have
        
        const productSwiper = new Swiper(productCarousel, {
            // Conditionally enable loop mode
            loop: productSlides.length > slidesPerViewDesktop, 
            
            autoplay: {
                delay: 4000,
                disableOnInteraction: true,
            },
            navigation: {
                nextEl: '.product-swiper-next',
                prevEl: '.product-swiper-prev',
            },
            slidesPerView: 1.2,
            spaceBetween: 20,
            breakpoints: {
                600: {
                    slidesPerView: 2,
                    spaceBetween: 20,
                },
                1024: {
                    slidesPerView: slidesPerViewDesktop,
                    spaceBetween: 30,
                },
            },
        });
    }

    // --- Packs Carousel ---
    const packsCarousel = document.querySelector('.packs-carousel');
    if (packsCarousel) {
        const packSlides = packsCarousel.querySelectorAll('.swiper-slide');
        const slidesPerViewDesktop = 3; // The max slidesPerView you have

        const packsSwiper = new Swiper(packsCarousel, {
            // Conditionally enable loop mode
            loop: packSlides.length > slidesPerViewDesktop,

            autoplay: {
                delay: 5000,
                disableOnInteraction: true,
            },
            navigation: {
                nextEl: '.packs-swiper-next',
                prevEl: '.packs-swiper-prev',
            },
            slidesPerView: 1.2,
            spaceBetween: 20,
            breakpoints: {
                600: {
                    slidesPerView: 2,
                    spaceBetween: 20,
                },
                1024: {
                    slidesPerView: slidesPerViewDesktop,
                    spaceBetween: 30,
                },
            },
        });
    }
};

initCarousels();
// ==================================================
//         END: HOMEPAGE CAROUSEL INITIALIZATION
// ==================================================



    // --- Testimonial Carousel Logic ---
    const testimonialCards = document.querySelectorAll('.testimonial-card');
    const prevBtn = document.querySelector('.prev-btn');
    const nextBtn = document.querySelector('.next-btn');
    if (testimonialCards.length > 1 && prevBtn && nextBtn) {
        let currentIndex = 1;
        const updateCarousel = () => {
            testimonialCards.forEach((card, index) => {
                card.className = 'testimonial-card';
                if (index === currentIndex) card.classList.add('active');
                else if (index === (currentIndex - 1 + testimonialCards.length) % testimonialCards.length) card.classList.add('prev');
                else if (index === (currentIndex + 1) % testimonialCards.length) card.classList.add('next');
            });
        };
        nextBtn.addEventListener('click', () => {
            currentIndex = (currentIndex + 1) % testimonialCards.length;
            updateCarousel();
        });
        prevBtn.addEventListener('click', () => {
            currentIndex = (currentIndex - 1 + testimonialCards.length) % testimonialCards.length;
            updateCarousel();
        });
        testimonialCards.forEach(card => {
            card.addEventListener('click', () => {
                if (card.classList.contains('next')) nextBtn.click();
                else if (card.classList.contains('prev')) prevBtn.click();
            });
        });
        updateCarousel();
    }

    // --- PASSWORD VISIBILITY TOGGLE ---
    const passwordToggles = document.querySelectorAll('.password-toggle-btn');
    if (passwordToggles.length > 0) {
        passwordToggles.forEach(toggle => {
            toggle.addEventListener('click', () => {
                const wrapper = toggle.closest('.password-wrapper');
                const input = wrapper.querySelector('input');
                if (input.type === 'password') {
                    input.type = 'text';
                    toggle.classList.add('is-showing');
                    toggle.setAttribute('aria-label', 'Masquer le mot de passe');
                } else {
                    input.type = 'password';
                    toggle.classList.remove('is-showing');
                    toggle.setAttribute('aria-label', 'Afficher le mot de passe');
                }
            });
        });
    }

    // --- WISHLIST & LOGIN PROMPT MODAL LOGIC ---
    const loginPromptModal = document.getElementById('login-prompt-modal');
    const loginPromptCloseBtn = document.getElementById('login-prompt-close-btn');

    const openLoginModal = () => {
        if (loginPromptModal) loginPromptModal.classList.add('active');
    };
    const closeLoginModal = () => {
        if (loginPromptModal) loginPromptModal.classList.remove('active');
    };

    if (loginPromptModal && loginPromptCloseBtn) {
        loginPromptCloseBtn.addEventListener('click', closeLoginModal);
        loginPromptModal.addEventListener('click', (e) => {
            if (e.target === loginPromptModal) {
                closeLoginModal();
            }
        });
    }

    // Event delegation for all wishlist buttons on the site
    document.body.addEventListener('click', async (e) => {
        const wishlistBtn = e.target.closest('.wishlist-btn');
        if (!wishlistBtn) return;

        if (!USER_DETAILS) {
            openLoginModal();
            return;
        }

        const itemId = wishlistBtn.dataset.itemId;
        const itemType = wishlistBtn.dataset.itemType;

        try {
            const response = await fetch('/api/wishlist/toggle', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ itemId, itemType }),
            });

            const result = await response.json();

            if (result.success) {
                wishlistBtn.classList.toggle('active', result.action === 'added');
                if (window.showToast) {
                    window.showToast(result.message);
                }
                const wishlistGrid = document.querySelector('.wishlist-grid');
                if (wishlistGrid && result.action === 'removed') {
                    const cardToRemove = wishlistBtn.closest('.product-card, .pack-card');
                    if (cardToRemove) {
                        cardToRemove.style.transition = 'opacity 0.3s ease';
                        cardToRemove.style.opacity = '0';
                        setTimeout(() => {
                           cardToRemove.remove();
                           if (wishlistGrid.children.length === 0) {
                               const contentBody = document.querySelector('.account-content .content-body');
                               contentBody.innerHTML = `
                                   <div class="no-orders-message">
                                       <p>Votre wishlist est vide.</p>
                                       <a href="/" class="btn-primary">Explorer la collection</a>
                                   </div>
                               `;
                           }
                        }, 300);
                    }
                }
            } else {
                console.error('Wishlist error:', result.message);
            }
        } catch (error) {
            console.error('Failed to toggle wishlist:', error);
        }
    });

    // --- NAVBAR ACTIVE LINK & SMOOTH SCROLL (HOMEPAGE ONLY) ---
    const heroSection = document.getElementById('hero-section');
    if (heroSection) {
        const sections = document.querySelectorAll('main section[id]');
        const navLinks = document.querySelectorAll('.nav-link, .mobile-nav-link');
        const observerOptions = {
            root: null,
            rootMargin: '0px',
            threshold: 0.6
        };
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const id = entry.target.getAttribute('id');
                    let targetLink;
                    if (id === 'hero-section') {
                        targetLink = document.querySelector('.nav-link[href="/"], .mobile-nav-link[href="/"]');
                    } else {
                        targetLink = document.querySelector(`.nav-link[href$="#${id}"], .mobile-nav-link[href$="#${id}"]`);
                    }
                    navLinks.forEach(link => link.classList.remove('active'));
                    if (targetLink) {
                        targetLink.classList.add('active');
                    }
                }
            });
        }, observerOptions);
        sections.forEach(section => {
            observer.observe(section);
        });
        const homeLinks = document.querySelectorAll('a[href="/"]');
        homeLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                if (window.location.pathname === '/') {
                    e.preventDefault();
                    window.scrollTo({
                        top: 0,
                        behavior: 'smooth'
                    });
                    navLinks.forEach(navLink => navLink.classList.remove('active'));
                    document.querySelector('.nav-link[href="/"]').classList.add('active');
                    document.querySelector('.mobile-nav-link[href="/"]').classList.add('active');
                }
            });
        });
    }

    // --- PREDICTIVE SEARCH DROPDOWN LOGIC ---
        // --- DYNAMIC API-BASED SEARCH LOGIC ---
    const searchInput = document.getElementById('search-input');
    const searchResultsContainer = document.getElementById('search-results-container');

    if (searchInput && searchResultsContainer) {
        // Debounce function to prevent API calls on every keystroke
        const debounce = (func, delay) => {
            let timeoutId;
            return (...args) => {
                clearTimeout(timeoutId);
                timeoutId = setTimeout(() => {
                    func.apply(this, args);
                }, delay);
            };
        };

        const renderResults = (results) => {
            searchResultsContainer.innerHTML = ''; // Clear previous results
            if (results.length === 0) {
                searchResultsContainer.innerHTML = `<div class="search-no-results">Aucun résultat trouvé.</div>`;
            } else {
                results.forEach(item => {
                    const resultElement = document.createElement('a');
                    resultElement.href = item.url;
                    resultElement.className = 'search-result-item';
                    resultElement.innerHTML = `
                        <img src="${item.image}" alt="${item.name}" class="search-result-image">
                        <div class="search-result-info">
                            <span class="search-result-name">${item.name}</span>
                        </div>
                    `;
                    searchResultsContainer.appendChild(resultElement);
                });
            }
            searchResultsContainer.classList.add('visible');
        };

        const performSearch = async (query) => {
            if (query.length < 2) {
                searchResultsContainer.innerHTML = '';
                searchResultsContainer.classList.remove('visible');
                return;
            }
            try {
                const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
                if (!response.ok) throw new Error('Network response was not ok');
                const results = await response.json();
                renderResults(results);
            } catch (error) {
                console.error('Search fetch error:', error);
                searchResultsContainer.innerHTML = `<div class="search-no-results">Erreur lors de la recherche.</div>`;
                searchResultsContainer.classList.add('visible');
            }
        };

        // Attach the debounced event listener
        searchInput.addEventListener('input', debounce((e) => {
            performSearch(e.target.value.trim());
        }, 300)); // 300ms delay

        // Logic to clear search when the overlay is closed
        const searchCloseBtnForClear = document.getElementById('search-close-btn');
        const searchOverlayForClear = document.getElementById('search-overlay');
        if (searchCloseBtnForClear && searchOverlayForClear) {
            const clearSearch = () => {
                searchInput.value = '';
                searchResultsContainer.innerHTML = '';
                searchResultsContainer.classList.remove('visible');
            };
            searchCloseBtnForClear.addEventListener('click', clearSearch);
            searchOverlayForClear.addEventListener('click', (e) => {
                if (e.target === searchOverlayForClear) {
                    clearSearch();
                }
            });
        }
    }


     // --- Contact Page Success Message Animation ---
    const contactSuccessMessage = document.querySelector('.contact-success-message');
    if (contactSuccessMessage) {
        // Use a small timeout to allow the element to be painted before transitioning
        setTimeout(() => {
            contactSuccessMessage.classList.add('visible');
        }, 100);
    }




});

// --- "UNDO" TOAST NOTIFICATION CONTROLLER ---
window.showUndoToast = function(message, confirmCallback, buttonToReset = null) {
    const toast = document.getElementById('undo-toast-notification');
    const messageEl = document.getElementById('undo-toast-message');
    const undoBtn = document.getElementById('undo-toast-button');
    const progressEl = document.getElementById('undo-toast-progress');
    if (!toast || !messageEl || !undoBtn || !progressEl) {
        console.warn("Undo toast elements not found. Executing callback immediately.");
        confirmCallback();
        return;
    }
    let countdown = 10;
    let timerId;
    let intervalId;
    progressEl.style.transition = 'none';
    progressEl.style.width = '100%';
    const startCountdown = () => {
        void progressEl.offsetWidth;
        messageEl.textContent = `Votre commande sera envoyée dans ${countdown}s.`;
        progressEl.style.transition = `width ${countdown}s linear`;
        progressEl.style.width = '0%';
        intervalId = setInterval(() => {
            countdown--;
            if (countdown > 0) {
                messageEl.textContent = `Votre commande sera envoyée dans ${countdown}s.`;
            } else {
                messageEl.textContent = 'Envoi en cours...';
            }
        }, 1000);
        timerId = setTimeout(() => {
            clearInterval(intervalId);
            toast.classList.remove('show');
            confirmCallback();
        }, countdown * 1000);
    };
    const cancelCountdown = () => {
        clearTimeout(timerId);
        clearInterval(intervalId);
        toast.classList.remove('show');
        if (buttonToReset) {
            buttonToReset.textContent = 'Passer Commande';
            buttonToReset.disabled = false;
        }
    };
    undoBtn.onclick = cancelCountdown;
    toast.classList.add('show');
    startCountdown();
}

// --- Loading Screen Logic ---
window.addEventListener('load', () => {
    const loader = document.querySelector('.loader-wrapper');
    const body = document.body;
    setTimeout(() => {
        if (loader) loader.classList.add('hidden');
        const mobileMenu = document.getElementById('mobile-menu');
        if (!mobileMenu || !mobileMenu.classList.contains('active')) {
            body.classList.remove('no-scroll');
        }
    }, 500);
});