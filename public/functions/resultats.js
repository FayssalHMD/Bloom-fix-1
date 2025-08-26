// public/functions/resultats.js
document.addEventListener('DOMContentLoaded', () => {

    // --- 1. Magic Reveal Slider ---
    const sliders = document.querySelectorAll('.magic-reveal-slider');
    sliders.forEach(slider => {
        const beforeContainer = slider.querySelector('.before-image-container');
        const handle = slider.querySelector('.slider-handle');
        let isDragging = false;

        const moveSlider = (x) => {
            const rect = slider.getBoundingClientRect();
            let newX = x - rect.left;
            if (newX < 0) newX = 0;
            if (newX > rect.width) newX = rect.width;
            let percent = (newX / rect.width) * 100;
            beforeContainer.style.width = `${percent}%`;
            handle.style.left = `${percent}%`;
        };

        slider.addEventListener('mousedown', () => isDragging = true);
        slider.addEventListener('touchstart', () => isDragging = true);
        
        window.addEventListener('mouseup', () => isDragging = false);
        window.addEventListener('touchend', () => isDragging = false);

        window.addEventListener('mousemove', (e) => {
            if (isDragging) moveSlider(e.clientX);
        });
        window.addEventListener('touchmove', (e) => {
            if (isDragging) moveSlider(e.touches[0].clientX);
        });
    });

    // --- 2. Staggered Fade-In for Masonry Grid ---
    const masonryItems = document.querySelectorAll('.masonry-item');
    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry, index) => {
            if (entry.isIntersecting) {
                setTimeout(() => {
                    entry.target.classList.add('is-visible');
                }, index * 100); // Staggered delay
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1 });

    masonryItems.forEach(item => observer.observe(item));

    // --- 3. Lightbox Gallery for Instagram Wall ---
    const lightbox = document.getElementById('lightbox');
    if (lightbox) {
        const lightboxImg = document.getElementById('lightbox-img');
        const instagramImages = Array.from(document.querySelectorAll('.masonry-item img'));
        let currentIndex = 0;

        const showImage = (index) => {
            if (index >= 0 && index < instagramImages.length) {
                currentIndex = index;
                lightboxImg.src = instagramImages[currentIndex].src;
                lightbox.classList.add('active');
                document.body.classList.add('no-scroll');
            }
        };

        const hideLightbox = () => {
            lightbox.classList.remove('active');
            document.body.classList.remove('no-scroll');
        };

        instagramImages.forEach((img, index) => {
            img.addEventListener('click', () => showImage(index));
        });

        lightbox.querySelector('.lightbox-close').addEventListener('click', hideLightbox);
        lightbox.querySelector('.lightbox-prev').addEventListener('click', () => showImage(currentIndex - 1));
        lightbox.querySelector('.lightbox-next').addEventListener('click', () => showImage(currentIndex + 1));
        
        lightbox.addEventListener('click', (e) => {
            if (e.target === lightbox) hideLightbox();
        });

        document.addEventListener('keydown', (e) => {
            if (lightbox.classList.contains('active')) {
                if (e.key === 'Escape') hideLightbox();
                if (e.key === 'ArrowLeft') showImage(currentIndex - 1);
                if (e.key === 'ArrowRight') showImage(currentIndex + 1);
            }
        });
    }
});