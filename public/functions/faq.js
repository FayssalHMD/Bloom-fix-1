// public/functions/faq.js
document.addEventListener('DOMContentLoaded', () => {
    const faqPage = document.querySelector('.faq-page');
    if (!faqPage) return; // Only run this script on the FAQ page

    const accordionItems = document.querySelectorAll('.faq-item');
    const categoryTabs = document.querySelectorAll('.category-tab');
    const searchInput = document.getElementById('faq-search-input');
    const noResultsMessage = document.getElementById('faq-no-results');

    // 1. Accordion Functionality
    accordionItems.forEach(item => {
        const question = item.querySelector('.faq-question');
        question.addEventListener('click', () => {
            // Close other open items
            accordionItems.forEach(otherItem => {
                if (otherItem !== item && otherItem.classList.contains('active')) {
                    otherItem.classList.remove('active');
                }
            });
            // Toggle the clicked item
            item.classList.toggle('active');
        });
    });

    // Function to filter items based on search and category
    const filterItems = () => {
        const searchTerm = searchInput.value.toLowerCase().trim();
        const activeCategory = document.querySelector('.category-tab.active').dataset.category;
        let itemsFound = 0;

        accordionItems.forEach(item => {
            const questionText = item.querySelector('.faq-question span').textContent.toLowerCase();
            const answerText = item.querySelector('.faq-answer p').textContent.toLowerCase();
            const itemCategory = item.dataset.category;

            const matchesCategory = activeCategory === 'all' || itemCategory === activeCategory;
            const matchesSearch = questionText.includes(searchTerm) || answerText.includes(searchTerm);

            if (matchesCategory && matchesSearch) {
                item.classList.remove('hidden');
                itemsFound++;
            } else {
                item.classList.add('hidden');
            }
        });

        // Show or hide the "no results" message
        if (itemsFound === 0) {
            noResultsMessage.style.display = 'block';
        } else {
            noResultsMessage.style.display = 'none';
        }
    };

    // 2. Category Filtering
    categoryTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            categoryTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            filterItems();
        });
    });

    // 3. Live Search Filtering
    searchInput.addEventListener('input', filterItems);
});