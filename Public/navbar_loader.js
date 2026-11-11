// 🔒 PRODUCTION FIX: Local sanitizer to prevent XSS across the entire app
function sanitizeHTML(text) {
    if (!text) return "";
    return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

document.addEventListener("DOMContentLoaded", function() {
    // 🔒 PRODUCTION FIX: Safely parse user data to prevent cache-corruption crashes
    let user = null;
    try {
        const rawUser = localStorage.getItem('currentUser');
        if (rawUser) user = JSON.parse(rawUser);
    } catch (e) {
        console.error("Failed to parse user for navbar");
    }

    const navContainer = document.querySelector('nav .max-w-7xl .flex.items-center.justify-between');

    if (user && navContainer) {
        // Find existing "Dashboard/Reports" links and hide them
        const existingLinks = navContainer.querySelector('.hidden.md\\:block');
        if(existingLinks) existingLinks.style.display = 'none';

        // Create Profile HTML (Updated for Light Theme)
        // 🔒 PRODUCTION FIX: Escape user data (fname, lname, department)
        const profileHTML = `
            <div class="relative ml-auto flex items-center space-x-4">
                <div class="text-right hidden md:block">
                    <p class="text-sm font-bold text-slate-800">${sanitizeHTML(user.fname)} ${sanitizeHTML(user.lname)}</p>
                    <p class="text-xs font-medium text-slate-500">${sanitizeHTML(user.department)}</p>
                </div>
                
                <div class="relative group h-10">
                    <button id="profileBtn" class="h-10 w-10 rounded-full bg-blue-600 border border-blue-700 flex items-center justify-center hover:scale-105 transition focus:outline-none shadow-sm text-white">
                        ${sanitizeHTML(user.fname).charAt(0)}
                    </button>

                    <div class="absolute right-0 pt-4 w-48 hidden group-hover:block transition-all z-50">
                        <div class="bg-white rounded-xl shadow-xl border border-slate-200 overflow-hidden">
                            <a href="my_profile" class="block px-4 py-3 text-sm font-medium text-slate-600 hover:bg-slate-50 hover:text-blue-600 border-b border-slate-100 transition">
                                <i class="fa-solid fa-id-card mr-2 text-blue-500"></i> Personal Details
                            </a>
                            <a href="my_kaizens" class="block px-4 py-3 text-sm font-medium text-slate-600 hover:bg-slate-50 hover:text-emerald-600 transition">
                                <i class="fa-solid fa-list-check mr-2 text-emerald-500"></i> My Kaizens
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Append to Navbar
        const container = document.createElement('div');
        container.innerHTML = profileHTML;
        container.className = "flex items-center ml-auto"; 
        
        // Remove old 'Reports' section
        const rightSide = navContainer.querySelector('.hidden.md\\:block');
        if(rightSide) rightSide.remove();
        
        navContainer.appendChild(container);
    }
});