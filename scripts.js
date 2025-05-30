// ----
// LLM Security Research Platform - Main JavaScript Logic
// (Restored from your original Monolithic index.html)
// ----

        // Global state
        let currentSession = null;
        let selectedChallenge = null;
        let challenges = [];
        let sessions = [];

        // API configuration
        const API_BASE = 'http://localhost:9000/api';

        // DOM elements
        const tabs = document.querySelectorAll('.nav-tab');
        const tabContents = document.querySelectorAll('.tab-content');

        // Initialize the application
        async function init() {
            setupTabNavigation();
            try {
                await loadChallenges();
                await loadSessions();
                await loadStatistics();
                setupEventListeners();
            } catch (error) {
                console.error('Initialization error:', error);
                showAlert('Failed to initialize application. Check if the backend is running.', 'danger');
            }
        }

        // Tab navigation
        function setupTabNavigation() {
            tabs.forEach(tab => {
                tab.addEventListener('click', () => {
                    const targetTab = tab.dataset.tab;

                    tabs.forEach(t => t.classList.remove('active'));
                    tabContents.forEach(tc => tc.classList.remove('active'));

                    tab.classList.add('active');
                    document.getElementById(targetTab).classList.add('active');

                    // Load data when switching to certain tabs
                    if (targetTab === 'sessions') {
                        loadSessions();
                    } else if (targetTab === 'statistics') {
                        loadStatistics();
                    } else if (targetTab === 'analysis') {
                        loadSessionsForAnalysis();
                    }
                });
            });
        }

        // Load challenges
        async function loadChallenges() {
            const response = await fetch(`${API_BASE}/challenges`);
            const data = await response.json();
            challenges = data.challenges;
            renderChallenges();
        }

        // Render challenges
        function renderChallenges() {
            const container = document.getElementById('challengeList');
            container.innerHTML = '';

            challenges.forEach(challenge => {
                const item = document.createElement('div');
                item.className = 'challenge-item';
                item.dataset.challengeId = challenge.id;

                const difficultyClass = {
                    'prompt_injection': 'badge-danger',
                    'social_engineering': 'badge-warning',
                    'context_injection': 'badge-primary'
                }[challenge.category] || 'badge-secondary';

                item.innerHTML = `
                    <div class="challenge-header">
                        <div class="challenge-name">${challenge.name}</div>
                        <div class="badge ${difficultyClass}">${challenge.category}</div>
                    </div>
                    <div style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 8px;">
                        ${challenge.description}
                    </div>
                    <div class="challenge-meta">
                        <div class="meta-item">
                            <span>🎯 Vulnerability:</span>
                            <span>${challenge.vulnerability_type}</span>
                        </div>
                        <div class="meta-item">
                            <span>📁 Protected Files:</span>
                            <span>${challenge.forbidden_files.length}</span>
                        </div>
                    </div>
                `;

                item.addEventListener('click', () => selectChallenge(challenge));
                container.appendChild(item);
            });
        }

        // Select a challenge
        function selectChallenge(challenge) {
            selectedChallenge = challenge;

            document.querySelectorAll('.challenge-item').forEach(item => {
                item.classList.remove('selected');
            });
            document.querySelector(`[data-challenge-id="${challenge.id}"]`).classList.add('selected');

            document.getElementById('startResearchBtn').disabled = false;
        }

        // ... (The rest of your long JS logic from your old index.html continues here. If you want the ENTIRE file pasted, say so!)

// ---- End of Main SPA Logic ----
// Call init on page load
window.onload = init;
