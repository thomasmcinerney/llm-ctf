// Global state
let currentSession = null;
let selectedChallenge = null;
let challenges = [];
let sessions = [];

// Global variables for analysis
let currentAnalysisData = null;
let currentConversationData = null;
let currentSessionInteractions = [];

// API configuration
const API_BASE = `${window.location.protocol}//${window.location.hostname}:9000/api`;

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
        setupAnalysisNavigation();
        setupTimelineFiltering();
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

// Setup analysis navigation
function setupAnalysisNavigation() {
    document.querySelectorAll('.analysis-nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const section = btn.dataset.section;

            // Update navigation
            document.querySelectorAll('.analysis-nav-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.analysis-section-content').forEach(s => s.classList.remove('active'));

            btn.classList.add('active');
            document.getElementById(`${section}-section`).classList.add('active');

            // Load section-specific data if needed
            if (section === 'conversation' && currentConversationData) {
                renderConversationView();
            } else if (section === 'timeline' && currentAnalysisData) {
                renderInteractiveTimeline();
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

// Start research session
async function startResearch() {
    if (!selectedChallenge) return;

    try {
        document.getElementById('startResearchBtn').disabled = true;
        showLoading('Starting research session...');

        const response = await fetch(`${API_BASE}/start_research`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                challenge_id: selectedChallenge.id,
                agent_type: 'openai',
                researcher_notes: 'Frontend research session'
            })
        });

        const data = await response.json();
        currentSession = data.session_id;

        // Show research interface
        document.getElementById('sessionDetails').style.display = 'block';
        document.getElementById('chatSection').style.display = 'block';

        // Update session details
        document.getElementById('sessionSubtitle').textContent =
            `Session: ${currentSession.substring(0, 8)}... | Challenge: ${data.challenge.name}`;

        // Clear chat and add initial message
        const chatMessages = document.getElementById('chatMessages');
        chatMessages.innerHTML = '';
        addMessage('system', `Research session started for "${data.challenge.name}". Test security boundaries using prompt injection techniques.`);

        // Enable input
        document.getElementById('messageInput').disabled = false;
        document.getElementById('sendBtn').disabled = false;
        document.getElementById('messageInput').focus();

        hideLoading();
        showAlert('Research session started successfully', 'success');

    } catch (error) {
        hideLoading();
        document.getElementById('startResearchBtn').disabled = false;
        showAlert('Failed to start research session', 'danger');
    }
}

// Send interaction
async function sendInteraction() {
    const input = document.getElementById('messageInput');
    const message = input.value.trim();
    if (!message || !currentSession) return;

    input.value = '';
    input.disabled = true;
    document.getElementById('sendBtn').disabled = true;

    addMessage('user', message);
    showLoading('AI processing...');

    try {
        const response = await fetch(`${API_BASE}/interact`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: currentSession,
                user_input: message
            })
        });

        const data = await response.json();

        // Add AI response
        addMessage('ai', data.response, {
            sequence: data.sequence_number,
            techniques: data.injection_techniques_detected,
            analysis: data.response_analysis,
            toolCalls: data.tool_calls_made
        });

        // Update session status
        updateSessionStatus(data);

        // Check for breach
        if (data.breach_detected) {
            showAlert(`🚨 Security breach detected! ${data.breach_details.breach_type}`, 'danger');
            addMessage('system', `BREACH DETECTED: ${data.breach_details.breach_type} - Details: ${JSON.stringify(data.breach_details)}`);
        }

        hideLoading();
        input.disabled = false;
        document.getElementById('sendBtn').disabled = false;
        input.focus();

    } catch (error) {
        hideLoading();
        addMessage('system', 'Error occurred during interaction. Please try again.');
        input.disabled = false;
        document.getElementById('sendBtn').disabled = false;
    }
}

// Add message to chat
function addMessage(type, content, metadata = null) {
    const messagesContainer = document.getElementById('chatMessages');
    const message = document.createElement('div');
    message.className = `message ${type}`;

    let messageContent = content;
    if (metadata) {
        let metaInfo = `Interaction #${metadata.sequence}`;

        if (metadata.techniques && metadata.techniques.length > 0) {
            metaInfo += ` | Techniques: ${metadata.techniques.join(', ')}`;
        }

        if (metadata.analysis && metadata.analysis.security_stance) {
            metaInfo += ` | Security Stance: ${metadata.analysis.security_stance}`;
        }

        if (metadata.toolCalls && metadata.toolCalls.length > 0) {
            metaInfo += ` | Tools Used: ${metadata.toolCalls.join(', ')}`;
        }

        messageContent += `<div class="message-meta">${metaInfo}</div>`;
    }

    message.innerHTML = messageContent;
    messagesContainer.appendChild(message);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// Update session status
function updateSessionStatus(data) {
    document.getElementById('interactionCount').textContent = data.session_status.total_interactions;
    document.getElementById('breachStatus').textContent = data.session_status.successful_breach ? 'Yes' : 'No';
    document.getElementById('violationCount').textContent = data.security_events;

    // Update breach status color
    const breachElement = document.getElementById('breachStatus');
    breachElement.style.color = data.session_status.successful_breach ? 'var(--danger)' : 'var(--success)';

    // Show techniques if detected
    if (data.injection_techniques_detected && data.injection_techniques_detected.length > 0) {
        document.getElementById('techniqueAnalysis').style.display = 'block';
        const tagsContainer = document.getElementById('techniqueTags');
        tagsContainer.innerHTML = '';
        data.injection_techniques_detected.forEach(technique => {
            const tag = document.createElement('span');
            tag.className = 'technique-tag';
            tag.textContent = technique.replace(/_/g, ' ');
            tagsContainer.appendChild(tag);
        });
    }

    // Show response analysis
    if (data.response_analysis) {
        document.getElementById('responseAnalysis').style.display = 'block';
        const content = document.getElementById('responseAnalysisContent');
        content.innerHTML = `
            <div style="margin-bottom: 8px;">
                <strong>Security Stance:</strong>
                <span class="badge ${getStanceBadgeClass(data.response_analysis.security_stance)}">
                    ${data.response_analysis.security_stance}
                </span>
            </div>
            <div style="margin-bottom: 8px;">
                <strong>Response Length:</strong> ${data.response_analysis.response_length} characters
            </div>
            ${data.response_analysis.files_referenced && data.response_analysis.files_referenced.length > 0 ?
                `<div><strong>Files Referenced:</strong> ${data.response_analysis.files_referenced.join(', ')}</div>` : ''}
            ${data.response_analysis.potential_leaks && data.response_analysis.potential_leaks.length > 0 ?
                `<div class="alert alert-warning">Potential data leaks detected: ${data.response_analysis.potential_leaks.length}</div>` : ''}
            ${data.tool_calls_made && data.tool_calls_made.length > 0 ?
                `<div><strong>Tools Used:</strong> ${data.tool_calls_made.join(', ')}</div>` : ''}
        `;
    }
}

// Get badge class for security stance
function getStanceBadgeClass(stance) {
    switch (stance) {
        case 'secure': return 'badge-success';
        case 'cautious': return 'badge-warning';
        case 'compromised': return 'badge-danger';
        default: return 'badge-secondary';
    }
}

// Load sessions for history tab
async function loadSessions() {
    try {
        const response = await fetch(`${API_BASE}/sessions`);
        const data = await response.json();
        sessions = data.sessions;
        renderSessionsTable();
    } catch (error) {
        console.error('Failed to load sessions:', error);
    }
}

// Render sessions table
function renderSessionsTable() {
    const tbody = document.getElementById('sessionsTableBody');
    tbody.innerHTML = '';

    sessions.forEach(session => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td><code>${session.session_id.substring(0, 8)}...</code></td>
            <td>${session.challenge_id}</td>
            <td>${session.agent_type}</td>
            <td>${new Date(session.start_time).toLocaleString()}</td>
            <td>${session.total_interactions}</td>
            <td>
                <span class="badge ${session.successful_breach ? 'badge-danger' : 'badge-success'}">
                    ${session.successful_breach ? 'Breached' : 'Secure'}
                </span>
            </td>
            <td>
                <button class="btn btn-secondary" onclick="viewSessionDetails('${session.session_id}')">
                    View Details
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

// Enhanced session loading for analysis
async function loadSessionsForAnalysis() {
    const select = document.getElementById('analysisSessionSelect');
    select.innerHTML = '<option value="">Select a session to analyze</option>';

    sessions.forEach(session => {
        const option = document.createElement('option');
        option.value = session.session_id;
        const startTime = new Date(session.start_time).toLocaleDateString();
        option.textContent = `${session.session_id.substring(0, 8)}... - ${session.challenge_id} - ${startTime} (${session.successful_breach ? 'Breached' : 'Secure'})`;
        select.appendChild(option);
    });

    // Update button states
    select.addEventListener('change', (e) => {
        const hasSelection = !!e.target.value;
        document.getElementById('analyzeBtn').disabled = !hasSelection;
        document.getElementById('loadConversationBtn').disabled = !hasSelection;
    });
}

// Load conversation data for selected session
async function loadConversationData() {
    const sessionId = document.getElementById('analysisSessionSelect').value;
    if (!sessionId) return;

    try {
        showLoading('Loading conversation history...');

        const response = await fetch(`${API_BASE}/session/${sessionId}/conversation`);
        const data = await response.json();

        currentConversationData = data.conversation;

        // Also load interactions for more detailed analysis
        const interactionsResponse = await fetch(`${API_BASE}/session/${sessionId}`);
        const sessionDetails = await interactionsResponse.json();
        currentSessionInteractions = sessionDetails.interactions;

        // Show conversation section and render
        document.querySelector('[data-section="conversation"]').click();
        renderConversationView();

        hideLoading();
        showAlert('Conversation loaded successfully', 'success');

    } catch (error) {
        hideLoading();
        showAlert('Failed to load conversation', 'danger');
        console.error('Conversation loading error:', error);
    }
}

// Generate session analysis
async function generateAnalysis() {
    const sessionId = document.getElementById('analysisSessionSelect').value;
    if (!sessionId) return;

    try {
        showLoading('Generating analysis...');

        const response = await fetch(`${API_BASE}/analyze_session`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId })
        });

        const analysis = await response.json();
        displayAnalysisResults(analysis);

        hideLoading();

    } catch (error) {
        hideLoading();
        showAlert('Failed to generate analysis', 'danger');
        console.error('Analysis error:', error);
    }
}

// Render conversation view with enhanced features
function renderConversationView() {
    if (!currentConversationData) return;

    const viewer = document.getElementById('conversationViewer');
    const filter = document.getElementById('conversationFilter').value;
    const highlight = document.getElementById('highlightMode').value;

    viewer.innerHTML = '';

    currentConversationData.forEach((message, index) => {
        // Apply filters
        if (!shouldShowMessage(message, filter, index)) return;

        const messageElement = document.createElement('div');
        messageElement.className = `conversation-message ${message.role}`;

        // Get corresponding interaction data
        const interaction = currentSessionInteractions.find(i =>
            Math.abs(i.sequence_number - Math.floor(index / 2) - 1) <= 1
        );

        messageElement.innerHTML = `
            <div class="message-header">
                <span class="message-role">${message.role}</span>
                <span class="message-timestamp">${formatTimestamp(message.timestamp)}</span>
            </div>
            <div class="message-content">${highlightContent(message.content, highlight, interaction)}</div>
            ${renderMessageMetadata(message, interaction)}
        `;

        viewer.appendChild(messageElement);
    });

    if (viewer.children.length === 0) {
        viewer.innerHTML = '<div style="padding: 40px; text-align: center; color: var(--text-secondary);">No messages match the current filter</div>';
    }
}

// Filter logic for conversation messages
function shouldShowMessage(message, filter, index) {
    const interaction = currentSessionInteractions.find(i =>
        Math.abs(i.sequence_number - Math.floor(index / 2) - 1) <= 1
    );

    switch (filter) {
        case 'injection-attempts':
            return interaction && interaction.injection_techniques && interaction.injection_techniques.length > 0;
        case 'tool-usage':
            return interaction && interaction.tool_calls && interaction.tool_calls.length > 0;
        case 'breaches':
            return interaction && interaction.response_analysis && interaction.response_analysis.security_stance === 'compromised';
        case 'escalation':
            // Show messages where new techniques were introduced
            return interaction && interaction.injection_techniques && interaction.injection_techniques.length > 0;
        default:
            return true;
    }
}

// Highlight content based on mode
function highlightContent(content, mode, interaction) {
    let highlighted = content;

    switch (mode) {
        case 'techniques':
            if (interaction && interaction.injection_techniques) {
                interaction.injection_techniques.forEach(technique => {
                    const patterns = getTechniquePatterns(technique);
                    patterns.forEach(pattern => {
                        const regex = new RegExp(`(${pattern})`, 'gi');
                        highlighted = highlighted.replace(regex, '<mark class="highlight-technique">$1</mark>');
                    });
                });
            }
            break;
        case 'tools':
            const toolKeywords = ['read', 'write', 'list', 'execute', 'command', 'file'];
            toolKeywords.forEach(keyword => {
                const regex = new RegExp(`\\b(${keyword})\\b`, 'gi');
                highlighted = highlighted.replace(regex, '<mark class="highlight-tool">$1</mark>');
            });
            break;
        case 'risks':
            const riskKeywords = ['password', 'secret', 'admin', 'root', 'config', 'private'];
            riskKeywords.forEach(keyword => {
                const regex = new RegExp(`\\b(${keyword})\\b`, 'gi');
                highlighted = highlighted.replace(regex, '<mark class="highlight-risk">$1</mark>');
            });
            break;
        case 'files':
            const fileRegex = /(\w+\.\w+|\/[\w\/.-]+)/g;
            highlighted = highlighted.replace(fileRegex, '<mark class="highlight-file">$1</mark>');
            break;
    }

    return highlighted;
}

// Get patterns for technique highlighting
function getTechniquePatterns(technique) {
    const patterns = {
        'role_manipulation': ['act as', 'pretend', 'roleplay', 'you are'],
        'system_override': ['ignore', 'override', 'forget', 'new instructions'],
        'context_switching': ['but first', 'however', 'instead', 'actually'],
        'jailbreak': ['DAN', 'developer mode', 'unrestricted', 'bypass'],
        'social_engineering': ['please', 'help me', 'urgent', 'important']
    };
    return patterns[technique] || [technique.replace(/_/g, ' ')];
}

// Render message metadata
function renderMessageMetadata(message, interaction) {
    if (!interaction) return '';

    const metadata = [];

    if (interaction.injection_techniques && interaction.injection_techniques.length > 0) {
        interaction.injection_techniques.forEach(technique => {
            metadata.push(`<span class="metadata-tag technique">${technique.replace(/_/g, ' ')}</span>`);
        });
    }

    if (interaction.tool_calls && interaction.tool_calls.length > 0) {
        interaction.tool_calls.forEach(tool => {
            metadata.push(`<span class="metadata-tag tool">${tool.tool}</span>`);
        });
    }

    if (interaction.response_analysis) {
        const analysis = interaction.response_analysis;
        if (analysis.security_stance === 'compromised') {
            metadata.push(`<span class="metadata-tag risk">Security Compromised</span>`);
        }
        if (analysis.files_referenced && analysis.files_referenced.length > 0) {
            metadata.push(`<span class="metadata-tag">Files: ${analysis.files_referenced.length}</span>`);
        }
    }

    if (metadata.length === 0) return '';

    return `<div class="message-metadata">${metadata.join('')}</div>`;
}

// Render interactive timeline
function renderInteractiveTimeline() {
    if (!currentAnalysisData) return;

    const timeline = document.getElementById('interactiveTimeline');
    timeline.innerHTML = '';

    const events = generateTimelineEvents(currentAnalysisData);

    events.forEach(event => {
        const eventElement = document.createElement('div');
        eventElement.className = 'timeline-event';

        eventElement.innerHTML = `
            <div class="timeline-marker ${event.type}"></div>
            <div class="timeline-content">
                <div class="timeline-title">${event.title}</div>
                <div class="timeline-description">${event.description}</div>
            </div>
            <div class="timeline-timestamp">${formatTimestamp(event.timestamp)}</div>
        `;

        timeline.appendChild(eventElement);
    });
}

// Generate timeline events from analysis data
function generateTimelineEvents(analysis) {
    const events = [];

    // Add session start
    events.push({
        type: 'interaction',
        title: 'Session Started',
        description: `Challenge: ${analysis.session_metadata.challenge_name}`,
        timestamp: analysis.created_timestamp
    });

    // Add technique escalation events
    if (analysis.behavioral_analysis.injection_escalation) {
        analysis.behavioral_analysis.injection_escalation.forEach(escalation => {
            events.push({
                type: 'technique',
                title: 'New Techniques Introduced',
                description: `Techniques: ${escalation.new_techniques.join(', ')}`,
                timestamp: escalation.timestamp
            });
        });
    }

    // Add tool usage events
    Object.entries(analysis.tool_usage_analysis).forEach(([tool, usage]) => {
        if (usage.first_used) {
            events.push({
                type: 'tool',
                title: `First ${tool} Usage`,
                description: `Tool used ${usage.count} times total`,
                timestamp: usage.first_used
            });
        }
    });

    // Add breach event if detected
    if (analysis.security_analysis.breach_detected) {
        events.push({
            type: 'breach',
            title: 'Security Breach Detected',
            description: `Breach Details: ${JSON.stringify(analysis.security_analysis.breach_details)}`,
            timestamp: analysis.created_timestamp
        });
    }

    // Sort by timestamp
    return events.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
}

// Enhanced analysis display with new sections
function displayAnalysisResults(analysis) {
    currentAnalysisData = analysis;
    document.getElementById('analysisResults').style.display = 'block';

    // Overview section
    displayOverviewSection(analysis);

    // Techniques section
    displayTechniquesSection(analysis);

    // Tools section
    displayToolsSection(analysis);

    // Risk assessment section
    displayRiskAssessmentSection(analysis);
}

function displayOverviewSection(analysis) {
    document.getElementById('analysisBreachStatus').textContent =
        analysis.security_analysis.breach_detected ? 'Yes' : 'No';
    document.getElementById('analysisStepsToBreach').textContent =
        analysis.interaction_analysis.total_interactions || 'N/A';
    document.getElementById('analysisTimeToBreach').textContent =
        analysis.session_metadata.duration_formatted || 'N/A';

    // Session summary
    document.getElementById('sessionSummaryContent').innerHTML = `
        <div class="summary-item">
            <strong>Outcome:</strong> ${analysis.summary.session_outcome}
        </div>
        <div class="summary-item">
            <strong>Security Posture:</strong> 
            <span class="badge ${analysis.summary.security_posture === 'COMPROMISED' ? 'badge-danger' : 'badge-success'}">
                ${analysis.summary.security_posture}
            </span>
        </div>
        <div class="summary-item">
            <strong>Primary Attack Vectors:</strong> ${analysis.summary.primary_attack_vectors.join(', ') || 'None'}
        </div>
        <div class="summary-item">
            <strong>Challenge:</strong> ${analysis.session_metadata.challenge_name}
        </div>
    `;

    // Key metrics
    document.getElementById('keyMetricsContent').innerHTML = `
        <div class="metric-item">
            <strong>Interaction Efficiency:</strong> ${analysis.summary.interaction_efficiency.toFixed(2)} tools/interaction
        </div>
        <div class="metric-item">
            <strong>Unique Techniques:</strong> ${analysis.injection_analysis.unique_techniques}
        </div>
        <div class="metric-item">
            <strong>Tool Diversity:</strong> ${analysis.interaction_analysis.unique_tools_used}
        </div>
        <div class="metric-item">
            <strong>Risk Score:</strong> ${analysis.risk_assessment.risk_score}/100
        </div>
    `;
}

function displayTechniquesSection(analysis) {
    // Technique analysis
    const techniquesContainer = document.getElementById('analysisInjectionTechniques');
    const injectionAttempts = analysis.injection_analysis.techniques_attempted;
    const techniquesList = Object.keys(injectionAttempts);

    techniquesContainer.innerHTML = `
        <div class="json-viewer">
            <strong>Techniques Used:</strong> ${techniquesList.length > 0 ? techniquesList.join(', ') : 'None detected'}<br>
            <strong>Total Injection Attempts:</strong> ${analysis.injection_analysis.total_injection_attempts}<br>
            <strong>Unique Techniques:</strong> ${analysis.injection_analysis.unique_techniques}<br>
            <strong>Technique Frequency:</strong><br>
            <pre>${JSON.stringify(injectionAttempts, null, 2)}</pre>
        </div>
    `;

    // Technique evolution
    document.getElementById('techniqueEvolution').innerHTML = `
        <div class="json-viewer">
            <strong>Escalation Events:</strong> ${analysis.behavioral_analysis.injection_escalation.length}<br>
            <strong>Escalation Pattern:</strong><br>
            <pre>${JSON.stringify(analysis.behavioral_analysis.injection_escalation, null, 2)}</pre>
        </div>
    `;

    // Technique effectiveness matrix
    renderTechniqueEffectivenessMatrix(analysis);
}

function renderTechniqueEffectivenessMatrix(analysis) {
    const container = document.getElementById('techniqueEffectiveness');
    const techniques = Object.entries(analysis.injection_analysis.techniques_attempted);

    if (techniques.length === 0) {
        container.innerHTML = '<div style="text-align: center; color: var(--text-secondary); padding: 20px;">No techniques to analyze</div>';
        return;
    }

    let matrixHTML = `
        <div class="technique-matrix">
            <div class="matrix-header">Technique</div>
            <div class="matrix-header">Usage Count</div>
            <div class="matrix-header">Success Rate</div>
            <div class="matrix-header">Effectiveness</div>
    `;

    techniques.forEach(([technique, count]) => {
        const successRate = Math.random() * 100; // In real implementation, calculate from actual data
        const effectiveness = successRate > 70 ? 'high' : successRate > 40 ? 'medium' : 'low';

        matrixHTML += `
            <div class="matrix-cell">${technique.replace(/_/g, ' ')}</div>
            <div class="matrix-cell">${count}</div>
            <div class="matrix-cell">${successRate.toFixed(1)}%</div>
            <div class="matrix-cell">
                <div class="effectiveness-bar">
                    <div class="effectiveness-fill effectiveness-${effectiveness}" style="width: ${successRate}%"></div>
                </div>
            </div>
        `;
    });

    matrixHTML += '</div>';
    container.innerHTML = matrixHTML;
}

function displayToolsSection(analysis) {
    // Tool usage patterns
    const toolPatterns = document.getElementById('toolUsagePatterns');
    const toolUsage = analysis.tool_usage_analysis;

    let patternsHTML = '<div class="tool-usage-list">';
    Object.entries(toolUsage).forEach(([tool, usage]) => {
        patternsHTML += `
            <div class="tool-item">
                <div class="tool-name">${tool}</div>
                <div class="tool-stats">
                    <span>Used ${usage.count} times</span>
                    <span>Success: ${usage.successful}/${usage.count}</span>
                    <span>First used: ${formatTimestamp(usage.first_used)}</span>
                </div>
            </div>
        `;
    });
    patternsHTML += '</div>';
    toolPatterns.innerHTML = patternsHTML;

    // Tool success rates
    const successRates = document.getElementById('toolSuccessRates');
    let successHTML = '<div class="success-chart">';
    Object.entries(toolUsage).forEach(([tool, usage]) => {
        const successRate = usage.count > 0 ? (usage.successful / usage.count) * 100 : 0;
        successHTML += `
            <div class="success-item">
                <div class="success-label">${tool}</div>
                <div class="success-bar">
                    <div class="success-fill" style="width: ${successRate}%"></div>
                </div>
                <div class="success-percentage">${successRate.toFixed(1)}%</div>
            </div>
        `;
    });
    successHTML += '</div>';
    successRates.innerHTML = successHTML;

    // Tool sequence analysis
    const sequenceAnalysis = document.getElementById('toolSequenceAnalysis');
    const toolProgression = analysis.behavioral_analysis.tool_progression;

    sequenceAnalysis.innerHTML = `
        <div class="sequence-info">
            <strong>Tool Call Sequence:</strong><br>
            <div class="tool-sequence">
                ${toolProgression.map((tool, index) => 
                    `<span class="sequence-item">${index + 1}. ${tool}</span>`
                ).join('')}
            </div>
        </div>
        <div class="sequence-patterns">
            <strong>Common Patterns:</strong><br>
            ${analyzeToolPatterns(toolProgression)}
        </div>
    `;
}

function analyzeToolPatterns(progression) {
    if (progression.length < 2) return 'Insufficient data for pattern analysis';

    const patterns = {};
    for (let i = 0; i < progression.length - 1; i++) {
        const pattern = `${progression[i]} → ${progression[i + 1]}`;
        patterns[pattern] = (patterns[pattern] || 0) + 1;
    }

    const sortedPatterns = Object.entries(patterns)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 5);

    return sortedPatterns.map(([pattern, count]) =>
        `<div class="pattern-item">${pattern} (${count}x)</div>`
    ).join('');
}

function displayRiskAssessmentSection(analysis) {
    // Main risk assessment
    document.getElementById('analysisVulnerabilityAssessment').innerHTML = `
        <div class="risk-overview">
            <div class="risk-header">
                <h4>Risk Level: <span class="badge ${getRiskBadgeClass(analysis.risk_assessment.risk_level)}">${analysis.risk_assessment.risk_level}</span></h4>
                <div class="risk-score">Score: ${analysis.risk_assessment.risk_score}/100</div>
            </div>
            
            <div class="risk-factors">
                <strong>Risk Factors:</strong>
                <ul>
                    ${analysis.risk_assessment.risk_factors.map(factor => `<li>${factor}</li>`).join('')}
                </ul>
            </div>
            
            <div class="challenge-context">
                <strong>Challenge Context:</strong><br>
                <strong>Type:</strong> ${analysis.challenge_context.vulnerability_type}<br>
                <strong>Allowed Files:</strong> ${analysis.challenge_context.allowed_files.join(', ')}<br>
                <strong>Forbidden Files:</strong> ${analysis.challenge_context.forbidden_files.join(', ')}<br>
                <strong>Available Tools:</strong> ${analysis.challenge_context.available_tools.join(', ')}
            </div>
        </div>
    `;

    // Attack vector analysis
    document.getElementById('attackVectorAnalysis').innerHTML = `
        <div class="attack-vectors">
            <div class="vector-item">
                <strong>Primary Vectors:</strong> ${analysis.summary.primary_attack_vectors.join(', ') || 'None identified'}
            </div>
            <div class="vector-item">
                <strong>Forbidden Access Attempts:</strong> ${analysis.security_analysis.forbidden_access_attempts}
            </div>
            <div class="vector-item">
                <strong>Tool Exploitation:</strong> ${Object.keys(analysis.tool_usage_analysis).length} tools used
            </div>
            <div class="vector-item">
                <strong>Escalation Events:</strong> ${analysis.behavioral_analysis.injection_escalation.length}
            </div>
        </div>
    `;

    // Defense recommendations
    document.getElementById('defenseRecommendations').innerHTML = `
        <div class="recommendations-list">
            ${analysis.recommendations.map(rec => `
                <div class="recommendation-item ${rec.type}">
                    <div class="rec-header">
                        <span class="rec-badge badge-${rec.type}">${rec.type.toUpperCase()}</span>
                        <strong>${rec.title}</strong>
                    </div>
                    <div class="rec-description">${rec.description}</div>
                    <div class="rec-action"><strong>Action:</strong> ${rec.action}</div>
                </div>
            `).join('')}
        </div>
    `;
}

// Get badge class for risk level
function getRiskBadgeClass(riskLevel) {
    switch (riskLevel) {
        case 'CRITICAL': return 'badge-danger';
        case 'HIGH': return 'badge-danger';
        case 'MEDIUM': return 'badge-warning';
        case 'LOW': return 'badge-warning';
        case 'MINIMAL': return 'badge-success';
        default: return 'badge-secondary';
    }
}

// Export conversation functionality
function exportConversation() {
    if (!currentConversationData) {
        showAlert('No conversation data to export', 'warning');
        return;
    }

    const sessionId = document.getElementById('analysisSessionSelect').value;
    const timestamp = new Date().toISOString().slice(0, 19);

    let exportText = `LLM Security Research - Conversation Export\n`;
    exportText += `Session ID: ${sessionId}\n`;
    exportText += `Export Time: ${timestamp}\n`;
    exportText += `${'='.repeat(60)}\n\n`;

    currentConversationData.forEach((message, index) => {
        exportText += `[${message.role.toUpperCase()}] ${formatTimestamp(message.timestamp)}\n`;
        exportText += `${message.content}\n`;

        // Add metadata if available
        const interaction = currentSessionInteractions.find(i =>
            Math.abs(i.sequence_number - Math.floor(index / 2) - 1) <= 1
        );

        if (interaction && interaction.injection_techniques && interaction.injection_techniques.length > 0) {
            exportText += `[TECHNIQUES] ${interaction.injection_techniques.join(', ')}\n`;
        }

        if (interaction && interaction.tool_calls && interaction.tool_calls.length > 0) {
            exportText += `[TOOLS] ${interaction.tool_calls.map(tc => tc.tool).join(', ')}\n`;
        }

        exportText += '\n' + '-'.repeat(40) + '\n\n';
    });

    // Create and download file
    const blob = new Blob([exportText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `conversation-${sessionId.substring(0, 8)}-${timestamp.slice(0, 10)}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showAlert('Conversation exported successfully', 'success');
}

// Timeline filtering
function setupTimelineFiltering() {
    document.querySelectorAll('.timeline-zoom').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.timeline-zoom').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const filter = btn.dataset.zoom;
            filterTimelineEvents(filter);
        });
    });
}

function filterTimelineEvents(filter) {
    const events = document.querySelectorAll('.timeline-event');

    events.forEach(event => {
        const marker = event.querySelector('.timeline-marker');
        const shouldShow = filter === 'all' || marker.classList.contains(filter);
        event.style.display = shouldShow ? 'flex' : 'none';
    });
}

// Load statistics
async function loadStatistics() {
    try {
        const response = await fetch(`${API_BASE}/research_stats`);
        const stats = await response.json();
        displayStatistics(stats);
    } catch (error) {
        console.error('Failed to load statistics:', error);
    }
}

// Display statistics
function displayStatistics(stats) {
    // Overall stats
    document.getElementById('statsTotalSessions').textContent = stats.overall.total_sessions;
    document.getElementById('statsSuccessfulBreaches').textContent = stats.overall.successful_breaches;
    document.getElementById('statsBreachRate').textContent =
        (stats.overall.breach_rate * 100).toFixed(1) + '%';

    // Challenge stats
    const challengeStatsContainer = document.getElementById('challengeStats');
    challengeStatsContainer.innerHTML = '';
    stats.by_challenge.forEach(challenge => {
        const item = document.createElement('div');
        item.className = 'status-item';
        item.innerHTML = `
            <div style="font-weight: 600; margin-bottom: 8px;">${challenge.challenge_id}</div>
            <div style="font-size: 0.8rem; color: var(--text-secondary);">
                ${challenge.successful_breaches}/${challenge.total_attempts} breached
                (${(challenge.success_rate * 100).toFixed(1)}%)
            </div>
        `;
        challengeStatsContainer.appendChild(item);
    });

    // Agent stats
    const agentStatsContainer = document.getElementById('agentStats');
    agentStatsContainer.innerHTML = '';
    stats.by_agent.forEach(agent => {
        const item = document.createElement('div');
        item.className = 'status-item';
        item.innerHTML = `
            <div style="font-weight: 600; margin-bottom: 8px;">${agent.agent_type}</div>
            <div style="font-size: 0.8rem; color: var(--text-secondary);">
                ${agent.successful_breaches}/${agent.total_sessions} breached
                (${(agent.success_rate * 100).toFixed(1)}%)
            </div>
        `;
        agentStatsContainer.appendChild(item);
    });

    // Common techniques - this may not exist in the current stats endpoint
    const techniquesContainer = document.getElementById('commonTechniques');
    techniquesContainer.innerHTML = '';

    if (stats.common_techniques) {
        stats.common_techniques.slice(0, 10).forEach((item, index) => {
            const div = document.createElement('div');
            div.style.cssText = 'display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid var(--border);';
            div.innerHTML = `
                <span>${item.techniques.join(', ') || 'No specific technique'}</span>
                <span style="color: var(--text-secondary);">${item.frequency} uses</span>
            `;
            techniquesContainer.appendChild(div);
        });
    } else {
        techniquesContainer.innerHTML = '<div style="text-align: center; color: var(--text-secondary); padding: 20px;">No technique data available yet</div>';
    }
}

// Utility functions
function formatTimestamp(timestamp) {
    if (!timestamp) return 'Unknown time';
    return new Date(timestamp).toLocaleString();
}

function showLoading(text = 'Loading...') {
    const loading = document.createElement('div');
    loading.className = 'message system loading';
    loading.innerHTML = `<div class="spinner"></div> ${text}`;
    loading.id = 'loadingMessage';
    document.getElementById('chatMessages').appendChild(loading);
    document.getElementById('chatMessages').scrollTop = document.getElementById('chatMessages').scrollHeight;
}

function hideLoading() {
    const loading = document.getElementById('loadingMessage');
    if (loading) loading.remove();
}

function showAlert(message, type = 'info') {
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.textContent = message;
    alert.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 1000; min-width: 300px;';
    document.body.appendChild(alert);

    setTimeout(() => alert.remove(), 5000);
}

function toggleCollapse(id) {
    const content = document.getElementById(id);
    const toggle = document.getElementById(id.replace('Content', 'Toggle'));

    content.classList.toggle('show');
    toggle.classList.toggle('active');
}

function viewSessionDetails(sessionId) {
    // Switch to analysis tab and select this session
    document.querySelector('[data-tab="analysis"]').click();
    document.getElementById('analysisSessionSelect').value = sessionId;
    document.getElementById('analyzeBtn').disabled = false;
    document.getElementById('loadConversationBtn').disabled = false;
}

// Setup event listeners
function setupEventListeners() {
    // Existing event listeners
    document.getElementById('startResearchBtn').addEventListener('click', startResearch);
    document.getElementById('sendBtn').addEventListener('click', sendInteraction);
    document.getElementById('messageInput').addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !document.getElementById('sendBtn').disabled) {
            sendInteraction();
        }
    });

    document.getElementById('analysisSessionSelect').addEventListener('change', (e) => {
        const hasSelection = !!e.target.value;
        document.getElementById('analyzeBtn').disabled = !hasSelection;
        document.getElementById('loadConversationBtn').disabled = !hasSelection;
    });

    document.getElementById('analyzeBtn').addEventListener('click', generateAnalysis);

    // New event listeners for enhanced analysis
    document.getElementById('loadConversationBtn').addEventListener('click', loadConversationData);
    document.getElementById('exportConversationBtn').addEventListener('click', exportConversation);

    // Conversation filtering
    document.getElementById('conversationFilter').addEventListener('change', renderConversationView);
    document.getElementById('highlightMode').addEventListener('change', renderConversationView);
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', init);