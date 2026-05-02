/**
 * Network Traffic Analyzer - Frontend Application
 * Different approach: Object-oriented structure with polling
 */

const API_URL = 'http://localhost:8080';
const REFRESH_INTERVAL = 1000; // 1 second polling

class TrafficAnalyzer {
    constructor() {
        this.isCapturing = false;
        this.pollingTimer = null;
        this.packetCache = [];
        this.filterState = {
            protocol: '',
            source: '',
            destination: ''
        };
        
        this.dom = {
            ifaceSelect: document.getElementById('ifaceSelect'),
            btnBegin: document.getElementById('btnBegin'),
            btnHalt: document.getElementById('btnHalt'),
            btnFilter: document.getElementById('btnFilter'),
            btnReset: document.getElementById('btnReset'),
            btnThemeToggle: document.getElementById('btnThemeToggle'),
            filterProto: document.getElementById('filterProto'),
            filterSrc: document.getElementById('filterSrc'),
            filterDst: document.getElementById('filterDst'),
            statusDot: document.getElementById('statusDot'),
            statusText: document.getElementById('statusText'),
            statTotal: document.getElementById('statTotal'),
            statBytes: document.getElementById('statBytes'),
            statAvg: document.getElementById('statAvg'),
            statTopProto: document.getElementById('statTopProto'),
            captureInterface: document.getElementById('captureInterface'),
            trafficBody: document.getElementById('trafficBody'),
            recordCount: document.getElementById('recordCount'),
            activityLog: document.getElementById('activityLog'),
        };
        
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadInterfaces();
        this.updateInitialTime();
        this.loadThemePreference();
    }

    bindEvents() {
        this.dom.btnBegin.addEventListener('click', () => { this.playSound('click'); this.startCapture(); });
        this.dom.btnHalt.addEventListener('click', () => { this.playSound('click'); this.stopCapture(); });
        this.dom.btnFilter.addEventListener('click', () => { this.playSound('click'); this.applyFilters(); });
        this.dom.btnReset.addEventListener('click', () => { this.playSound('click'); this.resetFilters(); });
        this.dom.btnThemeToggle.addEventListener('click', () => { this.playSound('click'); this.toggleTheme(); });
    }

    loadThemePreference() {
        const savedTheme = localStorage.getItem('netwatch-theme');
        if (savedTheme === 'light') {
            document.body.classList.add('light-mode');
        }
    }

    toggleTheme() {
        const isLightMode = document.body.classList.toggle('light-mode');
        localStorage.setItem('netwatch-theme', isLightMode ? 'light' : 'dark');
        this.logMessage('info', `Switched to ${isLightMode ? 'light' : 'dark'} mode`);
    }

    initAudio() {
        if (!this.audioCtx) {
            this.audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        }
    }

    playSound(type) {
        if (!this.audioCtx) {
            this.initAudio();
        }
        if (this.audioCtx.state === 'suspended') {
            this.audioCtx.resume();
        }

        const osc = this.audioCtx.createOscillator();
        const gainNode = this.audioCtx.createGain();

        osc.connect(gainNode);
        gainNode.connect(this.audioCtx.destination);

        const now = this.audioCtx.currentTime;

        switch (type) {
            case 'start':
                osc.type = 'sine';
                osc.frequency.setValueAtTime(440, now);
                osc.frequency.exponentialRampToValueAtTime(880, now + 0.1);
                gainNode.gain.setValueAtTime(0.3, now);
                gainNode.gain.exponentialRampToValueAtTime(0.01, now + 0.3);
                osc.start(now);
                osc.stop(now + 0.3);
                break;
            case 'stop':
                osc.type = 'sine';
                osc.frequency.setValueAtTime(880, now);
                osc.frequency.exponentialRampToValueAtTime(440, now + 0.2);
                gainNode.gain.setValueAtTime(0.3, now);
                gainNode.gain.exponentialRampToValueAtTime(0.01, now + 0.4);
                osc.start(now);
                osc.stop(now + 0.4);
                break;
            case 'alert':
                osc.type = 'square';
                osc.frequency.setValueAtTime(200, now);
                osc.frequency.setValueAtTime(400, now + 0.1);
                osc.frequency.setValueAtTime(200, now + 0.2);
                gainNode.gain.setValueAtTime(0.2, now);
                gainNode.gain.exponentialRampToValueAtTime(0.01, now + 0.3);
                osc.start(now);
                osc.stop(now + 0.3);
                break;
            case 'click':
                osc.type = 'triangle';
                osc.frequency.setValueAtTime(600, now);
                gainNode.gain.setValueAtTime(0.1, now);
                gainNode.gain.exponentialRampToValueAtTime(0.01, now + 0.1);
                osc.start(now);
                osc.stop(now + 0.1);
                break;
            case 'success':
                osc.type = 'sine';
                osc.frequency.setValueAtTime(523.25, now);
                osc.frequency.setValueAtTime(659.25, now + 0.1);
                osc.frequency.setValueAtTime(783.99, now + 0.2);
                gainNode.gain.setValueAtTime(0.2, now);
                gainNode.gain.exponentialRampToValueAtTime(0.01, now + 0.5);
                osc.start(now);
                osc.stop(now + 0.5);
                break;
            default:
                osc.type = 'sine';
                osc.frequency.setValueAtTime(440, now);
                gainNode.gain.setValueAtTime(0.1, now);
                gainNode.gain.exponentialRampToValueAtTime(0.01, now + 0.2);
                osc.start(now);
                osc.stop(now + 0.2);
        }
    }

    updateInitialTime() {
        const timeEl = document.getElementById('initialTime');
        if (timeEl) {
            timeEl.textContent = this.formatTime(new Date());
        }
    }

    async loadInterfaces() {
        try {
            const response = await fetch(`${API_URL}/api/interfaces`);
            const interfaces = await response.json();
            
            this.dom.ifaceSelect.innerHTML = '<option value="">Select Interface...</option>';
            
            interfaces.forEach(iface => {
                const option = document.createElement('option');
                option.value = iface.name;
                option.textContent = iface.description || iface.name;
                this.dom.ifaceSelect.appendChild(option);
            });
            
            this.playSound('success');
            this.logMessage('info', `Found ${interfaces.length} network interfaces`);
        } catch (error) {
            this.playSound('alert');
            this.logMessage('error', 'Failed to load interfaces. Is backend running?');
        }
    }

    async startCapture() {
        const device = this.dom.ifaceSelect.value;
        if (!device) {
            this.logMessage('error', 'Please select a network interface');
            return;
        }

        try {
            const response = await fetch(`${API_URL}/api/begin?device=${encodeURIComponent(device)}`);
            const result = await response.json();
            
            if (result.success) {
                this.isCapturing = true;
                this.updateUIState(true, device);
                this.beginPolling();
                this.playSound('start');
                this.logMessage('success', `Capture started on ${device.substring(0, 30)}`);
            } else {
                this.playSound('alert');
                this.logMessage('error', result.error || 'Failed to start');
            }
        } catch (error) {
            this.logMessage('error', 'Failed to start capture');
        }
    }

    async stopCapture() {
        try {
            await fetch(`${API_URL}/api/halt`);
            this.isCapturing = false;
            this.stopPolling();
            this.updateUIState(false);
            this.playSound('stop');
            this.logMessage('warn', `Capture stopped. ${this.packetCache.length} packets captured`);
        } catch (error) {
            this.logMessage('error', 'Error stopping capture');
        }
    }

    beginPolling() {
        this.fetchData(); // Immediate first fetch
        this.pollingTimer = setInterval(() => this.fetchData(), REFRESH_INTERVAL);
    }

    stopPolling() {
        if (this.pollingTimer) {
            clearInterval(this.pollingTimer);
            this.pollingTimer = null;
        }
    }

    async fetchData() {
        await Promise.all([
            this.fetchFlows(),
            this.fetchMetrics()
        ]);
    }

    async fetchFlows() {
        try {
            const params = new URLSearchParams();
            if (this.filterState.protocol) params.append('protocol', this.filterState.protocol);
            if (this.filterState.source) params.append('src', this.filterState.source);
            if (this.filterState.destination) params.append('dst', this.filterState.destination);
            
            const queryString = params.toString();
            const url = `${API_URL}/api/flows${queryString ? '?' + queryString : ''}`;
            
            const response = await fetch(url);
            const flows = await response.json();
            
            this.packetCache = flows;
            this.renderTable(flows);
        } catch (error) {
            console.error('Fetch flows error:', error);
        }
    }

    async fetchMetrics() {
        try {
            const response = await fetch(`${API_URL}/api/metrics`);
            const metrics = await response.json();
            
            this.updateStats(metrics);
        } catch (error) {
            console.error('Fetch metrics error:', error);
        }
    }

    updateStats(metrics) {
        this.dom.statTotal.textContent = this.formatNumber(metrics.total_packets);
    }

    renderTable(flows) {
        const tbody = this.dom.trafficBody;
        
        if (flows.length === 0) {
            tbody.innerHTML = `
                <tr class="empty-row">
                    <td colspan="9">
                        <div class="empty-message">
                            <span class="empty-icon">◈</span>
                            <p>${this.isCapturing ? 'Waiting for traffic...' : 'Click "Start" to begin capturing'}</p>
                        </div>
                    </td>
                </tr>
            `;
            this.dom.recordCount.textContent = '0 records';
            return;
        }

        // Show last 300 flows, newest first
        const display = flows.slice(-300).reverse();
        const html = display.map((flow, idx) => {
            const rowNum = flows.length - idx;
            const protoClass = flow.proto.toLowerCase();
            return `
                <tr>
                    <td style="color: var(--text-muted)">${rowNum}</td>
                    <td>${flow.time}</td>
                    <td>${flow.src}</td>
                    <td style="color: var(--text-muted)">${flow.sport || '-'}</td>
                    <td>${flow.dst}</td>
                    <td style="color: var(--text-muted)">${flow.dport || '-'}</td>
                    <td><span class="proto-badge ${protoClass}">${flow.proto}</span></td>
                    <td>${this.formatNumber(flow.size)}</td>
                    <td>${flow.service}</td>
                </tr>
            `;
        }).join('');

        tbody.innerHTML = html;
        this.dom.recordCount.textContent = `${flows.length} records`;
    }

    applyFilters() {
        this.filterState.protocol = this.dom.filterProto.value;
        this.filterState.source = this.dom.filterSrc.value.trim();
        this.filterState.destination = this.dom.filterDst.value.trim();
        
        const parts = [];
        if (this.filterState.protocol) parts.push(`Proto: ${this.filterState.protocol}`);
        if (this.filterState.source) parts.push(`Src: ${this.filterState.source}`);
        if (this.filterState.destination) parts.push(`Dst: ${this.filterState.destination}`);
        
        this.logMessage('info', `Filter applied: ${parts.join(', ') || 'none'}`);
        this.fetchFlows();
    }

    resetFilters() {
        this.dom.filterProto.value = '';
        this.dom.filterSrc.value = '';
        this.dom.filterDst.value = '';
        this.filterState = { protocol: '', source: '', destination: '' };
        this.logMessage('info', 'Filters cleared');
        this.fetchFlows();
    }

    updateUIState(active, deviceName = '') {
        this.dom.btnBegin.disabled = active;
        this.dom.btnHalt.disabled = !active;
        this.dom.ifaceSelect.disabled = active;
        
        if (active) {
            this.dom.statusDot.classList.add('active');
            this.dom.statusText.textContent = 'LIVE Capturing';
            if (this.dom.captureInterface && deviceName) {
                this.dom.captureInterface.textContent = deviceName.substring(0, 25);
            }
        } else {
            this.dom.statusDot.classList.remove('active');
            this.dom.statusText.textContent = 'Ready';
            if (this.dom.captureInterface) {
                this.dom.captureInterface.textContent = 'No interface selected';
            }
        }
    }

    logMessage(level, message) {
        const entry = document.createElement('div');
        entry.className = `log-entry ${level}`;
        entry.innerHTML = `
            <span class="log-time">${this.formatTime(new Date())}</span>
            <span class="log-msg">${message}</span>
        `;
        
        this.dom.activityLog.appendChild(entry);
        this.dom.activityLog.scrollTop = this.dom.activityLog.scrollHeight;
        
        // Keep only last 50 entries
        while (this.dom.activityLog.children.length > 50) {
            this.dom.activityLog.removeChild(this.dom.activityLog.firstChild);
        }
    }

    formatNumber(num) {
        return num.toLocaleString();
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    formatTime(date) {
        return date.toTimeString().slice(0, 8);
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.analyzer = new TrafficAnalyzer();
});
