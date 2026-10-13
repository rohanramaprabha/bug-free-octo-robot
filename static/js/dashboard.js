/**
 * PrivacyVault AI - Dashboard Charts & Visualization Engine
 * Renders Category Doughnut, Severity Bar, and Top Data Types Chart.
 */

let categoryChartInstance = null;
let severityChartInstance = null;
let dataTypesChartInstance = null;

function initDashboardCharts(stats) {
    if (!stats) return;
    
    // 1. Findings by Category (Doughnut Chart)
    const catLabels = Object.keys(stats.findings_by_category || {});
    const catValues = Object.values(stats.findings_by_category || {});
    
    const catColors = [
        '#00d2ff', // PII
        '#ff9100', // Financial
        '#ff1744', // Secrets
        '#6366f1', // Confidential Business
        '#00e676'  // Public
    ];
    
    const ctxCategory = document.getElementById('categoryChart')?.getContext('2d');
    if (ctxCategory) {
        if (categoryChartInstance) categoryChartInstance.destroy();
        categoryChartInstance = new Chart(ctxCategory, {
            type: 'doughnut',
            data: {
                labels: catLabels.length ? catLabels : ['No Data'],
                datasets: [{
                    data: catValues.length ? catValues : [1],
                    backgroundColor: catLabels.length ? catColors.slice(0, catLabels.length) : ['#334155'],
                    borderWidth: 2,
                    borderColor: '#111827'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#94a3b8', font: { size: 11, family: 'Plus Jakarta Sans' }, boxWidth: 12 }
                    }
                },
                cutout: '68%'
            }
        });
    }

    // 2. Severity Distribution (Bar Chart)
    const sevMap = stats.findings_by_severity || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    const ctxSeverity = document.getElementById('severityChart')?.getContext('2d');
    if (ctxSeverity) {
        if (severityChartInstance) severityChartInstance.destroy();
        severityChartInstance = new Chart(ctxSeverity, {
            type: 'bar',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    label: 'Findings Count',
                    data: [sevMap.CRITICAL || 0, sevMap.HIGH || 0, sevMap.MEDIUM || 0, sevMap.LOW || 0],
                    backgroundColor: ['#ff1744', '#ff9100', '#00d2ff', '#00e676'],
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        ticks: { color: '#94a3b8', font: { size: 11 } },
                        grid: { display: false }
                    },
                    y: {
                        ticks: { color: '#94a3b8', precision: 0 },
                        grid: { color: 'rgba(255, 255, 255, 0.05)' }
                    }
                }
            }
        });
    }

    // 3. Top Sensitive Data Types (Horizontal Bar Chart)
    const topTypes = stats.top_data_types || [];
    const typeLabels = topTypes.map(t => t.type);
    const typeCounts = topTypes.map(t => t.count);

    const ctxTypes = document.getElementById('dataTypesChart')?.getContext('2d');
    if (ctxTypes) {
        if (dataTypesChartInstance) dataTypesChartInstance.destroy();
        dataTypesChartInstance = new Chart(ctxTypes, {
            type: 'bar',
            indexAxis: 'y',
            data: {
                labels: typeLabels.length ? typeLabels : ['None Found'],
                datasets: [{
                    label: 'Occurrences',
                    data: typeCounts.length ? typeCounts : [0],
                    backgroundColor: '#00d2ff',
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: {
                        ticks: { color: '#94a3b8', precision: 0 },
                        grid: { color: 'rgba(255, 255, 255, 0.05)' }
                    },
                    y: {
                        ticks: { color: '#94a3b8', font: { size: 11 } },
                        grid: { display: false }
                    }
                }
            }
        });
    }
}

async function refreshDashboardData() {
    showToast("Refreshing live database telemetry...");
    try {
        const res = await fetch("/api/stats");
        const stats = await res.json();
        
        // Update metric counters in DOM
        const elTotal = document.getElementById("metric-total-scans");
        if (elTotal) elTotal.textContent = stats.total_scans;
        
        const elFind = document.getElementById("metric-total-findings");
        if (elFind) elFind.textContent = stats.total_findings;
        
        const elCrit = document.getElementById("metric-critical-findings");
        if (elCrit) elCrit.textContent = stats.critical_findings + stats.high_findings;
        
        const elRisk = document.getElementById("metric-avg-risk");
        if (elRisk) elRisk.innerHTML = `${stats.avg_risk_score} <span class="fs-6 text-muted">/100</span>`;
        
        initDashboardCharts(stats);
        showToast("Telemetry metrics updated.");
    } catch (e) {
        showToast("Error refreshing stats: " + e, true);
    }
}
