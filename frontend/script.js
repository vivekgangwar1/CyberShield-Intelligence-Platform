
// ============================================
// CYBERSHIELD - JAVASCRIPT
// ============================================

const API_BASE_URL = "https://cybershield-api-ndmv.onrender.com";


// ============================================
// HELPER FUNCTIONS
// ============================================

function getElement(id) {
    return document.getElementById(id);
}

function showError(message) {
    alert(message);
}

function refreshIcons() {
    if (window.lucide) {
        lucide.createIcons();
    }
}

function setLoading(button, loading, text) {
    if (!button) return;

    button.disabled = loading;

    const span = button.querySelector("span");

    if (span) {
        if (loading) {
            button.dataset.oldText = span.textContent;
            span.textContent = text;
        } else {
            span.textContent = button.dataset.oldText || text;
        }
    }
}

function formatPercentage(value) {
    const number = Number(value);

    if (!Number.isFinite(number)) return "0%";

    return `${(number * 100).toFixed(2)}%`;
}

function getApiError(data) {
    if (typeof data.detail === "string") {
        return data.detail;
    }

    if (data.detail) {
        return JSON.stringify(data.detail);
    }

    return data.message || "Something went wrong.";
}


// ============================================
// 1. PHISHING URL SCANNER
// ============================================

const urlForm = getElement("url-form");

if (urlForm) {

    urlForm.addEventListener("submit", async function (event) {

        event.preventDefault();

        const urlInput = getElement("url-input");
        const scanButton = getElement("scan-button");
        const resultBox = getElement("result-box");

        const resultTitle = getElement("result-title");
        const resultUrl = getElement("result-url");
        const confidence = getElement("confidence");
        const confidenceBar = getElement("confidence-bar");
        const description = getElement("result-description");
        const symbol = getElement("result-symbol");

        const url = urlInput.value.trim();

        if (!url) {
            showError("Please enter a website URL.");
            return;
        }

        setLoading(scanButton, true, "Analyzing...");

        resultBox.classList.add("hidden");

        try {

            const response = await fetch(
                `${API_BASE_URL}/api/phishing-detection`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    body: JSON.stringify({
                        url: url
                    })
                }
            );

            const data = await response.json();

            if (!response.ok) {
                throw new Error(getApiError(data));
            }

            const prediction = String(data.prediction).toLowerCase();

            const isPhishing =
                prediction.includes("phishing") ||
                prediction.includes("malicious");

            const score = Number(data.confidence) || 0;

            resultTitle.textContent = data.prediction;
            resultUrl.textContent = data.url || url;

            confidence.textContent = formatPercentage(score);

            confidenceBar.style.width =
                `${Math.min(Math.max(score * 100, 0), 100)}%`;

            description.textContent =
                data.message || "URL analysis completed.";

            resultBox.classList.toggle("danger", isPhishing);

            symbol.innerHTML = isPhishing
                ? '<i data-lucide="shield-alert"></i>'
                : '<i data-lucide="shield-check"></i>';

            resultBox.classList.remove("hidden");

            refreshIcons();

        } catch (error) {

            showError(
                "Phishing Scanner Error: " + error.message
            );

        } finally {

            setLoading(scanButton, false, "Analyze URL");

        }

    });

}



// ============================================
// 2. NETWORK INTRUSION SCANNER
// ============================================

const intrusionForm = getElement("intrusion-form");

if (intrusionForm) {

    intrusionForm.addEventListener("submit", async function (event) {

        event.preventDefault();

        const jsonInput = getElement("intrusion-json");
        const scanButton = getElement("intrusion-button");

        const resultBox = getElement("intrusion-result");

        const resultTitle = getElement("intrusion-title");
        const resultSymbol = getElement("intrusion-symbol");
        const confidence = getElement("intrusion-confidence");
        const threshold = getElement("intrusion-threshold");
        const confidenceBar = getElement("intrusion-bar");
        const description = getElement("intrusion-description");

        let features;

        try {

            features = JSON.parse(jsonInput.value);

            // Both formats are supported:
            // { "features": { ... } }
            // { ... }

            if (
                features &&
                typeof features === "object" &&
                features.features &&
                typeof features.features === "object"
            ) {
                features = features.features;
            }

            if (
                !features ||
                typeof features !== "object" ||
                Array.isArray(features)
            ) {
                throw new Error("JSON must contain a features object.");
            }

        } catch (error) {

            showError("Invalid JSON: " + error.message);
            return;

        }

        setLoading(scanButton, true, "Analyzing...");

        resultBox.classList.add("hidden");

        try {

            const response = await fetch(
                `${API_BASE_URL}/api/intrusion-detection`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    body: JSON.stringify({
                        features: features
                    })
                }
            );

            const data = await response.json();

            if (!response.ok) {
                throw new Error(getApiError(data));
            }

            const prediction = String(data.prediction).toLowerCase();

            const isAttack =
                prediction.includes("attack") ||
                prediction.includes("intrusion");

            const score = Number(data.attack_probability) || 0;

            resultTitle.textContent = data.prediction;

            confidence.textContent = formatPercentage(score);

            confidenceBar.style.width =
                `${Math.min(Math.max(score * 100, 0), 100)}%`;

            threshold.textContent =
                `Detection threshold: ${data.threshold ?? "N/A"}`;

            description.textContent =
                data.message || "Network analysis completed.";

            resultBox.classList.toggle("danger", isAttack);

            resultSymbol.innerHTML = isAttack
                ? '<i data-lucide="shield-alert"></i>'
                : '<i data-lucide="shield-check"></i>';

            resultBox.classList.remove("hidden");

            refreshIcons();

        } catch (error) {

            showError(
                "Intrusion Scanner Error: " + error.message
            );

        } finally {

            setLoading(
                scanButton,
                false,
                "Analyze Network Traffic"
            );

        }

    });

}



// ============================================
// 3. MALWARE EXE SCANNER
// ============================================

const malwareForm = getElement("malware-form");

if (malwareForm) {

    malwareForm.addEventListener("submit", async function (event) {

        event.preventDefault();

        const fileInput = getElement("malware-file");
        const scanButton = getElement("malware-button");

        const resultBox = getElement("malware-result");

        const resultTitle = getElement("malware-title");
        const resultSymbol = getElement("malware-symbol");
        const confidence = getElement("malware-confidence");

        const filename = getElement("malware-filename");
        const probability = getElement("malware-probability");

        const confidenceBar = getElement("malware-bar");
        const description = getElement("malware-description");

        const file = fileInput.files[0];

        // File selection validation

        if (!file) {
            showError("Please select an EXE file.");
            return;
        }

        // EXE extension validation

        if (!file.name.toLowerCase().endsWith(".exe")) {
            showError("Only EXE files are allowed.");
            fileInput.value = "";
            return;
        }

        // Maximum 100 MB

        const MAX_FILE_SIZE = 100 * 1024 * 1024;

        if (file.size > MAX_FILE_SIZE) {

            showError("File size must be less than or equal to 100 MB.");

            fileInput.value = "";
            return;

        }

        setLoading(scanButton, true, "Scanning File...");

        resultBox.classList.add("hidden");

        try {

            const formData = new FormData();

            formData.append("file", file);

            const response = await fetch(
                `${API_BASE_URL}/api/malware-scan-exe`,
                {
                    method: "POST",
                    body: formData
                }
            );

            const data = await response.json();

            if (!response.ok) {
                throw new Error(getApiError(data));
            }

            const prediction = String(data.prediction).toLowerCase();

            const isMalware =
                prediction.includes("malware");

            const score = Number(data.confidence) || 0;

            const malwareScore =
                Number(data.malware_probability) || 0;

            // Update result

            resultTitle.textContent = data.prediction;

            confidence.textContent = formatPercentage(score);

            filename.textContent =
                `File: ${data.filename || file.name}`;

            probability.textContent =
                `Malware Probability: ${formatPercentage(malwareScore)}`;

            confidenceBar.style.width =
                `${Math.min(Math.max(score * 100, 0), 100)}%`;

            description.textContent =
                data.message || "Malware analysis completed.";

            resultBox.classList.toggle("danger", isMalware);

            resultSymbol.innerHTML = isMalware
                ? '<i data-lucide="shield-alert"></i>'
                : '<i data-lucide="shield-check"></i>';

            resultBox.classList.remove("hidden");

            refreshIcons();

        } catch (error) {

            showError(
                "Malware Scanner Error: " + error.message
            );

        } finally {

            setLoading(
                scanButton,
                false,
                "Scan EXE File"
            );

        }

    });

}



// ============================================
// INITIALIZE LUCIDE ICONS
// ============================================

document.addEventListener("DOMContentLoaded", function () {

    refreshIcons();

});


// =========================================
// CYBERSHIELD SCAN HISTORY
// =========================================


// ============================================
// CYBERSHIELD SCAN HISTORY - SEARCH & FILTER
// ============================================

// HTML Elements

const historyTableBody = getElement("history-table-body");
const totalScansElement = getElement("total-scans");
const historyMessage = getElement("history-message");
const refreshHistoryButton = getElement("refresh-history");

const historySearch = getElement("history-search");
const historyTypeFilter = getElement("history-type-filter");
const historyPredictionFilter = getElement("history-prediction-filter");
const clearHistoryFilters = getElement("clear-history-filters");

// Store all records

let allHistoryRecords = [];


// ============================================
// LOAD SCAN HISTORY
// ============================================

async function loadScanHistory() {

    if (!historyTableBody) return;

    historyTableBody.innerHTML = `
        <tr>
            <td colspan="6">Loading scan history...</td>
        </tr>
    `;

    historyMessage.textContent = "";

    try {

        const response = await fetch(
            `${API_BASE_URL}/api/scan-history?limit=100`
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(getApiError(data));
        }

        // Store all records

        allHistoryRecords = data.scans || [];

        // Update total count

        totalScansElement.textContent = data.total_scans ?? 0;

        // Apply search and filters

        filterHistory();

        historyMessage.textContent =
            "Scan history loaded successfully.";

        historyMessage.className =
            "history-message success";

    } catch (error) {

        console.error("Scan History Error:", error);

        historyTableBody.innerHTML = `
            <tr>
                <td colspan="6">Unable to load scan history.</td>
            </tr>
        `;

        historyMessage.textContent =
            "Please check whether the backend server is running.";

        historyMessage.className =
            "history-message error";

    }

}


// ============================================
// SEARCH AND FILTER
// ============================================

function filterHistory() {

    const searchValue = historySearch.value
        .trim()
        .toLowerCase();

    const selectedType = historyTypeFilter.value.toLowerCase();

    const selectedPrediction =
        historyPredictionFilter.value.toLowerCase();

    const filteredRecords = allHistoryRecords.filter(scan => {

        const target = String(scan.target || "").toLowerCase();

        const scanType = String(scan.scan_type || "").toLowerCase();

        const prediction = String(scan.prediction || "").toLowerCase();

        // Search condition

        const matchesSearch =
            target.includes(searchValue) ||
            scanType.includes(searchValue) ||
            prediction.includes(searchValue);

        // Scan type condition

        const matchesType =
            selectedType === "all" ||
            scanType === selectedType;

        // Prediction condition

        const matchesPrediction =
            selectedPrediction === "all" ||
            prediction === selectedPrediction;

        return (
            matchesSearch &&
            matchesType &&
            matchesPrediction
        );

    });

    displayHistory(filteredRecords);

}


// ============================================
// DISPLAY FILTERED HISTORY
// ============================================

function displayHistory(records) {

    historyTableBody.innerHTML = "";

    if (records.length === 0) {

        historyTableBody.innerHTML = `
            <tr>
                <td colspan="6">No matching scan records found.</td>
            </tr>
        `;

        return;

    }

    records.forEach(scan => {

        const row = document.createElement("tr");

        const prediction = String(scan.prediction || "Unknown");

        const lowerPrediction = prediction.toLowerCase();

        let badgeClass = "normal";

        if (
            ["phishing", "attack", "malware"].includes(lowerPrediction)
        ) {
            badgeClass = "danger";
        }

        else if (
            ["legitimate", "benign", "normal"].includes(lowerPrediction)
        ) {
            badgeClass = "safe";
        }

        const confidence = (
            Number(scan.confidence || 0) * 100
        ).toFixed(2);

        const values = [
            scan.id,
            scan.scan_type,
            scan.target,
            prediction,
            `${confidence}%`,
            scan.scanned_at
        ];

        values.forEach((value, index) => {

            const cell = document.createElement("td");

            if (index === 3) {

                const badge = document.createElement("span");

                badge.className = `history-badge ${badgeClass}`;

                badge.textContent = value;

                cell.appendChild(badge);

            } else {

                cell.textContent = value ?? "-";

            }

            row.appendChild(cell);

        });

        historyTableBody.appendChild(row);

    });

}


// ============================================
// SEARCH EVENT
// ============================================

if (historySearch) {

    historySearch.addEventListener("input", filterHistory);

}


// ============================================
// SCAN TYPE FILTER EVENT
// ============================================

if (historyTypeFilter) {

    historyTypeFilter.addEventListener(
        "change",
        filterHistory
    );

}


// ============================================
// PREDICTION FILTER EVENT
// ============================================

if (historyPredictionFilter) {

    historyPredictionFilter.addEventListener(
        "change",
        filterHistory
    );

}


// ============================================
// CLEAR FILTERS
// ============================================

if (clearHistoryFilters) {

    clearHistoryFilters.addEventListener("click", function () {

        historySearch.value = "";

        historyTypeFilter.value = "all";

        historyPredictionFilter.value = "all";

        filterHistory();

    });

}


// ============================================
// REFRESH HISTORY
// ============================================

if (refreshHistoryButton) {

    refreshHistoryButton.addEventListener(
        "click",
        loadScanHistory
    );

}


// ============================================
// INITIALIZE SCAN HISTORY
// ============================================

document.addEventListener("DOMContentLoaded", function () {

    loadScanHistory();

});
