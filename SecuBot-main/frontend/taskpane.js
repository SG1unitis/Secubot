const SERVER_URL = "https://localhost:5000"; 
Office.onReady((info) => {
    if (info.host === Office.HostType.Outlook) {
        console.log("SecuBot est prêt dans Outlook");
    }
    document.getElementById("analyzeBtn").onclick = startAnalysis;
    const analyzeMailBtn = document.getElementById("analyzeMailBtn");
    if (analyzeMailBtn) analyzeMailBtn.onclick = startMailAnalysis;
});

function startAnalysis() {
    const urlInput = document.getElementById("urlInput").value.trim();
    if (urlInput === "") { alert("Veuillez entrer une URL."); return; }
    toggleLoading(true);
    
    fetch(`${SERVER_URL}/api/analyze`, {
        method: "POST",
        headers: { 
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ url: urlInput })
    })
    .then(response => {
        if (!response.ok) throw new Error("Erreur serveur");
        return response.json();
    })
    .then(data => displayVerdict(data.titre, data.texte))
    .catch(() => displayVerdict("⚠️ ERREUR", "Impossible de joindre le serveur SecuBot."));
}

function startMailAnalysis() {
    toggleLoading(true);
    Office.context.mailbox.item.body.getAsync(Office.CoercionType.Text, (result) => {
        if (result.status === Office.AsyncResultStatus.Succeeded) {
            
            fetch(`${SERVER_URL}/api/analyze-mail`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ body: result.value })
            })
            .then(response => {
                if (!response.ok) throw new Error("Erreur serveur");
                return response.json();
            })
            .then(data => displayMultiResults(data))
            .catch(() => displayVerdict("⚠️ ERREUR", "Impossible de joindre le serveur pour l'analyse du mail."));
        } else {
            displayVerdict("⚠️ ERREUR", "Échec de la lecture du contenu de l'email.");
        }
    });
}

function toggleLoading(isLoading) {
    const loadingSection = document.getElementById("loadingSection");
    const resultSection  = document.getElementById("resultSection");
    const analyzeBtn     = document.getElementById("analyzeBtn");
    const analyzeMailBtn = document.getElementById("analyzeMailBtn");

    if (isLoading) {
        loadingSection.classList.remove("hidden");
        resultSection.classList.add("hidden");
        analyzeBtn.classList.add("hidden");
        if (analyzeMailBtn) analyzeMailBtn.classList.add("hidden");
    } else {
        loadingSection.classList.add("hidden");
        analyzeBtn.classList.remove("hidden");
        if (analyzeMailBtn) analyzeMailBtn.classList.remove("hidden");
    }
}

function displayVerdict(title, text) {
    toggleLoading(false);
    document.getElementById("resultTitle").innerText = title;
    document.getElementById("resultText").innerText  = text;
    document.getElementById("resultSection").classList.remove("hidden");
}

function displayMultiResults(data) {
    toggleLoading(false);

    document.getElementById("resultTitle").innerText = `Résultats (${data.count} lien(s))`;

    const resultText = document.getElementById("resultText");
    resultText.textContent = "";

    if (data.count === 0) {
        resultText.innerText = "Aucun lien détecté dans cet email.";
        document.getElementById("resultSection").classList.remove("hidden");
        return;
    }

    const list = document.createElement("ul");
    list.style.paddingLeft = "20px";
    list.style.wordWrap = "break-word";

    data.results.forEach((res) => {
        const item = document.createElement("li");
        item.style.marginBottom = "10px";

        const verdict = document.createElement("strong");
        verdict.textContent = res.verdict;

        if (res.verdict.includes("ALERTE")) {
            verdict.style.color = "#d13438";
        } else if (res.verdict.includes("SUSPECT")) {
            verdict.style.color = "#ffaa44";
        } else {
            verdict.style.color = "#107c41";
        }

        const code = document.createElement("code");
        code.textContent = res.original_defanged;
        code.style.fontSize = "11px";
        code.style.background = "#eee";
        code.style.padding = "2px 4px";
        code.style.borderRadius = "3px";

        item.appendChild(verdict);
        item.appendChild(document.createElement("br"));
        item.appendChild(code);

        list.appendChild(item);
    });

    resultText.appendChild(list);
    document.getElementById("resultSection").classList.remove("hidden");
}
