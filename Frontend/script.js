document.getElementById("url-form").addEventListener("submit", async (e) => {
  e.preventDefault();

  const url = document.getElementById("url-input").value;
  const loading = document.getElementById("loading");
  const resultsContent = document.getElementById("results-content");

  loading.classList.remove("hidden");
  resultsContent.classList.add("hidden");

  try {
    const response = await fetch("http://localhost:3000/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      throw new Error("Failed to fetch analysis");
    }

    const data = await response.json();
    displayResults(data);
  } catch (error) {
    console.error("Error:", error);
    resultsContent.innerHTML = "<p>Error analyzing URL. Please try again.</p>";
    resultsContent.classList.remove("hidden");
  } finally {
    loading.classList.add("hidden");
  }
});

function displayResults(data) {
  const resultsContent = document.getElementById("results-content");
  const riskColor =
    data.riskScore > 75 ? "red" : data.riskScore > 50 ? "orange" : "green";

  document.getElementById(
    "risk-score"
  ).innerHTML = `<span style="color: ${riskColor}">${data.riskScore}/100</span>`;
  document.getElementById("risk-description").value =
    data.riskDescription || "Moderate risk due to broad permissions.";
  document.getElementById("permissions-list").innerHTML = data.permissions
    .map(
      (p) => `
        <li>
            ${p}
            <input type="text" class="permission-note editable" placeholder="Add note" data-permission="${p}">
        </li>
    `
    )
    .join("");
  document.getElementById("explanation").textContent = data.explanation;
  document.getElementById("recommendations").textContent = data.recommendations;

  resultsContent.classList.remove("hidden");
}

function getReportData() {
  const permissions = Array.from(
    document.querySelectorAll(".permission-note")
  ).map((note) => ({
    name: note.dataset.permission,
    notes: note.value,
  }));
  return {
    report: {
      riskScore: {
        value: parseInt(
          document.getElementById("risk-score").textContent.split("/")[0]
        ),
        description: document.getElementById("risk-description").value,
      },
      permissions,
      explanation: document.getElementById("explanation").textContent,
      recommendations: document.getElementById("recommendations").textContent,
    },
  };
}

document.getElementById("generate-report").addEventListener("click", () => {
  const reportData = getReportData();
  const date = new Date().toLocaleDateString();

  const jsonBlob = new Blob([JSON.stringify(reportData, null, 2)], {
    type: "application/json",
  });
  const jsonUrl = URL.createObjectURL(jsonBlob);
  const jsonLink = document.createElement("a");
  jsonLink.href = jsonUrl;
  jsonLink.download = `report-${date}.json`;
  jsonLink.click();

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();

  doc.setFontSize(16);
  doc.text(`Extension Analysis Report - ${date}`, 10, 10);

  doc.setFontSize(12);
  doc.text(`Risk Score: ${reportData.report.riskScore.value}/100`, 10, 30);
  doc.text(`Description: ${reportData.report.riskScore.description}`, 10, 40);

  doc.text("Permission Breakdown:", 10, 60);
  let y = 70;
  reportData.report.permissions.forEach((perm, i) => {
    doc.text(`${i + 1}. ${perm.name}`, 10, y);
    if (perm.notes) doc.text(`   Note: ${perm.notes}`, 20, y + 5);
    y += perm.notes ? 15 : 10;
  });

  doc.text("AI Explanation:", 10, y + 10);
  doc.text(reportData.report.explanation, 10, y + 20, { maxWidth: 180 });

  doc.text("Recommendations:", 10, y + 50);
  doc.text(reportData.report.recommendations, 10, y + 60, { maxWidth: 180 });

  doc.save(`report-${date}.pdf`);
});
